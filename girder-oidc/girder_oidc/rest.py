import datetime
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import cherrypy

from girder.api import access
from girder.api.describe import Description, autoDescribeRoute
from girder.api.rest import Resource, getApiUrl
from girder.constants import AccessType
from girder.exceptions import RestException
from girder.models.setting import Setting
from girder.models.token import Token
from girder.models.user import User

from .client import OidcClient, generate_nonce, generate_pkce_pair, probeProvider
from .settings import PluginSettings
from .user import claimGrantsAdmin, createOrReuseUser


def _safeRedirect(redirect):
    """Reject open-redirect attempts: only same-origin absolute paths allowed."""
    if not redirect:
        return '/'
    parsed = urlparse(redirect)
    if parsed.scheme or parsed.netloc or not redirect.startswith('/') \
            or redirect.startswith('//'):
        raise RestException(
            'Redirect must be a same-origin absolute path (e.g. "/").', code=400)
    return redirect


class Oidc(Resource):
    """REST endpoints for OpenID Connect login."""

    def __init__(self):
        super().__init__()
        self.resourceName = 'oidc'

        self.route('GET', ('config',), self.getPublicConfig)
        self.route('GET', ('configuration',), self.getConfiguration)
        self.route('PUT', ('configuration',), self.setConfiguration)
        self.route('POST', ('configuration', 'test'), self.testConfiguration)
        self.route('GET', ('login',), self.login)
        self.route('GET', ('callback',), self.callback)

    def _redirectUri(self):
        return '/'.join((getApiUrl(), 'oidc', 'callback'))

    @access.public
    @autoDescribeRoute(
        Description('Get the public OIDC config used to render the login button.')
    )
    def getPublicConfig(self):
        settings = Setting()
        return {
            'enabled': settings.get(PluginSettings.ENABLED),
            'buttonLabel': settings.get(PluginSettings.BUTTON_LABEL),
        }

    @access.admin
    @autoDescribeRoute(
        Description('Get the full OIDC configuration (secret omitted).')
    )
    def getConfiguration(self):
        settings = Setting()
        return {
            'enabled': settings.get(PluginSettings.ENABLED),
            'clientId': settings.get(PluginSettings.CLIENT_ID),
            'clientSecretSet': bool(settings.get(PluginSettings.CLIENT_SECRET)),
            'publicUrl': settings.get(PluginSettings.PUBLIC_URL),
            'internalUrl': settings.get(PluginSettings.INTERNAL_URL),
            'scopes': settings.get(PluginSettings.SCOPES),
            'buttonLabel': settings.get(PluginSettings.BUTTON_LABEL),
            'autoCreateUsers': settings.get(PluginSettings.AUTO_CREATE_USERS),
            'ignoreRegistrationPolicy': settings.get(
                PluginSettings.IGNORE_REGISTRATION_POLICY),
            'adminClaim': settings.get(PluginSettings.ADMIN_CLAIM),
            'adminClaimValue': settings.get(PluginSettings.ADMIN_CLAIM_VALUE),
        }

    @access.admin
    @autoDescribeRoute(
        Description('Update the OIDC configuration.')
        .param('enabled', 'Enable OIDC login.', dataType='boolean', required=False)
        .param('clientId', 'OAuth2 client ID.', required=False)
        .param('clientSecret', 'OAuth2 client secret (leave blank to keep current).',
               required=False)
        .param('publicUrl', 'Browser-facing provider base URL (the issuer).',
               required=False)
        .param('internalUrl', 'Server-to-server provider base URL (optional).',
               required=False)
        .param('scopes', 'Space-separated OAuth2 scopes.', required=False)
        .param('buttonLabel', 'Login button label.', required=False)
        .param('autoCreateUsers', 'Create Girder accounts for new identities.',
               dataType='boolean', required=False)
        .param('ignoreRegistrationPolicy', 'Allow creation even if registration '
               'policy is closed.', dataType='boolean', required=False)
        .param('adminClaim', 'ID-token claim that confers site-admin (blank to '
               'disable admin mapping).', required=False)
        .param('adminClaimValue', 'Required value of the admin claim (blank means '
               'any truthy value).', required=False)
    )
    def setConfiguration(self, enabled, clientId, clientSecret, publicUrl,
                         internalUrl, scopes, buttonLabel, autoCreateUsers,
                         ignoreRegistrationPolicy, adminClaim, adminClaimValue):
        settings = Setting()
        if enabled is not None:
            settings.set(PluginSettings.ENABLED, enabled)
        if clientId is not None:
            settings.set(PluginSettings.CLIENT_ID, clientId)
        # Only overwrite the secret when a non-empty value is supplied.
        if clientSecret:
            settings.set(PluginSettings.CLIENT_SECRET, clientSecret)
        if publicUrl is not None:
            settings.set(PluginSettings.PUBLIC_URL, publicUrl)
        if internalUrl is not None:
            settings.set(PluginSettings.INTERNAL_URL, internalUrl)
        if scopes is not None:
            settings.set(PluginSettings.SCOPES, scopes)
        if buttonLabel is not None:
            settings.set(PluginSettings.BUTTON_LABEL, buttonLabel)
        if autoCreateUsers is not None:
            settings.set(PluginSettings.AUTO_CREATE_USERS, autoCreateUsers)
        if ignoreRegistrationPolicy is not None:
            settings.set(PluginSettings.IGNORE_REGISTRATION_POLICY,
                         ignoreRegistrationPolicy)
        if adminClaim is not None:
            settings.set(PluginSettings.ADMIN_CLAIM, adminClaim)
        if adminClaimValue is not None:
            settings.set(PluginSettings.ADMIN_CLAIM_VALUE, adminClaimValue)
        return self.getConfiguration()

    @access.admin
    @autoDescribeRoute(
        Description('Test connectivity to the OIDC provider (discovery + JWKS).')
        .notes('Probes the URLs supplied (or the saved settings when omitted) '
               'without persisting them, so an admin can verify before saving.')
        .param('publicUrl', 'Provider URL to test; defaults to the saved value.',
               required=False)
        .param('internalUrl', 'Internal provider URL to test; defaults to the '
               'saved value.', required=False)
    )
    def testConfiguration(self, publicUrl, internalUrl):
        settings = Setting()
        if publicUrl is None:
            publicUrl = settings.get(PluginSettings.PUBLIC_URL)
        if internalUrl is None:
            internalUrl = settings.get(PluginSettings.INTERNAL_URL)
        try:
            result = probeProvider(publicUrl, internalUrl)
        except RestException as e:
            return {'ok': False, 'message': str(e)}
        result['ok'] = True
        return result

    @access.public
    @autoDescribeRoute(
        Description('Begin the OIDC login flow; returns the authorization URL.')
        .param('redirect', 'Same-origin path to return to after login.')
    )
    def login(self, redirect):
        if not Setting().get(PluginSettings.ENABLED):
            raise RestException('OIDC login is not enabled.', code=403)

        redirect = _safeRedirect(redirect)
        client = OidcClient()

        verifier, challenge = generate_pkce_pair()
        nonce = generate_nonce()

        # Stash the PKCE verifier, nonce, and redirect server-side, keyed by a
        # short-lived token whose id is the opaque `state`. None of these leak
        # into the URL the way the redirect alone would.
        csrf = Token().createToken(days=0.25)
        csrf['oidc'] = {'codeVerifier': verifier, 'nonce': nonce, 'redirect': redirect}
        Token().save(csrf)

        url = client.authorizationUrl(
            state=str(csrf['_id']), nonce=nonce, codeChallenge=challenge,
            redirectUri=self._redirectUri())
        return {'url': url}

    @access.public
    @autoDescribeRoute(
        Description('OIDC redirect callback.')
        .param('state', 'Opaque state token.', required=False)
        .param('code', 'Authorization code.', required=False)
        .param('error', 'Error returned by the provider.', required=False),
        hide=True
    )
    def callback(self, state, code, error):
        if error:
            raise RestException("OIDC provider returned an error: '%s'." % error,
                                code=502)
        self.requireParams({'state': state, 'code': code})

        token = Token().load(state, objectId=False, level=AccessType.READ)
        if token is None or 'oidc' not in token:
            raise RestException('Invalid OIDC state token.', code=403)
        Token().remove(token)
        if token['expires'] < datetime.datetime.now(datetime.timezone.utc):
            raise RestException('Expired OIDC state token.', code=403)

        oidcData = token['oidc']
        redirect = _safeRedirect(oidcData.get('redirect'))

        client = OidcClient()
        tokenResp = client.exchangeCode(
            code, oidcData['codeVerifier'], self._redirectUri())
        idToken = tokenResp.get('id_token')
        if not idToken:
            raise RestException('OIDC token response had no id_token.', code=502)

        claims = client.validateIdToken(idToken, oidcData['nonce'])
        email = claims.get('email')
        if not email:
            raise RestException('OIDC ID token did not include an email claim.',
                                code=502)

        settings = Setting()
        isAdmin = claimGrantsAdmin(
            claims, settings.get(PluginSettings.ADMIN_CLAIM),
            settings.get(PluginSettings.ADMIN_CLAIM_VALUE))

        user = createOrReuseUser(
            oidcId=claims['sub'], email=email,
            firstName=claims.get('given_name', ''),
            lastName=claims.get('family_name', ''),
            userName=claims.get('preferred_username'),
            fullName=claims.get('name'), admin=isAdmin)
        User().verifyLogin(user)

        girderToken = Token().createToken(user)
        self.sendAuthTokenCookie(token=girderToken)

        parsed = urlparse(redirect)
        query = parse_qs(parsed.query)
        query['girderToken'] = str(girderToken['_id'])
        updated = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, parsed.params,
            urlencode(query, doseq=True), parsed.fragment))
        raise cherrypy.HTTPRedirect(updated)
