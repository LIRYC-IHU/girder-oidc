import datetime
import hmac
import logging
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import cherrypy

from girder.api import access
from girder.api.describe import Description, autoDescribeRoute
from girder.api.rest import Resource, getApiUrl
from girder.exceptions import RestException
from girder.models.setting import Setting
from girder.models.token import Token
from girder.models.user import User

from .client import OidcClient, generate_nonce, generate_pkce_pair, probeProvider
from .settings import PluginSettings
from .user import (claimAssertsVerifiedEmail, claimGrantsAccess, claimGrantsAdmin,
                   createOrReuseUser)

logger = logging.getLogger(__name__)

# Cookie that ties an in-flight login to the browser that started it.
_STATE_COOKIE = 'girderOidcState'
# The authorization round trip is interactive; ten minutes is generous and keeps
# abandoned attempts from piling up in the token collection.
_STATE_TTL_MINUTES = 10
# The SPA redeems its handoff code as soon as the redirect lands.
_HANDOFF_TTL_SECONDS = 60
# Dedicated scopes so neither of these bookkeeping tokens can ever be mistaken
# for a user-authentication token.
_STATE_SCOPE = 'oidc.state'
_HANDOFF_SCOPE = 'oidc.handoff'


def _safeRedirect(redirect):
    """Reject open-redirect attempts: only same-origin absolute paths allowed."""
    if not redirect:
        return '/'
    parsed = urlparse(redirect)
    # Backslashes are normalised to '/' by browsers, so "/\evil.com" reads as a
    # protocol-relative URL to anything that resolves the path before the host.
    if parsed.scheme or parsed.netloc or not redirect.startswith('/') \
            or redirect.startswith('//') or '\\' in redirect:
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
        self.route('POST', ('exchange',), self.exchange)

    def _redirectUri(self):
        return '/'.join((getApiUrl(), 'oidc', 'callback'))

    def _isHttps(self):
        # CherryPy proxy tools rewrite request.base but not request.scheme when a
        # reverse proxy sends X-Forwarded-Proto (same test girder core uses).
        return (cherrypy.request.scheme == 'https'
                or cherrypy.request.base.startswith('https'))

    def _setStateCookie(self, value):
        cookie = cherrypy.response.cookie
        cookie[_STATE_COOKIE] = value
        cookie[_STATE_COOKIE]['path'] = '/'
        cookie[_STATE_COOKIE]['max-age'] = _STATE_TTL_MINUTES * 60
        cookie[_STATE_COOKIE]['httponly'] = True
        # Lax, not Strict: the provider returns the user with a top-level GET
        # navigation, which Strict would strip -- breaking every login.
        cookie[_STATE_COOKIE]['samesite'] = 'Lax'
        if self._isHttps():
            cookie[_STATE_COOKIE]['secure'] = True

    def _clearStateCookie(self):
        cookie = cherrypy.response.cookie
        cookie[_STATE_COOKIE] = ''
        cookie[_STATE_COOKIE]['path'] = '/'
        cookie[_STATE_COOKIE]['expires'] = 0

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
            'trustUnverifiedEmail': settings.get(
                PluginSettings.TRUST_UNVERIFIED_EMAIL),
            'requiredClaim': settings.get(PluginSettings.REQUIRED_CLAIM),
            'requiredClaimValue': settings.get(
                PluginSettings.REQUIRED_CLAIM_VALUE),
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
        .param('trustUnverifiedEmail', 'Act on the email claim even when the '
               'provider does not assert email_verified. Only enable for a '
               'provider that vouches for every address it emits.',
               dataType='boolean', required=False)
        .param('requiredClaim', 'ID-token claim an identity must satisfy to log '
               'in at all (blank to let every identity the provider '
               'authenticates in).', required=False)
        .param('requiredClaimValue', 'Required value of the access claim (blank '
               'means any truthy value).', required=False)
        .param('adminClaim', 'ID-token claim that confers site-admin (blank to '
               'disable admin mapping).', required=False)
        .param('adminClaimValue', 'Required value of the admin claim (blank means '
               'any truthy value).', required=False)
    )
    def setConfiguration(self, enabled, clientId, clientSecret, publicUrl,
                         internalUrl, scopes, buttonLabel, autoCreateUsers,
                         ignoreRegistrationPolicy, trustUnverifiedEmail,
                         requiredClaim, requiredClaimValue,
                         adminClaim, adminClaimValue):
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
        if trustUnverifiedEmail is not None:
            settings.set(PluginSettings.TRUST_UNVERIFIED_EMAIL,
                         trustUnverifiedEmail)
        if requiredClaim is not None:
            settings.set(PluginSettings.REQUIRED_CLAIM, requiredClaim)
        if requiredClaimValue is not None:
            settings.set(PluginSettings.REQUIRED_CLAIM_VALUE, requiredClaimValue)
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
        #
        # `browserSecret` is mirrored into an httponly cookie and re-checked at
        # the callback. A valid state alone is not enough to complete a login:
        # without this, an attacker could run the flow against their own account
        # and then feed the resulting state+code to a victim, whose browser would
        # silently end up signed in as the attacker.
        browserSecret = generate_nonce()
        csrf = Token().createToken(
            days=_STATE_TTL_MINUTES / 1440, scope=_STATE_SCOPE)
        csrf['oidc'] = {
            'codeVerifier': verifier,
            'nonce': nonce,
            'redirect': redirect,
            'browserSecret': browserSecret,
        }
        Token().save(csrf)
        self._setStateCookie(browserSecret)

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

        # force=True, then require our own marker field: loading by ACL would
        # answer 401 for a token that exists but isn't ours and 403 for one that
        # doesn't exist, handing out a token-existence oracle for free.
        token = Token().load(state, objectId=False, force=True)
        if token is None or 'oidc' not in token:
            raise RestException('Invalid OIDC state token.', code=403)
        Token().remove(token)
        if token['expires'] < datetime.datetime.now(datetime.timezone.utc):
            raise RestException('Expired OIDC state token.', code=403)

        oidcData = token['oidc']

        # The state must have been minted for *this* browser (see `login`).
        presented = cherrypy.request.cookie.get(_STATE_COOKIE)
        self._clearStateCookie()
        expected = oidcData.get('browserSecret') or ''
        # Compare as bytes: compare_digest refuses non-ASCII str, and the cookie
        # value is attacker-controlled, so a str comparison would turn a crafted
        # cookie into a 500 instead of this 403.
        if not expected or not hmac.compare_digest(
                (presented.value if presented else '').encode('utf-8', 'ignore'),
                expected.encode('utf-8')):
            raise RestException(
                'This login attempt did not start in this browser. Please try '
                'signing in again.', code=403)

        redirect = _safeRedirect(oidcData.get('redirect'))

        client = OidcClient()
        tokenResp = client.exchangeCode(
            code, oidcData['codeVerifier'], self._redirectUri())
        idToken = tokenResp.get('id_token')
        if not idToken:
            raise RestException('OIDC token response had no id_token.', code=502)

        claims = client.validateIdToken(idToken, oidcData['nonce'])

        settings = Setting()
        # Before anything is derived from the token, and well before an account
        # could be provisioned: an identity the instance does not admit must
        # leave no trace here beyond this log line.
        if not claimGrantsAccess(
                claims, settings.get(PluginSettings.REQUIRED_CLAIM),
                settings.get(PluginSettings.REQUIRED_CLAIM_VALUE)):
            logger.info(
                'oidc: refused login for sub=%s -- the ID token does not carry '
                'the configured access claim.', claims.get('sub'))
            raise RestException(
                'Your identity provider signed you in, but this Girder instance '
                'has not granted you access. Ask an administrator to add you to '
                'the group that is allowed to use it.', code=403)

        email = claims.get('email')
        if not email:
            raise RestException('OIDC ID token did not include an email claim.',
                                code=502)

        isAdmin = claimGrantsAdmin(
            claims, settings.get(PluginSettings.ADMIN_CLAIM),
            settings.get(PluginSettings.ADMIN_CLAIM_VALUE))

        user = createOrReuseUser(
            oidcId=claims['sub'], email=email,
            firstName=claims.get('given_name', ''),
            lastName=claims.get('family_name', ''),
            userName=claims.get('preferred_username'),
            fullName=claims.get('name'), admin=isAdmin,
            emailVerified=claimAssertsVerifiedEmail(claims))
        User().verifyLogin(user)

        girderToken = Token().createToken(user)
        self.sendAuthTokenCookie(token=girderToken)

        # Hand the session token to the web client through a single-use code
        # rather than putting the token itself in the URL, where it would outlive
        # the request in browser history and in every access log between here and
        # the user (the token cookie above is httponly, so the SPA still needs a
        # copy of the value for its own API calls).
        handoff = Token().createToken(
            days=_HANDOFF_TTL_SECONDS / 86400, scope=_HANDOFF_SCOPE)
        handoff['oidcHandoff'] = str(girderToken['_id'])
        Token().save(handoff)

        parsed = urlparse(redirect)
        query = parse_qs(parsed.query)
        query['girderOidcCode'] = str(handoff['_id'])
        updated = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, parsed.params,
            urlencode(query, doseq=True), parsed.fragment))
        raise cherrypy.HTTPRedirect(updated)

    @access.public
    @autoDescribeRoute(
        Description('Redeem a one-time OIDC handoff code for a session token.')
        .notes('The code is issued by the login redirect, is valid for %d '
               'seconds, and is consumed on first use.' % _HANDOFF_TTL_SECONDS)
        .param('code', 'The handoff code from the login redirect.'),
        hide=True
    )
    def exchange(self, code):
        handoff = Token().load(code, objectId=False, force=True)
        if handoff is None or 'oidcHandoff' not in handoff:
            raise RestException('Invalid OIDC handoff code.', code=403)
        Token().remove(handoff)
        if handoff['expires'] < datetime.datetime.now(datetime.timezone.utc):
            raise RestException('Expired OIDC handoff code.', code=403)
        return {'token': handoff['oidcHandoff']}
