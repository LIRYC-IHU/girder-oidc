import base64
import hashlib
import hmac
import secrets
import threading
import time
from urllib.parse import urlencode, urlparse

import requests
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError

from girder.exceptions import RestException
from girder.models.setting import Setting

from .settings import PluginSettings

_DISCOVERY_TTL = 300  # seconds; cache OIDC discovery + JWKS this long
# After a failed discovery/JWKS fetch, fail fast for this long instead of
# re-fetching: every anonymous request that needs the provider (login, token
# exchange) would otherwise hold a server thread for the full HTTP timeout
# while the provider is down -- an easy way to exhaust the thread pool.
_FAILURE_TTL = 30
_HTTP_TIMEOUT = 10

# Asymmetric signature algorithms only. The provider signs with a key from its
# JWKS and we only ever hold the public half, so an HMAC algorithm here would
# invite the classic confusion attack (forge a token by HMAC-ing with the
# provider's *public* key). Passing an explicit list also pins the behaviour
# rather than inheriting whatever the installed authlib happens to allow.
_ID_TOKEN_ALGORITHMS = [
    'RS256', 'RS384', 'RS512',
    'PS256', 'PS384', 'PS512',
    'ES256', 'ES384', 'ES512',
    'EdDSA',
]
_jwt = JsonWebToken(_ID_TOKEN_ALGORITHMS)

# An access token is a bearer credential: bound its size before any parsing.
_MAX_ACCESS_TOKEN_LENGTH = 16 * 1024
# Values that mark a JWT as an ACCESS token. Keycloak puts `typ` in the payload
# ("Bearer"; its ID tokens say "ID", refresh tokens "Refresh"/"Offline");
# RFC 9068 puts it in the header ("at+jwt"). A token that declares any other
# type is refused, so an ID token that happens to carry the audience can never
# be traded in.
_ACCESS_TOKEN_TYPES = frozenset({'bearer', 'at+jwt', 'application/at+jwt'})
_HEADER_TYPES = frozenset({'jwt', 'at+jwt', 'application/at+jwt'})


def tokenScopes(claims):
    """OAuth scopes granted by an access token: the space-separated `scope`
    claim (RFC 9068, Keycloak), or `scp` as a list or string (Entra ID, Okta)."""
    scopes = set()
    for name in ('scope', 'scp'):
        value = claims.get(name)
        if isinstance(value, str):
            scopes.update(value.split())
        elif isinstance(value, (list, tuple)):
            scopes.update(str(v) for v in value)
    return scopes


def generate_pkce_pair():
    """Return an (code_verifier, code_challenge) PKCE S256 pair."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')
    return verifier, challenge


def generate_nonce():
    return secrets.token_urlsafe(32)


def _origin(url):
    parsed = urlparse(url)
    return f'{parsed.scheme}://{parsed.netloc}'


def _requireHttpUrl(url, label):
    """Reject anything that isn't an absolute http(s) URL before we hand it to
    requests, so a setting can't aim server-side fetches at another scheme."""
    parsed = urlparse(url or '')
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise RestException(f'{label} must be an absolute http(s) URL.', code=400)
    return parsed


def _rewriteOrigin(publicUrl, internalUrl, url):
    """Swap a public provider origin for its server-to-server equivalent."""
    if internalUrl == publicUrl or not url:
        return url
    pubOrigin = _origin(publicUrl)
    if url.startswith(pubOrigin):
        return _origin(internalUrl) + url[len(pubOrigin):]
    return url


def _httpGetJson(url, **kwargs):
    try:
        resp = requests.get(url, timeout=_HTTP_TIMEOUT, **kwargs)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        raise RestException(f'OIDC provider request failed: {e}', code=502)


def probeProvider(publicUrl, internalUrl=None):
    """Fetch the provider's discovery document and JWKS to verify connectivity.

    Used by the admin "test connection" button. Returns a summary of the
    discovered endpoints; raises RestException if anything is unreachable or
    malformed."""
    publicUrl = (publicUrl or '').rstrip('/')
    internalUrl = (internalUrl or '').rstrip('/') or publicUrl
    if not publicUrl:
        raise RestException('OIDC provider URL is not configured.', code=400)
    _requireHttpUrl(publicUrl, 'Provider URL')
    _requireHttpUrl(internalUrl, 'Internal provider URL')

    discoveryUrl = _rewriteOrigin(
        publicUrl, internalUrl, f'{publicUrl}/.well-known/openid-configuration')
    discovery = _httpGetJson(discoveryUrl)
    if not discovery.get('issuer'):
        raise RestException(
            'Discovery document is missing an "issuer".', code=502)

    jwksUri = discovery.get('jwks_uri')
    if not jwksUri:
        raise RestException(
            'Discovery document is missing a "jwks_uri".', code=502)
    jwks = _httpGetJson(_rewriteOrigin(publicUrl, internalUrl, jwksUri))

    return {
        'issuer': discovery.get('issuer'),
        'authorizationEndpoint': discovery.get('authorization_endpoint'),
        'tokenEndpoint': discovery.get('token_endpoint'),
        'userinfoEndpoint': discovery.get('userinfo_endpoint'),
        'endSessionEndpoint': discovery.get('end_session_endpoint'),
        'jwksKeys': len(jwks.get('keys', [])),
    }


class OidcClient:
    """
    Thin OpenID Connect client built on the provider's discovery document.

    It performs discovery + JWKS fetches against the *internal* provider URL
    (server-to-server) while keeping the *public* URL for the browser-facing
    authorization redirect and as the expected ``iss`` of the ID token.
    """

    _cache = {}  # shared across instances: {publicUrl: (expiry, discovery, jwks)}
    _failures = {}  # {publicUrl: (until, message)} -- recent fetch failures
    _loadLock = threading.Lock()  # one provider fetch at a time

    def __init__(self):
        settings = Setting()
        self.clientId = settings.get(PluginSettings.CLIENT_ID)
        self.clientSecret = settings.get(PluginSettings.CLIENT_SECRET)
        self.publicUrl = (settings.get(PluginSettings.PUBLIC_URL) or '').rstrip('/')
        self.internalUrl = (settings.get(PluginSettings.INTERNAL_URL) or '').rstrip('/') \
            or self.publicUrl
        self.scopes = settings.get(PluginSettings.SCOPES) or 'openid profile email'

        if not self.publicUrl:
            raise RestException('OIDC provider URL is not configured.', code=503)
        if not self.clientId:
            raise RestException('OIDC client ID is not configured.', code=503)

    def _toInternal(self, url):
        """Rewrite a public provider URL to its server-to-server equivalent."""
        return _rewriteOrigin(self.publicUrl, self.internalUrl, url)

    def _providerEndpoint(self, discovery, name):
        """Resolve an endpoint advertised by the discovery document.

        The document is only as trustworthy as the channel it arrived on, so
        refuse a scheme downgrade: a provider we reach over https must not be
        able to send us to a plaintext endpoint. That matters most for the token
        endpoint, whose POST body carries the client secret.
        """
        url = discovery.get(name)
        if not url:
            raise RestException(
                f'Discovery document is missing a "{name}".', code=502)
        internal = self._toInternal(url)
        parsed = urlparse(internal)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            raise RestException(
                f'Provider advertised an unusable "{name}".', code=502)
        if urlparse(self.internalUrl).scheme == 'https' and parsed.scheme != 'https':
            raise RestException(
                f'Provider advertised a plaintext "{name}"; refusing to use it.',
                code=502)
        return internal

    def _fetchJson(self, url, **kwargs):
        return _httpGetJson(url, **kwargs)

    def _fresh(self):
        cached = self._cache.get(self.publicUrl)
        if cached and cached[0] > time.time():
            return cached[1], cached[2]
        failed = self._failures.get(self.publicUrl)
        if failed and failed[0] > time.time():
            if cached:  # recent failure, but last known keys still usable
                return cached[1], cached[2]
            raise RestException(failed[1], code=502)
        return None

    def _load(self):
        """Return (discovery, jwks), using the per-issuer cache when fresh.

        Fetches are serialised, and a failure is remembered for _FAILURE_TTL
        seconds, so a slow or unreachable provider costs one timeout, not one
        per request.
        """
        fresh = self._fresh()
        if fresh:
            return fresh
        stale = self._cache.get(self.publicUrl)
        # Never queue behind a fetch in progress: while the provider is slow, that
        # would pile up server threads exactly as the failure cache is meant to
        # prevent. Serve the previous document (keys rotate rarely) or refuse.
        if not self._loadLock.acquire(blocking=False):
            if stale:
                return stale[1], stale[2]
            raise RestException('The OIDC provider is being contacted; retry shortly.',
                                code=503)
        try:
            fresh = self._fresh()  # another thread may have just fetched
            if fresh:
                return fresh
            try:
                discoveryUrl = self._toInternal(
                    f'{self.publicUrl}/.well-known/openid-configuration')
                discovery = self._fetchJson(discoveryUrl)
                jwks = self._fetchJson(self._providerEndpoint(discovery, 'jwks_uri'))
            except RestException as e:
                self._failures[self.publicUrl] = (time.time() + _FAILURE_TTL, str(e))
                if stale:
                    # Stale-while-revalidate: a provider hiccup must not break
                    # logins that the last known keys can still verify.
                    return stale[1], stale[2]
                raise
            self._failures.pop(self.publicUrl, None)
            self._cache[self.publicUrl] = (time.time() + _DISCOVERY_TTL, discovery, jwks)
            return discovery, jwks
        finally:
            self._loadLock.release()

    @property
    def discovery(self):
        return self._load()[0]

    def authorizationUrl(self, state, nonce, codeChallenge, redirectUri):
        """Build the browser-facing authorization URL (uses the public endpoint)."""
        discovery = self.discovery
        params = {
            'client_id': self.clientId,
            'response_type': 'code',
            'scope': self.scopes,
            'redirect_uri': redirectUri,
            'state': state,
            'nonce': nonce,
            'code_challenge': codeChallenge,
            'code_challenge_method': 'S256',
        }
        return f"{discovery['authorization_endpoint']}?{urlencode(params)}"

    def endSessionUrl(self, idTokenHint=None, postLogoutRedirectUri=None,
                      state=None):
        """Build the browser-facing RP-initiated logout URL, or None.

        Returns ``None`` when the provider advertises no ``end_session_endpoint``
        -- plenty of providers (dex, for one) implement no logout endpoint at
        all, and that has to degrade to a Girder-only logout rather than fail.

        Unlike the token and JWKS endpoints this one is *not* rewritten to the
        internal origin: the browser is what goes there, so it needs the public
        address the provider published.
        """
        endpoint = self.discovery.get('end_session_endpoint')
        if not endpoint:
            return None
        parsed = urlparse(endpoint)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            raise RestException(
                'Provider advertised an unusable "end_session_endpoint".',
                code=502)
        if urlparse(self.publicUrl).scheme == 'https' and parsed.scheme != 'https':
            raise RestException(
                'Provider advertised a plaintext "end_session_endpoint"; '
                'refusing to send the browser there.', code=502)

        # `client_id` goes alongside `id_token_hint` rather than instead of it.
        # The hint is stored at login and used whenever the user signs out,
        # which is usually long after the ID token's `exp`: the spec tells the
        # provider to honour an expired hint for a session it still recognises,
        # but not every provider does. With `client_id` present as well, a
        # provider that rejects the stale hint can still identify the client and
        # honour `post_logout_redirect_uri` (which it would otherwise refuse),
        # at the cost of showing its own confirmation page. The spec allows both
        # and requires the provider to check that they agree.
        params = {'client_id': self.clientId}
        if idTokenHint:
            params['id_token_hint'] = idTokenHint
        if postLogoutRedirectUri:
            params['post_logout_redirect_uri'] = postLogoutRedirectUri
        if state:
            params['state'] = state
        separator = '&' if parsed.query else '?'
        return f'{endpoint}{separator}{urlencode(params)}'

    def exchangeCode(self, code, codeVerifier, redirectUri):
        """Exchange an authorization code for tokens (server-side, internal URL)."""
        tokenUrl = self._providerEndpoint(self.discovery, 'token_endpoint')
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirectUri,
            'client_id': self.clientId,
            'code_verifier': codeVerifier,
        }
        # Omit rather than blank the secret: a public client authenticates with
        # PKCE alone, and an empty client_secret makes some providers 400.
        if self.clientSecret:
            data['client_secret'] = self.clientSecret
        try:
            # No redirect following: a 307/308 would replay this body, secret
            # included, at whatever location the provider names.
            resp = requests.post(tokenUrl, data=data, timeout=_HTTP_TIMEOUT,
                                 allow_redirects=False)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            raise RestException(f'OIDC token exchange failed: {e}', code=502)

    def validateIdToken(self, idToken, nonce):
        """
        Verify the ID token signature and claims, returning the claims dict.

        Validates the signature against the provider JWKS and checks ``iss``,
        ``aud``, ``sub``, expiry, and the ``nonce`` bound to this login attempt.
        """
        discovery, jwks = self._load()
        claimsOptions = {
            'iss': {'essential': True, 'value': discovery['issuer']},
            'aud': {'essential': True, 'value': self.clientId},
            # `sub` is the identity we key Girder accounts on, so a token
            # without one is unusable rather than merely incomplete.
            'sub': {'essential': True},
            'exp': {'essential': True},
        }
        try:
            claims = _jwt.decode(idToken, jwks, claims_options=claimsOptions)
            claims.validate(leeway=30)
        except (JoseError, ValueError) as e:
            raise RestException(f'Invalid OIDC ID token: {e}', code=403)

        # Bytes, not str: compare_digest rejects non-ASCII str, and the nonce in
        # the token is provider-supplied, so a str comparison could raise here.
        if not hmac.compare_digest(
                str(claims.get('nonce') or '').encode('utf-8', 'ignore'),
                str(nonce or '').encode('utf-8', 'ignore')):
            raise RestException('OIDC nonce mismatch.', code=403)

        # authlib accepts an `aud` list that merely contains our client id. When
        # a token has several audiences OIDC additionally requires `azp` to name
        # the client it was issued for; without this check a token minted for a
        # different client of the same provider would be accepted here.
        aud = claims.get('aud')
        if isinstance(aud, (list, tuple)) and len(aud) > 1 \
                and claims.get('azp') != self.clientId:
            raise RestException(
                'OIDC ID token has multiple audiences and is not authorized '
                'for this client.', code=403)

        return claims

    def validateAccessToken(self, accessToken, audience, requiredScope=''):
        """
        Verify an ACCESS token the provider issued for ``audience`` and return
        its claims.

        Used by the token exchange (``POST /oidc/token_exchange``): a resource
        server such as an MCP server receives the token from its own OAuth
        client and trades it for a Girder token. Checks the signature against
        the provider JWKS (asymmetric algorithms only), ``iss``, ``aud``
        (must contain ``audience``), ``sub``, ``exp``/``nbf``, that the token
        does not declare itself as anything but an access token, and, when
        ``requiredScope`` is set, that it grants that scope.

        Every failure raises a 401 ``RestException``.
        """
        if not audience:
            raise RestException('Token exchange is not configured.', code=403)
        if not isinstance(accessToken, str) or not accessToken \
                or len(accessToken) > _MAX_ACCESS_TOKEN_LENGTH \
                or accessToken.count('.') != 2:
            raise RestException('Invalid access token.', code=401)

        discovery, jwks = self._load()
        claimsOptions = {
            'iss': {'essential': True, 'value': discovery['issuer']},
            'aud': {'essential': True, 'value': audience},
            'sub': {'essential': True},
            'exp': {'essential': True},
        }
        try:
            claims = _jwt.decode(accessToken, jwks, claims_options=claimsOptions)
            claims.validate(leeway=30)
        except (JoseError, ValueError, TypeError) as e:
            raise RestException(f'Invalid access token: {e}', code=401)

        # `sub` keys the account lookup; refuse anything but a non-empty string
        # rather than letting an exotic value reach the database query.
        if not isinstance(claims.get('sub'), str) or not claims['sub']:
            raise RestException('Invalid access token: bad "sub".', code=401)

        payloadType = claims.get('typ')
        if payloadType is not None \
                and str(payloadType).lower() not in _ACCESS_TOKEN_TYPES:
            raise RestException(
                'Invalid access token: this is not an access token (typ=%s).'
                % payloadType, code=401)
        headerType = (claims.header or {}).get('typ')
        if headerType is not None and str(headerType).lower() not in _HEADER_TYPES:
            raise RestException(
                'Invalid access token: unexpected token type in header.', code=401)

        if requiredScope and requiredScope not in tokenScopes(claims):
            raise RestException(
                'Access token does not grant the "%s" scope.' % requiredScope,
                code=401)

        return claims
