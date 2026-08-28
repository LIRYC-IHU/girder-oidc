import base64
import hashlib
import hmac
import secrets
import time
from urllib.parse import urlencode, urlparse

import requests
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError

from girder.exceptions import RestException
from girder.models.setting import Setting

from .settings import PluginSettings

_DISCOVERY_TTL = 300  # seconds; cache OIDC discovery + JWKS this long
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

    def _load(self):
        """Return (discovery, jwks), using the per-issuer cache when fresh."""
        cached = self._cache.get(self.publicUrl)
        if cached and cached[0] > time.time():
            return cached[1], cached[2]

        discoveryUrl = self._toInternal(
            f'{self.publicUrl}/.well-known/openid-configuration')
        discovery = self._fetchJson(discoveryUrl)
        jwks = self._fetchJson(self._providerEndpoint(discovery, 'jwks_uri'))

        self._cache[self.publicUrl] = (time.time() + _DISCOVERY_TTL, discovery, jwks)
        return discovery, jwks

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
