import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode, urlparse

import requests
from authlib.jose import jwt
from authlib.jose.errors import JoseError

from girder.exceptions import RestException
from girder.models.setting import Setting

from .settings import PluginSettings

_DISCOVERY_TTL = 300  # seconds; cache OIDC discovery + JWKS this long
_HTTP_TIMEOUT = 10


def generate_pkce_pair():
    """Return an (code_verifier, code_challenge) PKCE S256 pair."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode('ascii')).digest()
    ).rstrip(b'=').decode('ascii')
    return verifier, challenge


def generate_nonce():
    return secrets.token_urlsafe(32)


def _rewriteOrigin(publicUrl, internalUrl, url):
    """Swap a public provider origin for its server-to-server equivalent."""
    if internalUrl == publicUrl or not url:
        return url
    pub = urlparse(publicUrl)
    intern = urlparse(internalUrl)
    pubOrigin = f'{pub.scheme}://{pub.netloc}'
    internOrigin = f'{intern.scheme}://{intern.netloc}'
    if url.startswith(pubOrigin):
        return internOrigin + url[len(pubOrigin):]
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
        jwks = self._fetchJson(self._toInternal(discovery['jwks_uri']))

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
        discovery = self.discovery
        tokenUrl = self._toInternal(discovery['token_endpoint'])
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirectUri,
            'client_id': self.clientId,
            'client_secret': self.clientSecret,
            'code_verifier': codeVerifier,
        }
        try:
            resp = requests.post(tokenUrl, data=data, timeout=_HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            raise RestException(f'OIDC token exchange failed: {e}', code=502)

    def validateIdToken(self, idToken, nonce):
        """
        Verify the ID token signature and claims, returning the claims dict.

        Validates the signature against the provider JWKS and checks ``iss``,
        ``aud``, expiry, and the ``nonce`` bound to this login attempt.
        """
        discovery, jwks = self._load()
        claimsOptions = {
            'iss': {'essential': True, 'value': discovery['issuer']},
            'aud': {'essential': True, 'value': self.clientId},
            'exp': {'essential': True},
        }
        try:
            claims = jwt.decode(idToken, jwks, claims_options=claimsOptions)
            claims.validate(leeway=30)
        except JoseError as e:
            raise RestException(f'Invalid OIDC ID token: {e}', code=403)

        if claims.get('nonce') != nonce:
            raise RestException('OIDC nonce mismatch.', code=403)

        return claims
