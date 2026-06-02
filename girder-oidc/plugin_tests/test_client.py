"""Unit tests for the OIDC client: PKCE, URL rewriting, ID-token validation.

These don't need a database; they build a throwaway RSA key and mint ID tokens
locally to exercise signature/claim validation.
"""

import base64
import hashlib
import time

import pytest
from authlib.jose import JsonWebKey, jwt

from girder.exceptions import RestException
from girder_oidc import client as oidc_client
from girder_oidc.client import OidcClient, generate_nonce, generate_pkce_pair, probeProvider

ISSUER = 'https://idp.example.com'
CLIENT_ID = 'test-client'
NONCE = 'the-nonce'


def test_pkce_pair_is_s256():
    verifier, challenge = generate_pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    assert challenge == expected
    assert verifier != generate_pkce_pair()[0]  # random each call


def test_nonce_is_random():
    assert generate_nonce() != generate_nonce()


def _client(internalUrl=ISSUER):
    client = OidcClient.__new__(OidcClient)
    client.clientId = CLIENT_ID
    client.clientSecret = 'secret'
    client.publicUrl = ISSUER
    client.internalUrl = internalUrl
    client.scopes = 'openid email'
    return client


def test_to_internal_rewrites_origin_only():
    client = _client(internalUrl='http://idp-internal:5556')
    assert client._toInternal(ISSUER + '/token') == 'http://idp-internal:5556/token'
    # Unrelated URLs are left alone.
    assert client._toInternal('https://other/keys') == 'https://other/keys'


def test_to_internal_noop_when_equal():
    client = _client()
    assert client._toInternal(ISSUER + '/token') == ISSUER + '/token'


def _discovery():
    return {
        'issuer': ISSUER,
        'authorization_endpoint': ISSUER + '/auth',
        'token_endpoint': ISSUER + '/token',
        'jwks_uri': ISSUER + '/keys',
    }


def test_probe_provider_success(monkeypatch):
    def fakeGet(url, **kwargs):
        if url.endswith('openid-configuration'):
            return _discovery()
        return {'keys': [{'kid': 'a'}, {'kid': 'b'}]}
    monkeypatch.setattr(oidc_client, '_httpGetJson', fakeGet)

    result = probeProvider(ISSUER)
    assert result['issuer'] == ISSUER
    assert result['tokenEndpoint'] == ISSUER + '/token'
    assert result['jwksKeys'] == 2


def test_probe_provider_uses_internal_origin(monkeypatch):
    seen = []

    def fakeGet(url, **kwargs):
        seen.append(url)
        return _discovery() if url.endswith('openid-configuration') else {'keys': []}
    monkeypatch.setattr(oidc_client, '_httpGetJson', fakeGet)

    probeProvider(ISSUER, 'http://idp-internal:5556')
    # Both the discovery and JWKS fetches hit the internal origin.
    assert seen and all(u.startswith('http://idp-internal:5556') for u in seen)


def test_probe_provider_requires_url():
    with pytest.raises(RestException):
        probeProvider('')


@pytest.fixture
def rsaKey():
    return JsonWebKey.generate_key('RSA', 2048, {'kid': 'test-key'}, is_private=True)


def _mint(rsaKey, **overrides):
    payload = {
        'iss': ISSUER, 'aud': CLIENT_ID, 'sub': 'subject-123',
        'email': 'user@example.com', 'nonce': NONCE,
        'iat': int(time.time()), 'exp': int(time.time()) + 300,
    }
    payload.update(overrides)
    header = {'alg': 'RS256', 'kid': 'test-key'}
    return jwt.encode(header, payload, rsaKey).decode('ascii')


def _patchLoad(client, rsaKey, monkeypatch):
    discovery = {
        'issuer': ISSUER,
        'authorization_endpoint': ISSUER + '/auth',
        'token_endpoint': ISSUER + '/token',
        'jwks_uri': ISSUER + '/keys',
    }
    jwks = {'keys': [rsaKey.as_dict(is_private=False)]}
    monkeypatch.setattr(client, '_load', lambda: (discovery, jwks))


def test_validate_id_token_success(rsaKey, monkeypatch):
    client = _client()
    _patchLoad(client, rsaKey, monkeypatch)
    claims = client.validateIdToken(_mint(rsaKey), NONCE)
    assert claims['sub'] == 'subject-123'
    assert claims['email'] == 'user@example.com'


def test_validate_id_token_bad_nonce(rsaKey, monkeypatch):
    client = _client()
    _patchLoad(client, rsaKey, monkeypatch)
    with pytest.raises(RestException):
        client.validateIdToken(_mint(rsaKey), 'wrong-nonce')


def test_validate_id_token_wrong_audience(rsaKey, monkeypatch):
    client = _client()
    _patchLoad(client, rsaKey, monkeypatch)
    with pytest.raises(RestException):
        client.validateIdToken(_mint(rsaKey, aud='someone-else'), NONCE)


def test_validate_id_token_expired(rsaKey, monkeypatch):
    client = _client()
    _patchLoad(client, rsaKey, monkeypatch)
    expired = _mint(rsaKey, exp=int(time.time()) - 3600, iat=int(time.time()) - 7200)
    with pytest.raises(RestException):
        client.validateIdToken(expired, NONCE)


def test_validate_id_token_wrong_issuer(rsaKey, monkeypatch):
    client = _client()
    _patchLoad(client, rsaKey, monkeypatch)
    with pytest.raises(RestException):
        client.validateIdToken(_mint(rsaKey, iss='https://evil.example.com'), NONCE)
