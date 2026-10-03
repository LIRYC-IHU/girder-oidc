"""Unit tests for access-token validation (the token exchange's first gate).

No database: a throwaway RSA key signs tokens locally, as in test_client.py.
Each test is one way a token that must NOT be traded for Girder access could be
presented, plus the shapes real providers emit that must keep working.
"""

import base64
import hashlib
import hmac
import json
import time

import pytest
from authlib.jose import JsonWebKey, jwt
from cryptography.hazmat.primitives import serialization

from girder.exceptions import RestException
from girder_oidc.client import OidcClient, tokenScopes

ISSUER = 'https://idp.example.com/realms/test'
CLIENT_ID = 'girder'
AUDIENCE = 'girder-mcp'


def _b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()


@pytest.fixture
def rsaKey():
    return JsonWebKey.generate_key('RSA', 2048, {'kid': 'k1'}, is_private=True)


@pytest.fixture
def otherKey():
    return JsonWebKey.generate_key('RSA', 2048, {'kid': 'k1'}, is_private=True)


@pytest.fixture
def client(rsaKey, monkeypatch):
    c = OidcClient.__new__(OidcClient)
    c.clientId = CLIENT_ID
    c.clientSecret = ''
    c.publicUrl = ISSUER
    c.internalUrl = ISSUER
    c.scopes = 'openid'
    discovery = {'issuer': ISSUER, 'jwks_uri': ISSUER + '/certs',
                 'authorization_endpoint': ISSUER + '/auth',
                 'token_endpoint': ISSUER + '/token'}
    jwks = {'keys': [rsaKey.as_dict(is_private=False)]}
    monkeypatch.setattr(c, '_load', lambda: (discovery, jwks))
    return c


def _payload(**overrides):
    now = int(time.time())
    payload = {
        'iss': ISSUER, 'aud': [AUDIENCE, 'account'], 'sub': 'sub-123',
        'azp': 'claude-code', 'typ': 'Bearer', 'scope': 'openid girder-mcp email',
        'iat': now, 'exp': now + 300,
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not _DROP}


_DROP = object()


def _mint(key, header=None, **overrides):
    header = header or {'alg': 'RS256', 'kid': 'k1', 'typ': 'JWT'}
    return jwt.encode(header, _payload(**overrides), key).decode('ascii')


def _refused(client, token, scope='', code=401):
    with pytest.raises(RestException) as exc:
        client.validateAccessToken(token, AUDIENCE, scope)
    assert exc.value.code == code, exc.value
    return str(exc.value)


# --- Accepted shapes -------------------------------------------------------------------

def test_keycloak_access_token_is_accepted(client, rsaKey):
    claims = client.validateAccessToken(_mint(rsaKey), AUDIENCE)
    assert claims['sub'] == 'sub-123' and claims['azp'] == 'claude-code'


def test_single_string_audience_is_accepted(client, rsaKey):
    assert client.validateAccessToken(_mint(rsaKey, aud=AUDIENCE), AUDIENCE)


def test_rfc9068_access_token_is_accepted(client, rsaKey):
    token = _mint(rsaKey, header={'alg': 'RS256', 'kid': 'k1', 'typ': 'at+jwt'},
                  typ=_DROP, aud=AUDIENCE, client_id='claude-code')
    assert client.validateAccessToken(token, AUDIENCE)['client_id'] == 'claude-code'


def test_token_without_any_typ_is_accepted(client, rsaKey):
    token = _mint(rsaKey, header={'alg': 'RS256', 'kid': 'k1'}, typ=_DROP)
    assert client.validateAccessToken(token, AUDIENCE)


def test_required_scope_present(client, rsaKey):
    assert client.validateAccessToken(_mint(rsaKey), AUDIENCE, 'girder-mcp')
    # `scp` as a list (Entra ID / Okta style) is understood too.
    token = _mint(rsaKey, scope=_DROP, scp=['girder-mcp'])
    assert client.validateAccessToken(token, AUDIENCE, 'girder-mcp')


def test_token_scopes_helper():
    assert tokenScopes({'scope': 'a b  c'}) == {'a', 'b', 'c'}
    assert tokenScopes({'scp': 'a b'}) == {'a', 'b'}
    assert tokenScopes({'scp': ['a', 'b']}) == {'a', 'b'}
    assert tokenScopes({}) == set()
    assert tokenScopes({'scope': 42}) == set()


# --- Refused: identity of the token -------------------------------------------------------

def test_wrong_audience_refused(client, rsaKey):
    _refused(client, _mint(rsaKey, aud='account'))
    _refused(client, _mint(rsaKey, aud=['account', 'other']))


def test_girder_own_client_audience_refused(client, rsaKey):
    """A token issued for Girder's login (aud = client id) is not for us."""
    _refused(client, _mint(rsaKey, aud=CLIENT_ID))


def test_missing_audience_refused(client, rsaKey):
    _refused(client, _mint(rsaKey, aud=_DROP))


def test_wrong_issuer_refused(client, rsaKey):
    _refused(client, _mint(rsaKey, iss='https://idp.example.com/realms/other'))
    _refused(client, _mint(rsaKey, iss=_DROP))


def test_missing_or_bad_subject_refused(client, rsaKey):
    _refused(client, _mint(rsaKey, sub=_DROP))
    _refused(client, _mint(rsaKey, sub=''))
    _refused(client, _mint(rsaKey, sub={'$ne': None}))
    _refused(client, _mint(rsaKey, sub=['sub-123']))


def test_expired_refused(client, rsaKey):
    now = int(time.time())
    _refused(client, _mint(rsaKey, iat=now - 7200, exp=now - 3600))


def test_missing_expiry_refused(client, rsaKey):
    _refused(client, _mint(rsaKey, exp=_DROP))


def test_not_yet_valid_refused(client, rsaKey):
    _refused(client, _mint(rsaKey, nbf=int(time.time()) + 3600))


# --- Refused: kind of token ----------------------------------------------------------------

@pytest.mark.parametrize('typ', ['ID', 'Refresh', 'Offline', 'Logout', 'id_token'])
def test_non_access_token_types_refused(client, rsaKey, typ):
    """Keycloak marks its ID / refresh / logout tokens in `typ`: none of them is a
    bearer credential for an API, whatever its audience."""
    message = _refused(client, _mint(rsaKey, typ=typ))
    assert 'not an access token' in message


def test_unexpected_header_type_refused(client, rsaKey):
    token = _mint(rsaKey, header={'alg': 'RS256', 'kid': 'k1', 'typ': 'logout+jwt'})
    _refused(client, token)


# --- Refused: signature --------------------------------------------------------------------

def test_signed_by_another_key_refused(client, otherKey):
    """Same kid, different key: the attacker's self-signed token."""
    _refused(client, _mint(otherKey))


def test_tampered_payload_refused(client, rsaKey):
    header, _, signature = _mint(rsaKey).split('.')
    forged = _b64(_payload(sub='admin-sub'))
    _refused(client, '.'.join([header, forged, signature]))


def test_alg_none_refused(client):
    token = _b64({'alg': 'none', 'typ': 'JWT'}) + '.' + _b64(_payload()) + '.'
    _refused(client, token)


def test_hmac_key_confusion_refused(client, rsaKey):
    publicPem = rsaKey.get_public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    signingInput = (_b64({'alg': 'HS256', 'kid': 'k1'}) + '.' + _b64(_payload())).encode()
    signature = base64.urlsafe_b64encode(
        hmac.new(publicPem, signingInput, hashlib.sha256).digest()).rstrip(b'=').decode()
    _refused(client, signingInput.decode() + '.' + signature)


# --- Refused: scope and malformed input ---------------------------------------------------

def test_required_scope_missing_refused(client, rsaKey):
    _refused(client, _mint(rsaKey, scope='openid email'), scope='girder-mcp')
    # Matching is on whole scope names, not substrings.
    _refused(client, _mint(rsaKey, scope='girder-mcp-admin x-girder-mcp'), scope='girder-mcp')
    _refused(client, _mint(rsaKey, scope=_DROP), scope='girder-mcp')


@pytest.mark.parametrize('garbage', [
    '', 'abc', 'a.b', 'a.b.c.d', None, 42, ['x.y.z'], 'eyJ.eyJ.sig',
])
def test_garbage_refused(client, garbage):
    _refused(client, garbage)


def test_oversized_token_refused(client, rsaKey):
    token = _mint(rsaKey, padding='x' * 20000)
    _refused(client, token)


def test_disabled_audience_refused(client, rsaKey):
    with pytest.raises(RestException) as exc:
        client.validateAccessToken(_mint(rsaKey), '')
    assert exc.value.code == 403


# --- Discovery / JWKS loading under provider trouble -------------------------------------

@pytest.fixture
def loader(monkeypatch):
    from girder_oidc import client as oidcClient
    c = OidcClient.__new__(OidcClient)
    c.clientId, c.clientSecret, c.scopes = CLIENT_ID, '', 'openid'
    c.publicUrl = c.internalUrl = ISSUER
    calls = []
    state = {'up': True}

    def fetch(url, **kwargs):
        calls.append(url)
        if not state['up']:
            raise RestException('OIDC provider request failed: down', code=502)
        if url.endswith('openid-configuration'):
            return {'issuer': ISSUER, 'jwks_uri': ISSUER + '/certs'}
        return {'keys': [{'kid': 'k%d' % len(calls)}]}
    monkeypatch.setattr(oidcClient, '_httpGetJson', fetch)
    OidcClient._cache.clear()
    OidcClient._failures.clear()
    yield c, calls, state
    OidcClient._cache.clear()
    OidcClient._failures.clear()


def test_failure_is_remembered(loader):
    c, calls, state = loader
    state['up'] = False
    for _ in range(3):
        with pytest.raises(RestException) as exc:
            c._load()
        assert exc.value.code == 502
    assert len(calls) == 1  # one fetch, then fail fast


def test_stale_keys_are_served_when_the_refresh_fails(loader, monkeypatch):
    c, calls, state = loader
    _, jwks = c._load()
    # Expire the cache, take the provider down: the last keys are still served.
    expiry, discovery, keys = OidcClient._cache[ISSUER]
    OidcClient._cache[ISSUER] = (0, discovery, keys)
    state['up'] = False
    assert c._load()[1] == jwks
    assert c._load()[1] == jwks  # and the failure is remembered, no new fetch
    assert len(calls) == 3


def test_no_thread_queues_behind_a_fetch_in_progress(loader):
    c, calls, state = loader
    assert OidcClient._loadLock.acquire()
    try:
        # No previous document: refuse at once rather than wait.
        with pytest.raises(RestException) as exc:
            c._load()
        assert exc.value.code == 503
        assert calls == []
    finally:
        OidcClient._loadLock.release()
    _, jwks = c._load()
    expiry, discovery, keys = OidcClient._cache[ISSUER]
    OidcClient._cache[ISSUER] = (0, discovery, keys)
    assert OidcClient._loadLock.acquire()
    try:
        assert c._load()[1] == jwks  # stale document served, no fetch
    finally:
        OidcClient._loadLock.release()
