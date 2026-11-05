"""RP-initiated logout: the end-session URL builder and `GET /oidc/logout`.

Signing out of Girder leaves the provider session untouched unless the logout is
forwarded, and a live provider session silently signs the user straight back in
on the next login click. These pin both halves: the URL handed to the browser,
and the conditions under which the plugin declines to hand one over at all.
"""

import pytest

from pytest_girder.assertions import assertStatus, assertStatusOk

from girder.exceptions import RestException
from girder.models.setting import Setting
from girder.models.token import Token
from girder.models.user import User

from girder_oidc import rest as oidc_rest
from girder_oidc.client import OidcClient
from girder_oidc.rest import _STATE_COOKIE, _STATE_SCOPE, _STATE_TTL_MINUTES
from girder_oidc.settings import PluginSettings

ISSUER = 'https://idp.example.com/realms/test'
CLIENT_ID = 'girder'
END_SESSION = ISSUER + '/protocol/openid-connect/logout'
SUB = 'sub-alice'
HINT = 'the.stored.id.token'
STATE_SECRET = 'the-browser-secret'


# --- the URL builder ----------------------------------------------------------

def _client(endSession=END_SESSION, publicUrl=ISSUER):
    client = OidcClient.__new__(OidcClient)
    client.clientId = CLIENT_ID
    client.clientSecret = 'secret'
    client.publicUrl = publicUrl
    client.internalUrl = publicUrl
    client.scopes = 'openid email'
    discovery = {'issuer': ISSUER, 'jwks_uri': ISSUER + '/certs'}
    if endSession is not None:
        discovery['end_session_endpoint'] = endSession
    client._cache = {publicUrl: (float('inf'), discovery, {'keys': []})}
    return client


def _params(url):
    from urllib.parse import parse_qs, urlparse
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def test_end_session_url_carries_hint_client_and_return_uri():
    url = _client().endSessionUrl(
        idTokenHint=HINT, postLogoutRedirectUri='https://girder.example.com/')
    assert url.startswith(END_SESSION + '?')
    params = _params(url)
    assert params['id_token_hint'] == HINT
    # `client_id` rides along with the hint rather than replacing it: the stored
    # hint is usually past its `exp` by the time the user signs out, and a
    # provider that rejects it can still honour the return URI with the client.
    assert params['client_id'] == CLIENT_ID
    assert params['post_logout_redirect_uri'] == 'https://girder.example.com/'


def test_end_session_url_without_a_hint_still_identifies_the_client():
    params = _params(_client().endSessionUrl(
        postLogoutRedirectUri='https://girder.example.com/'))
    assert 'id_token_hint' not in params
    assert params['client_id'] == CLIENT_ID


def test_end_session_url_is_none_when_provider_advertises_none():
    """dex, among others, implements no logout endpoint. That has to degrade to
    a Girder-only logout, not raise."""
    assert _client(endSession=None).endSessionUrl(idTokenHint=HINT) is None


def test_end_session_url_preserves_an_existing_query_string():
    url = _client(endSession=END_SESSION + '?realm=test').endSessionUrl(
        idTokenHint=HINT)
    assert '?realm=test&' in url
    assert _params(url)['realm'] == 'test'


def test_end_session_url_refuses_a_plaintext_downgrade():
    """The browser is what goes there, carrying the hint."""
    with pytest.raises(RestException):
        _client(endSession='http://idp.example.com/logout').endSessionUrl(
            idTokenHint=HINT)


@pytest.mark.parametrize('endpoint', ['javascript:alert(1)', 'not-a-url', '/logout'])
def test_end_session_url_refuses_a_non_http_endpoint(endpoint):
    with pytest.raises(RestException):
        _client(endSession=endpoint).endSessionUrl()


def test_end_session_url_is_not_rewritten_to_the_internal_origin():
    """Unlike the token and JWKS endpoints: the browser needs the public one."""
    client = _client()
    client.internalUrl = 'http://idp-internal:8080'
    assert client.endSessionUrl().startswith(END_SESSION)


# --- GET /oidc/logout --------------------------------------------------------

@pytest.fixture
def provider(monkeypatch):
    discovery = {'issuer': ISSUER, 'jwks_uri': ISSUER + '/certs',
                 'authorization_endpoint': ISSUER + '/auth',
                 'token_endpoint': ISSUER + '/token',
                 'end_session_endpoint': END_SESSION}
    monkeypatch.setattr(OidcClient, '_load',
                        lambda self: (discovery, {'keys': []}))


@pytest.fixture
def configured(db, provider):
    settings = Setting()
    settings.set(PluginSettings.ENABLED, True)
    settings.set(PluginSettings.CLIENT_ID, CLIENT_ID)
    settings.set(PluginSettings.PUBLIC_URL, ISSUER)
    yield
    settings.set(PluginSettings.PROPAGATE_LOGOUT, True)


@pytest.fixture
def linked(user):
    user['oidc'] = [{'provider': 'oidc', 'id': SUB}]
    return User().save(user)


def _sessionWithHint(user, hint=HINT):
    token = Token().createToken(user)
    if hint is not None:
        token['oidcLogout'] = {'idToken': hint}
        token = Token().save(token)
    return token


def _logout(server, token):
    return server.request(path='/oidc/logout', method='GET',
                          token=str(token['_id']))


@pytest.mark.plugin('oidc')
def test_logout_requires_authentication(server, configured):
    resp = server.request(path='/oidc/logout', method='GET')
    assertStatus(resp, 401)


@pytest.mark.plugin('oidc')
def test_logout_returns_the_provider_url_for_an_oidc_session(
        server, configured, linked):
    resp = _logout(server, _sessionWithHint(linked))
    assertStatusOk(resp)
    params = _params(resp.json['url'])
    assert params['id_token_hint'] == HINT
    assert params['client_id'] == CLIENT_ID
    # The provider sends the browser back to the Girder app root, not the API.
    assert params['post_logout_redirect_uri'].endswith('/')
    assert '/api/' not in params['post_logout_redirect_uri']


@pytest.mark.plugin('oidc')
def test_logout_of_a_local_account_propagates_nothing(server, configured, user):
    """A password user never had a provider session; bouncing them through an
    identity provider they never used would be worse than useless."""
    assert not user.get('oidc')
    resp = _logout(server, Token().createToken(user))
    assertStatusOk(resp)
    assert resp.json['url'] is None


@pytest.mark.plugin('oidc')
def test_logout_propagates_nothing_when_the_setting_is_off(
        server, configured, linked):
    Setting().set(PluginSettings.PROPAGATE_LOGOUT, False)
    resp = _logout(server, _sessionWithHint(linked))
    assertStatusOk(resp)
    assert resp.json['url'] is None


@pytest.mark.plugin('oidc')
def test_logout_without_a_stored_hint_still_returns_a_url(
        server, configured, linked):
    """Sessions that predate the feature, or were created while it was off."""
    resp = _logout(server, _sessionWithHint(linked, hint=None))
    assertStatusOk(resp)
    assert 'id_token_hint' not in _params(resp.json['url'])


@pytest.mark.plugin('oidc')
def test_logout_is_a_no_op_when_the_provider_has_no_logout_endpoint(
        server, configured, linked, monkeypatch):
    monkeypatch.setattr(
        OidcClient, '_load',
        lambda self: ({'issuer': ISSUER, 'jwks_uri': ISSUER + '/certs'},
                      {'keys': []}))
    resp = _logout(server, _sessionWithHint(linked))
    assertStatusOk(resp)
    assert resp.json['url'] is None


@pytest.mark.plugin('oidc')
def test_unreachable_provider_does_not_break_logout(
        server, configured, linked, monkeypatch):
    """Discovery is a network call. If it fails the user must still be able to
    sign out of Girder, so this answers 200 with no url rather than 5xx."""
    def unreachable(self):
        raise RestException('OIDC provider request failed', code=502)
    monkeypatch.setattr(OidcClient, '_load', unreachable)
    resp = _logout(server, _sessionWithHint(linked))
    assertStatusOk(resp)
    assert resp.json['url'] is None


@pytest.mark.plugin('oidc')
def test_hint_is_read_from_the_caller_own_session(
        server, configured, linked, admin):
    """The hint is per-session state, so one user's token must never surface
    another's ID token."""
    Token().save(dict(_sessionWithHint(linked, hint='alice-id-token')))
    adminToken = _sessionWithHint(admin, hint=None)
    admin['oidc'] = [{'provider': 'oidc', 'id': 'sub-admin'}]
    User().save(admin)

    resp = _logout(server, adminToken)
    assertStatusOk(resp)
    assert 'alice-id-token' not in resp.json['url']


# --- the hint is stored at login ---------------------------------------------

class _FakeOidcClient:
    """Drives the callback end to end without a provider."""

    def exchangeCode(self, code, codeVerifier, redirectUri):
        return {'id_token': HINT}

    def validateIdToken(self, idToken, nonce):
        return {'sub': SUB, 'email': 'alice@example.com',
                'email_verified': True, 'given_name': 'Al', 'family_name': 'Ice'}


def _login(server, monkeypatch):
    monkeypatch.setattr(oidc_rest, 'OidcClient', _FakeOidcClient)
    state = Token().createToken(
        days=_STATE_TTL_MINUTES / 1440, scope=_STATE_SCOPE)
    state['oidc'] = {'codeVerifier': 'v', 'nonce': 'n', 'redirect': '/',
                     'browserSecret': STATE_SECRET}
    Token().save(state)
    resp = server.request(
        path='/oidc/callback', method='GET',
        params={'state': str(state['_id']), 'code': 'auth-code'},
        cookie='%s=%s' % (_STATE_COOKIE, STATE_SECRET), isJson=False)
    assert resp.output_status[:3] == b'303'
    return Token().findOne({'oidcLogout.idToken': HINT})


@pytest.mark.plugin('oidc')
def test_login_stores_the_logout_hint_on_the_session(
        server, configured, monkeypatch):
    stored = _login(server, monkeypatch)
    assert stored is not None
    assert stored['userId'] is not None


@pytest.mark.plugin('oidc')
def test_login_stores_no_hint_when_propagation_is_off(
        server, configured, monkeypatch):
    """Nothing is kept at rest for a feature that is switched off."""
    Setting().set(PluginSettings.PROPAGATE_LOGOUT, False)
    assert _login(server, monkeypatch) is None


@pytest.mark.plugin('oidc')
def test_hint_does_not_make_a_session_token_usable_as_login_state(
        server, configured, linked):
    """`callback` recognises its own state tokens by an `oidc` key and consumes
    them on sight. A session token carrying the hint under that key would be
    destroyed by anyone who replayed it as `state`, so it is stored elsewhere."""
    session = _sessionWithHint(linked)
    assert 'oidc' not in session

    resp = server.request(
        path='/oidc/callback', method='GET',
        params={'state': str(session['_id']), 'code': 'auth-code'},
        cookie='%s=%s' % (_STATE_COOKIE, STATE_SECRET), isJson=True)
    assertStatus(resp, 403)
    # Still a valid session afterwards.
    assert Token().load(str(session['_id']), objectId=False, force=True) is not None
