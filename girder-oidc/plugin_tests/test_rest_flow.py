"""REST-level tests for the callback's browser binding and the token handoff.

These plant a state token directly rather than driving `GET /oidc/login`, which
would need a live provider for discovery. The checks under test both run before
any provider call, so nothing here touches the network.
"""

from urllib.parse import parse_qs, urlparse

import pytest

from pytest_girder.assertions import assertStatus, assertStatusOk

from girder.models.setting import Setting
from girder.models.token import Token
from girder.models.user import User

from girder_oidc import rest as oidc_rest
from girder_oidc.rest import (_HANDOFF_SCOPE, _HANDOFF_TTL_SECONDS, _STATE_COOKIE,
                              _STATE_SCOPE, _STATE_TTL_MINUTES)
from girder_oidc.settings import PluginSettings

SECRET = 'the-browser-secret'


def _stateToken(browserSecret=SECRET):
    token = Token().createToken(
        days=_STATE_TTL_MINUTES / 1440, scope=_STATE_SCOPE)
    token['oidc'] = {
        'codeVerifier': 'verifier', 'nonce': 'nonce', 'redirect': '/',
        'browserSecret': browserSecret,
    }
    return Token().save(token)


def _handoffToken(sessionToken):
    token = Token().createToken(
        days=_HANDOFF_TTL_SECONDS / 86400, scope=_HANDOFF_SCOPE)
    token['oidcHandoff'] = str(sessionToken['_id'])
    return Token().save(token)


@pytest.mark.plugin('oidc')
def test_callback_without_state_cookie_is_refused(server):
    """Login CSRF guard: a valid state plus code is not enough on its own. An
    attacker who runs the flow against their own account must not be able to
    replay the result into a victim's browser."""
    state = _stateToken()
    resp = server.request(
        path='/oidc/callback', method='GET',
        params={'state': str(state['_id']), 'code': 'auth-code'})
    assertStatus(resp, 403)
    assert 'this browser' in resp.json['message']


@pytest.mark.plugin('oidc')
def test_callback_with_wrong_state_cookie_is_refused(server):
    state = _stateToken()
    resp = server.request(
        path='/oidc/callback', method='GET',
        params={'state': str(state['_id']), 'code': 'auth-code'},
        cookie='%s=not-the-secret' % _STATE_COOKIE)
    assertStatus(resp, 403)


@pytest.mark.plugin('oidc')
def test_callback_consumes_the_state_token(server):
    state = _stateToken()
    server.request(
        path='/oidc/callback', method='GET',
        params={'state': str(state['_id']), 'code': 'auth-code'})
    assert Token().load(str(state['_id']), objectId=False, force=True) is None


@pytest.mark.plugin('oidc')
def test_handoff_code_yields_the_token_once(server, admin):
    session = Token().createToken(admin)
    handoff = _handoffToken(session)

    resp = server.request(path='/oidc/exchange', method='POST',
                          params={'code': str(handoff['_id'])})
    assertStatusOk(resp)
    assert resp.json['token'] == str(session['_id'])

    # Single use: the code is gone.
    resp = server.request(path='/oidc/exchange', method='POST',
                          params={'code': str(handoff['_id'])})
    assertStatus(resp, 403)


@pytest.mark.plugin('oidc')
def test_exchange_rejects_a_plain_session_token(server, admin):
    """The endpoint is public, so it must only ever redeem tokens it minted --
    handing back an arbitrary token would turn a stolen id into a session."""
    session = Token().createToken(admin)
    resp = server.request(path='/oidc/exchange', method='POST',
                          params={'code': str(session['_id'])})
    assertStatus(resp, 403)


@pytest.mark.plugin('oidc')
def test_exchange_rejects_unknown_code(server):
    resp = server.request(path='/oidc/exchange', method='POST',
                          params={'code': 'nope'})
    assertStatus(resp, 403)


# --- The access filter --------------------------------------------------------
#
# `oidc.required_claim` refuses an identity the provider was willing to
# authenticate. It is a post-authentication refusal by design -- the token
# already exists by the time we see it -- so what these pin is that nothing is
# left behind for a refused identity.


class _FakeOidcClient:
    """Stands in for the real client so the callback can be driven end to end
    without a provider. Everything under test happens after token validation."""

    claims = {}

    def exchangeCode(self, code, codeVerifier, redirectUri):
        return {'id_token': 'signed.id.token'}

    def validateIdToken(self, idToken, nonce):
        return dict(self.claims)


@pytest.fixture
def fakeProvider(monkeypatch):
    monkeypatch.setattr(oidc_rest, 'OidcClient', _FakeOidcClient)

    def setClaims(**claims):
        _FakeOidcClient.claims = claims
    yield setClaims
    _FakeOidcClient.claims = {}


@pytest.fixture
def accessFilter():
    """Gate logins on a keycloak per-client role, then put the settings back."""
    Setting().set(PluginSettings.REQUIRED_CLAIM, 'resource_access.girder.roles')
    Setting().set(PluginSettings.REQUIRED_CLAIM_VALUE, 'access')
    yield
    Setting().set(PluginSettings.REQUIRED_CLAIM, '')
    Setting().set(PluginSettings.REQUIRED_CLAIM_VALUE, '')


def _callback(server, state, isJson=True):
    # A successful callback ends in a redirect with an empty body, so those
    # calls have to opt out of pytest-girder's JSON parsing.
    return server.request(
        path='/oidc/callback', method='GET',
        params={'state': str(state['_id']), 'code': 'auth-code'},
        cookie='%s=%s' % (_STATE_COOKIE, SECRET), isJson=isJson)


def _errorFrom(resp):
    """The message the callback handed back to the web client, if any."""
    location = resp.headers['Location']
    return parse_qs(urlparse(location).query).get('girderOidcError', [None])[0]


@pytest.mark.plugin('oidc')
def test_callback_refuses_an_identity_without_the_required_claim(
        server, fakeProvider, accessFilter):
    # A realm shared with other applications: this identity holds the role of a
    # different client, which must not admit it here.
    fakeProvider(sub='sub-denied', email='denied@example.com',
                 email_verified=True, given_name='De', family_name='Nied',
                 resource_access={'other-app': {'roles': ['access']}})

    resp = _callback(server, _stateToken(), isJson=False)
    # A refusal comes back as a redirect carrying the message, not as a REST
    # error: this route is a top-level browser navigation, so a raw JSON error
    # document is what the user would otherwise be left staring at.
    assertStatus(resp, 303)
    assert 'has not granted you access' in _errorFrom(resp)
    # The whole point of refusing this early: no account was provisioned.
    assert User().findOne({'email': 'denied@example.com'}) is None


@pytest.mark.plugin('oidc')
def test_callback_hands_a_provider_error_to_the_web_client(server):
    """The provider reports a failed or cancelled login on the same redirect."""
    resp = server.request(
        path='/oidc/callback', method='GET',
        params={'state': str(_stateToken()['_id']), 'error': 'access_denied'},
        cookie='%s=%s' % (_STATE_COOKIE, SECRET), isJson=False)
    assertStatus(resp, 303)
    assert 'access_denied' in _errorFrom(resp)


@pytest.mark.plugin('oidc')
def test_provider_error_still_requires_a_valid_state(server):
    """`error` is only acted on once the state and browser binding check out --
    otherwise anyone could drive this endpoint into the redirect path."""
    resp = server.request(
        path='/oidc/callback', method='GET',
        params={'state': str(_stateToken()['_id']), 'error': 'access_denied'})
    assertStatus(resp, 403)


@pytest.mark.plugin('oidc')
def test_callback_admits_an_identity_carrying_the_required_claim(
        server, fakeProvider, accessFilter):
    fakeProvider(sub='sub-allowed', email='allowed@example.com',
                 email_verified=True, given_name='Al', family_name='Lowed',
                 resource_access={'girder': {'roles': ['access']}})

    resp = _callback(server, _stateToken(), isJson=False)
    # The callback ends in a redirect back to the web client with a handoff code.
    assertStatus(resp, 303)
    assert User().findOne({'email': 'allowed@example.com'}) is not None


@pytest.mark.plugin('oidc')
def test_callback_admits_everyone_when_no_claim_is_configured(server, fakeProvider):
    """The filter is opt-in: an instance that has not set one must keep letting
    every identity the provider authenticates in."""
    fakeProvider(sub='sub-open', email='open@example.com', email_verified=True,
                 given_name='O', family_name='Pen')

    resp = _callback(server, _stateToken(), isJson=False)
    assertStatus(resp, 303)
    assert User().findOne({'email': 'open@example.com'}) is not None


@pytest.fixture
def adminClaimOnRoles():
    Setting().set(PluginSettings.ADMIN_CLAIM, 'resource_access.girder.roles')
    Setting().set(PluginSettings.ADMIN_CLAIM_VALUE, 'admin')
    yield
    Setting().set(PluginSettings.ADMIN_CLAIM, '')
    Setting().set(PluginSettings.ADMIN_CLAIM_VALUE, '')


@pytest.mark.plugin('oidc')
def test_admin_claim_is_synced_in_both_directions(
        server, fakeProvider, adminClaimOnRoles, admin):
    """Through the real callback, not just the helper: the site-admin flag
    follows the claim on every login, granted *and* revoked.

    The `admin` fixture is a second site admin, so the revocation below is not
    blocked by the last-admin guard.
    """
    def login(roles):
        fakeProvider(sub='sub-sync', email='sync@example.com', email_verified=True,
                     given_name='Sy', family_name='Nc',
                     resource_access={'girder': {'roles': roles}})
        resp = _callback(server, _stateToken(), isJson=False)
        assertStatus(resp, 303)
        return User().findOne({'email': 'sync@example.com'})

    # First login without the role: an ordinary account.
    assert login(['access'])['admin'] is False
    # The role is granted at the provider; the next login picks it up.
    assert login(['access', 'admin'])['admin'] is True
    # ...and withdrawing it at the provider takes it away again.
    assert login(['access'])['admin'] is False


@pytest.mark.plugin('oidc')
def test_a_claim_absent_from_the_token_revokes_admin(
        server, fakeProvider, adminClaimOnRoles, admin):
    """The footgun of a full sync: a claim name that resolves to nothing is not
    "leave it alone", it is "not an admin". A mistyped claim path therefore
    demotes every OIDC user on their next login."""
    fakeProvider(sub='sub-lost', email='lost@example.com', email_verified=True,
                 given_name='Lo', family_name='St',
                 resource_access={'girder': {'roles': ['access', 'admin']}})
    assertStatus(_callback(server, _stateToken(), isJson=False), 303)
    assert User().findOne({'email': 'lost@example.com'})['admin'] is True

    # Same token, but the setting now points at a claim the token has no such
    # thing as -- exactly `oidc.admin_claim = "admin"` against a keycloak token.
    Setting().set(PluginSettings.ADMIN_CLAIM, 'admin')
    assertStatus(_callback(server, _stateToken(), isJson=False), 303)
    assert User().findOne({'email': 'lost@example.com'})['admin'] is False
