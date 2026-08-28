"""REST-level tests for the callback's browser binding and the token handoff.

These plant a state token directly rather than driving `GET /oidc/login`, which
would need a live provider for discovery. The checks under test both run before
any provider call, so nothing here touches the network.
"""

import pytest

from pytest_girder.assertions import assertStatus, assertStatusOk

from girder.models.token import Token

from girder_oidc.rest import (_HANDOFF_SCOPE, _HANDOFF_TTL_SECONDS, _STATE_COOKIE,
                              _STATE_SCOPE, _STATE_TTL_MINUTES)

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
