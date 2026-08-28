"""REST-level tests for the externally-managed account guards: OIDC users may
not edit their profile, change their password, or enable two-factor auth."""

import pytest

from pytest_girder.assertions import assertStatus, assertStatusOk

from girder.models.user import User
from girder.utility import mail_utils

from girder_oidc.user import createOrReuseUser


def _oidcUser():
    return createOrReuseUser('guard-sub', 'managed@example.com', 'Man', 'Aged',
                             emailVerified=True)


@pytest.mark.plugin('oidc')
def test_oidc_user_cannot_edit_profile(server):
    user = _oidcUser()
    resp = server.request(
        path='/user/%s' % user['_id'], method='PUT', user=user,
        params={'firstName': 'Hacked', 'lastName': user['lastName'],
                'email': user['email']})
    assertStatus(resp, 403)
    assert 'identity provider' in resp.json['message']
    # The name was not persisted.
    assert User().load(user['_id'], force=True)['firstName'] == 'Man'


@pytest.mark.plugin('oidc')
def test_oidc_user_cannot_change_password(server):
    user = _oidcUser()
    resp = server.request(
        path='/user/password', method='PUT', user=user,
        params={'old': 'whatever', 'new': 'newpassword123'})
    assertStatus(resp, 403)


@pytest.mark.plugin('oidc')
def test_oidc_user_cannot_enable_otp(server):
    user = _oidcUser()
    resp = server.request(
        path='/user/%s/otp' % user['_id'], method='POST', user=user)
    assertStatus(resp, 403)


@pytest.mark.plugin('oidc')
def test_oidc_field_exposed_on_self(server):
    user = _oidcUser()
    resp = server.request(path='/user/me', method='GET', user=user)
    assertStatusOk(resp)
    assert len(resp.json['oidc']) == 1
    assert resp.json['oidc'][0]['id'] == 'guard-sub'


@pytest.mark.plugin('oidc')
def test_oidc_user_cannot_request_temporary_password(server):
    """Girder's temporary-access flow issues a full session token before any
    password is set, so it would otherwise be a way into an OIDC account that
    never touches the identity provider (and its MFA)."""
    user = _oidcUser()
    resp = server.request(
        path='/user/password/temporary', method='PUT',
        params={'email': user['email']})
    assertStatus(resp, 403)
    assert 'identity provider' in resp.json['message']


@pytest.mark.plugin('oidc')
def test_oidc_user_cannot_redeem_temporary_password(server):
    user = _oidcUser()
    resp = server.request(
        path='/user/password/temporary/%s' % user['_id'], method='GET',
        params={'token': 'irrelevant'})
    assertStatus(resp, 403)


@pytest.mark.plugin('oidc')
def test_local_user_can_still_request_temporary_password(server, monkeypatch):
    """The guard must be surgical: a plain Girder account still gets its reset
    email. Girder sends it inline, so stub the SMTP call out."""
    sent = []
    monkeypatch.setattr(mail_utils, 'sendMail',
                        lambda *args, **kwargs: sent.append(args))

    User().createUser(
        login='resetme', password='password123', firstName='Reset',
        lastName='Me', email='resetme@example.com')
    resp = server.request(
        path='/user/password/temporary', method='PUT',
        params={'email': 'resetme@example.com'})
    assertStatusOk(resp)
    assert sent


@pytest.mark.plugin('oidc')
def test_local_user_can_still_edit_profile(server):
    user = User().createUser(
        login='localuser', password='password123', firstName='Local',
        lastName='User', email='local@example.com')
    resp = server.request(
        path='/user/%s' % user['_id'], method='PUT', user=user,
        params={'firstName': 'Renamed', 'lastName': 'User',
                'email': 'local@example.com'})
    assertStatusOk(resp)
    assert User().load(user['_id'], force=True)['firstName'] == 'Renamed'


# The `admin` fixture matters in the two tests below: girder promotes the very
# first account it creates to site-admin, so without an admin already on record
# the "plain user" would silently be one, and these would pass even with the
# guards mis-registered.

@pytest.mark.plugin('oidc')
def test_non_admin_can_still_edit_own_profile(server, admin):
    """Regression: every handler bound to a `rest.*.before` event must declare
    an access level. Without one girder falls back to requiring site-admin for
    the whole route, which would lock ordinary local users out of their own
    profile -- an outage caused by merely installing this plugin."""
    user = User().createUser(
        login='plainuser', password='password123', firstName='Plain',
        lastName='User', email='plain@example.com')
    assert not user['admin']

    resp = server.request(
        path='/user/%s' % user['_id'], method='PUT', user=user,
        params={'firstName': 'Still', 'lastName': 'Fine',
                'email': 'plain@example.com'})
    assertStatusOk(resp)
    assert User().load(user['_id'], force=True)['firstName'] == 'Still'


@pytest.mark.plugin('oidc')
def test_non_admin_can_still_change_own_password(server, admin):
    user = User().createUser(
        login='pwuser', password='password123', firstName='Pw',
        lastName='User', email='pw@example.com')
    assert not user['admin']

    resp = server.request(
        path='/user/password', method='PUT', user=user,
        params={'old': 'password123', 'new': 'newpassword456'})
    assertStatusOk(resp)
    assert User().authenticate('pwuser', 'newpassword456')
