"""REST-level tests for the externally-managed account guards: OIDC users may
not edit their profile, change their password, or enable two-factor auth."""

import pytest

from pytest_girder.assertions import assertStatus, assertStatusOk

from girder.models.user import User

from girder_oidc.user import createOrReuseUser


def _oidcUser():
    return createOrReuseUser('guard-sub', 'managed@example.com', 'Man', 'Aged')


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
