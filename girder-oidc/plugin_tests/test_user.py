"""Database-backed tests for OIDC user provisioning."""

import pytest

from girder.exceptions import RestException
from girder.models.setting import Setting
from girder.models.user import User
from girder.settings import SettingKey

from girder_oidc.settings import PluginSettings
from girder_oidc.user import claimGrantsAdmin, createOrReuseUser


@pytest.mark.plugin('oidc')
def test_creates_passwordless_user(server):
    user = createOrReuseUser('sub-1', 'alice@example.com', 'Alice', 'Smith')
    assert user['email'] == 'alice@example.com'
    assert user['login']
    assert user['oidc'] == [{'provider': 'oidc', 'id': 'sub-1'}]
    # No usable password was set.
    assert not User().hasPassword(user)


@pytest.mark.plugin('oidc')
def test_falls_back_to_name_then_email_when_names_missing(server):
    # IdP supplied no given_name/family_name and no full name: both names must
    # still be non-empty (Girder rejects empty names) — fall back to the email.
    user = createOrReuseUser('sub-n1', 'noname@example.com')
    assert user['firstName'] == 'noname'
    assert user['lastName'] == 'noname'
    # A full `name` claim is split into first/last.
    user2 = createOrReuseUser('sub-n2', 'fn@example.com', fullName='Grace Hopper')
    assert user2['firstName'] == 'Grace'
    assert user2['lastName'] == 'Hopper'


@pytest.mark.plugin('oidc')
def test_reuses_user_by_oidc_id(server):
    first = createOrReuseUser('sub-2', 'bob@example.com', 'Bob', 'B')
    again = createOrReuseUser('sub-2', 'bob@example.com', 'Bob', 'B')
    assert first['_id'] == again['_id']
    assert len(again['oidc']) == 1


@pytest.mark.plugin('oidc')
def test_links_existing_user_by_email(server):
    existing = User().createUser(
        login='carol', password='password123', firstName='Carol', lastName='C',
        email='carol@example.com')
    linked = createOrReuseUser('sub-3', 'carol@example.com', 'Carol', 'C')
    assert linked['_id'] == existing['_id']
    assert any(o['id'] == 'sub-3' for o in linked['oidc'])


@pytest.mark.plugin('oidc')
def test_auto_create_disabled_blocks_new_user(server):
    Setting().set(PluginSettings.AUTO_CREATE_USERS, False)
    try:
        with pytest.raises(RestException):
            createOrReuseUser('sub-4', 'dave@example.com', 'Dave', 'D')
    finally:
        Setting().set(PluginSettings.AUTO_CREATE_USERS, True)


def test_claim_grants_admin_semantics():
    # Disabled when no claim name is configured.
    assert claimGrantsAdmin({'groups': ['x']}, '', '') is None
    # List claim: membership.
    assert claimGrantsAdmin({'groups': ['a', 'b']}, 'groups', 'b') is True
    assert claimGrantsAdmin({'groups': ['a', 'b']}, 'groups', 'c') is False
    # List claim, blank value: any non-empty list.
    assert claimGrantsAdmin({'groups': ['a']}, 'groups', '') is True
    assert claimGrantsAdmin({'groups': []}, 'groups', '') is False
    # Scalar claim: equality.
    assert claimGrantsAdmin({'role': 'admin'}, 'role', 'admin') is True
    assert claimGrantsAdmin({'role': 'user'}, 'role', 'admin') is False
    # Scalar claim, blank value: truthiness (e.g. boolean is_admin).
    assert claimGrantsAdmin({'is_admin': True}, 'is_admin', '') is True
    assert claimGrantsAdmin({'is_admin': False}, 'is_admin', '') is False
    # Missing claim is not admin.
    assert claimGrantsAdmin({}, 'groups', 'x') is False


@pytest.mark.plugin('oidc')
def test_admin_mapping_grants_and_revokes(server):
    # Claim says admin at creation: account is created as a site admin.
    user = createOrReuseUser('sub-adm', 'frank@example.com', 'Frank', 'F',
                             admin=True)
    assert user['admin'] is True
    # Next login without the claim (full sync) revokes admin.
    user = createOrReuseUser('sub-adm', 'frank@example.com', 'Frank', 'F',
                             admin=False)
    assert user['admin'] is False
    # admin=None (mapping disabled) leaves the flag untouched.
    user['admin'] = True
    User().save(user)
    user = createOrReuseUser('sub-adm', 'frank@example.com', 'Frank', 'F',
                             admin=None)
    assert user['admin'] is True


@pytest.mark.plugin('oidc')
def test_closed_registration_blocks_new_user(server):
    Setting().set(SettingKey.REGISTRATION_POLICY, 'closed')
    try:
        with pytest.raises(RestException):
            createOrReuseUser('sub-5', 'erin@example.com', 'Erin', 'E')
        # ...unless the policy is explicitly ignored.
        Setting().set(PluginSettings.IGNORE_REGISTRATION_POLICY, True)
        user = createOrReuseUser('sub-5', 'erin@example.com', 'Erin', 'E')
        assert user['email'] == 'erin@example.com'
    finally:
        Setting().set(SettingKey.REGISTRATION_POLICY, 'open')
        Setting().set(PluginSettings.IGNORE_REGISTRATION_POLICY, False)
