"""Database-backed tests for mirroring provider groups into Girder groups."""

import pytest

from girder.constants import AccessType
from girder.models.collection import Collection
from girder.models.group import Group
from girder.models.setting import Setting
from girder.models.user import User

from girder_oidc.groups import _claimGroupValues, syncUserGroups
from girder_oidc.settings import PluginSettings


@pytest.fixture
def groupsClaim():
    """Turn the sync on, as an administrator would."""
    Setting().set(PluginSettings.GROUPS_CLAIM, 'groups')
    yield 'groups'
    Setting().unset(PluginSettings.GROUPS_CLAIM)


def _user(login='alice'):
    return User().createUser(
        login=login, password='password123', firstName='A', lastName='B',
        email='%s@example.com' % login)


def _groupNames(user):
    return sorted(
        Group().load(groupId, force=True)['name']
        for groupId in User().load(user['_id'], force=True).get('groups', []))


def test_claim_values_shapes():
    # The usual shape: a list of names.
    assert _claimGroupValues({'groups': ['a', 'b']}, 'groups') == ['a', 'b']
    # Keycloak sends group *paths*; the leading slash is not part of the name,
    # the rest of the path is what makes it unique.
    assert _claimGroupValues(
        {'groups': ['/liryc/recherche']}, 'groups') == ['liryc/recherche']
    # A provider emitting a single group unwrapped still works.
    assert _claimGroupValues({'groups': 'solo'}, 'groups') == ['solo']
    # Duplicates collapse, order is kept, blanks and non-strings are dropped.
    assert _claimGroupValues(
        {'groups': ['b', 'a', 'b', '', '  ', 7, {'x': 1}]}, 'groups') == ['b', 'a']
    # Nested claims, as for a keycloak per-client role.
    assert _claimGroupValues(
        {'resource_access': {'girder': {'roles': ['r']}}},
        'resource_access.girder.roles') == ['r']
    # Absent is None -- distinct from an empty list, which is [].
    assert _claimGroupValues({}, 'groups') is None
    assert _claimGroupValues({'groups': None}, 'groups') is None
    assert _claimGroupValues({'groups': []}, 'groups') == []


@pytest.mark.plugin('oidc')
def test_no_claim_configured_is_a_no_op(server, admin):
    user = _user('nosync')
    syncUserGroups(user, {'groups': ['research']})
    assert _groupNames(user) == []
    assert Group().findOne({'lowerName': 'research'}) is None


@pytest.mark.plugin('oidc')
def test_creates_group_and_membership(server, admin, groupsClaim):
    user = _user('newmember')
    syncUserGroups(user, {'groups': ['research']})

    group = Group().findOne({'lowerName': 'research'})
    assert group is not None
    assert group['oidc'] == {'provider': 'oidc', 'claim': 'research'}
    # Mirrored groups are private, and carry no member of their own: the site
    # admin who had to create the document is not left inside it.
    assert group['public'] is False
    assert [member['login'] for member in Group().listMembers(group)] == ['newmember']
    assert _groupNames(user) == ['research']


@pytest.mark.plugin('oidc')
def test_second_user_joins_the_same_group(server, admin, groupsClaim):
    first, second = _user('first'), _user('second')
    syncUserGroups(first, {'groups': ['shared']})
    syncUserGroups(second, {'groups': ['shared']})

    groups = list(Group().find({'lowerName': 'shared'}))
    assert len(groups) == 1
    assert sorted(m['login'] for m in Group().listMembers(groups[0])) == \
        ['first', 'second']


@pytest.mark.plugin('oidc')
def test_group_grants_access_to_a_collection(server, admin, groupsClaim):
    """The point of the whole thing: an ACL entry for the mirrored group is what
    gives its members access, with no per-user bookkeeping on the collection."""
    user = _user('reader')
    collection = Collection().createCollection(
        'Study data', creator=admin, public=False)
    assert Collection().hasAccess(collection, user, AccessType.READ) is False

    syncUserGroups(user, {'groups': ['study-team']})
    group = Group().findOne({'lowerName': 'study-team'})
    Collection().setGroupAccess(collection, group, AccessType.READ, save=True)

    user = User().load(user['_id'], force=True)
    collection = Collection().load(collection['_id'], force=True)
    assert Collection().hasAccess(collection, user, AccessType.READ) is True
    assert Collection().hasAccess(collection, user, AccessType.WRITE) is False


@pytest.mark.plugin('oidc')
def test_membership_is_revoked_when_the_group_disappears(server, admin, groupsClaim):
    user = _user('mover')
    syncUserGroups(user, {'groups': ['a', 'b']})
    assert _groupNames(user) == ['a', 'b']

    syncUserGroups(user, {'groups': ['b']})
    assert _groupNames(user) == ['b']

    # Present but empty means "in no group", and does revoke.
    syncUserGroups(user, {'groups': []})
    assert _groupNames(user) == []
    # The groups themselves survive; they are still referenced by ACLs.
    assert Group().findOne({'lowerName': 'a'}) is not None


@pytest.mark.plugin('oidc')
def test_absent_claim_never_revokes(server, admin, groupsClaim):
    """A mapper switched off at the provider must not strip the instance of its
    memberships, one login at a time."""
    user = _user('kept')
    syncUserGroups(user, {'groups': ['keepme']})
    syncUserGroups(user, {'sub': 'kept'})
    assert _groupNames(user) == ['keepme']


@pytest.mark.plugin('oidc')
def test_non_authoritative_only_adds(server, admin, groupsClaim):
    user = _user('additive')
    syncUserGroups(user, {'groups': ['x', 'y']})
    Setting().set(PluginSettings.GROUPS_AUTHORITATIVE, False)
    try:
        syncUserGroups(user, {'groups': ['x']})
        assert _groupNames(user) == ['x', 'y']
    finally:
        Setting().unset(PluginSettings.GROUPS_AUTHORITATIVE)


@pytest.mark.plugin('oidc')
def test_hand_made_groups_are_left_alone(server, admin, groupsClaim):
    """Neither taken over by a claim of the same name, nor revoked by a sync."""
    local = Group().createGroup('Local team', creator=admin, public=False)
    user = _user('mixed')
    Group().addUser(local, user, level=AccessType.READ)

    syncUserGroups(user, {'groups': ['Local team', 'mirrored']})

    # The name collision was refused rather than adopted: no marker was added,
    # and the group did not become a mirror of the provider's.
    local = Group().load(local['_id'], force=True)
    assert 'oidc' not in local
    assert len(list(Group().find({'lowerName': 'local team'}))) == 1

    # A later sync that mentions neither leaves the hand-made membership alone.
    syncUserGroups(user, {'groups': []})
    assert _groupNames(user) == ['Local team']


@pytest.mark.plugin('oidc')
def test_name_prefix_keeps_the_two_name_spaces_apart(server, admin, groupsClaim):
    Group().createGroup('Local team', creator=admin, public=False)
    Setting().set(PluginSettings.GROUP_NAME_PREFIX, 'IdP: ')
    try:
        user = _user('prefixed')
        syncUserGroups(user, {'groups': ['Local team']})
        assert _groupNames(user) == ['IdP: Local team']
        assert Group().findOne(
            {'lowerName': 'idp: local team'})['oidc']['claim'] == 'Local team'
    finally:
        Setting().unset(PluginSettings.GROUP_NAME_PREFIX)


@pytest.mark.plugin('oidc')
def test_group_is_found_by_its_claim_not_its_name(server, admin, groupsClaim):
    """An administrator may rename a mirrored group; the marker, not the name,
    is what ties it to the provider."""
    user = _user('renamer')
    syncUserGroups(user, {'groups': ['old-name']})
    group = Group().findOne({'lowerName': 'old-name'})
    group['name'] = 'Renamed by an admin'
    Group().save(group)

    syncUserGroups(user, {'groups': ['old-name']})
    assert len(list(Group().find({'oidc.claim': 'old-name'}))) == 1
    assert _groupNames(user) == ['Renamed by an admin']
