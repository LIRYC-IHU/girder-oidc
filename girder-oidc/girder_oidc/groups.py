"""Mirror the identity provider's groups into Girder groups.

Girder already has everything needed to grant access to a set of people: groups
(:class:`girder.models.group.Group`) are first-class entries in every ACL, so a
collection shared with a group is readable by its members and shows up in their
listings (the permission filter matches on ``user['groups']``). What is missing
is the link between "group at the provider" and "group in Girder" -- this module
is that link, and nothing here touches the permission model itself. An
administrator still grants access the ordinary way: collection → Access control
→ add the group → pick a level, optionally with ``recurse`` to push it down an
existing tree (new folders inherit their parent's ACL at creation).

Membership is reconciled at login, from a configurable claim
(``oidc.groups_claim``). Each value of that claim gets a Girder group, created on
first sight and stamped with an ``oidc`` marker; the reconciliation only ever
adds to or removes from *marked* groups, so groups maintained by hand in Girder
are never modified here.

Two failure modes drove the shape of the code:

* A claim that is missing entirely (a mapper switched off at the provider, a
  token that never carried it) must not be read as "this user is in no group" --
  that would strip every membership on the instance, one login at a time. Absent
  and present-but-empty are therefore treated differently: only the latter
  revokes.
* A name collision with a group somebody created by hand must not silently hand
  that group's members whatever the provider says. Such a value is skipped with
  a warning rather than adopted.
"""

import logging

from girder.constants import AccessType, SortDir
from girder.exceptions import ValidationException
from girder.models.group import Group
from girder.models.setting import Setting
from girder.models.user import User

from .settings import PluginSettings
from .user import PROVIDER, _resolveClaim

logger = logging.getLogger(__name__)

_GROUP_DESCRIPTION = (
    'Membership of this group is managed by the OIDC plugin, from the "%s" '
    'entry of the identity provider\'s group claim. Members are added and '
    'removed as they sign in; editing the member list here has no lasting '
    'effect.')


def _claimGroupValues(claims, claimName):
    """The group identifiers carried by ``claimName``, or ``None`` when the
    claim is absent from the token.

    A list claim (the usual shape: keycloak ``groups``, an OAuth2 ``roles``
    array) yields its members; a lone string yields itself, so a provider that
    emits a single group unwrapped still works. Values are de-duplicated,
    order-preserving, and stripped of the leading slash keycloak puts on group
    *paths* (``/liryc/recherche``) -- the rest of the path is kept, since that is
    what makes the value unique.
    """
    raw = _resolveClaim(claims, claimName)
    if raw is None:
        return None
    if isinstance(raw, (list, tuple, set)):
        rawValues = list(raw)
    else:
        rawValues = [raw]

    values = []
    for rawValue in rawValues:
        if not isinstance(rawValue, str):
            # Anything else (a nested object, a number) is not a group name any
            # provider would mean for us to act on.
            logger.debug('oidc: ignoring non-string entry in the %r claim: %r',
                         claimName, rawValue)
            continue
        value = rawValue.strip().lstrip('/').strip()
        if value and value not in values:
            values.append(value)
    return values


def _groupName(value):
    prefix = Setting().get(PluginSettings.GROUP_NAME_PREFIX) or ''
    return '%s%s' % (prefix, value)


def _findManagedGroup(value):
    return Group().findOne({'oidc.provider': PROVIDER, 'oidc.claim': value})


def _creator(user):
    """A site admin to own the group document at creation time.

    ``Group().createGroup`` requires a creator and makes them an admin *member*;
    we undo that membership straight after, so the group starts out with the
    provider as its only source of members. Preferring the user who is logging in
    (when they are a site admin) keeps us from writing to a second user document
    mid-login, which would otherwise race with our own copy of it.
    """
    if user.get('admin'):
        return user
    return User().findOne({'admin': True}, sort=[('created', SortDir.ASCENDING)])


def _ensureGroup(value, user):
    """The Girder group mirroring claim value ``value``, creating it if needed.

    Returns ``None`` when no group can be used for this value -- the reason is
    logged, and the caller simply grants no membership for it.
    """
    group = _findManagedGroup(value)
    if group is not None:
        return group

    name = _groupName(value)
    existing = Group().findOne({'lowerName': name.strip().lower()})
    if existing is not None:
        logger.warning(
            'oidc: the Girder group %r already exists and is not managed by '
            'this plugin, so the %r group from the identity provider was '
            'ignored. Rename one of the two, or set a value for '
            'oidc.group_name_prefix.', name, value)
        return None

    creator = _creator(user)
    if creator is None:
        # Only reachable on an instance with no site admin at all, which girder
        # itself does not really support -- but findOne would return None and
        # createGroup would raise a TypeError deep inside girder.
        logger.error(
            'oidc: cannot create the Girder group %r -- this instance has no '
            'site administrator to own it.', name)
        return None

    try:
        group = Group().createGroup(
            name=name, creator=creator, description=_GROUP_DESCRIPTION % value,
            public=False)
    except ValidationException:
        # Two logins for the same new group at once: the loser of the race finds
        # the winner's group here. Anything else (an empty name, say) leaves the
        # lookup empty and is reported.
        group = _findManagedGroup(value)
        if group is None:
            logger.exception(
                'oidc: could not create the Girder group %r for the %r group '
                'from the identity provider.', name, value)
        return group

    # createGroup grants the creator admin access *and* membership. A group whose
    # members come from the provider should have neither: site admins keep full
    # access to it regardless (Group.hasAccess short-circuits on the admin flag).
    Group().removeUser(group, creator)

    group['oidc'] = {'provider': PROVIDER, 'claim': value}
    return Group().save(group)


def syncUserGroups(user, claims):
    """Reconcile ``user``'s membership in OIDC-managed groups against ``claims``.

    A no-op unless ``oidc.groups_claim`` names a claim. Groups without the
    plugin's marker are never added to or removed from, whatever the token says.

    Removal is controlled by ``oidc.groups_authoritative`` (on by default): with
    it off the sync only ever adds, which suits an instance where an
    administrator may hand-grant membership of a mirrored group. It never applies
    to a claim that is absent from the token -- see the module docstring.

    Returns ``user``, whose ``groups`` list is updated in place.
    """
    settings = Setting()
    claimName = settings.get(PluginSettings.GROUPS_CLAIM)
    if not claimName:
        return user

    values = _claimGroupValues(claims, claimName)
    if values is None:
        logger.warning(
            'oidc: the ID token for %s carries no %r claim, so group membership '
            'was left untouched. Check that the provider is configured to emit '
            'it (and that the scope it needs is requested).',
            user['login'], claimName)
        return user

    # Snapshot before any change: addUser and removeUser both edit this list.
    memberships = list(user.get('groups', []))

    desired = {}
    for value in values:
        group = _ensureGroup(value, user)
        if group is not None:
            desired[group['_id']] = group

    for groupId, group in desired.items():
        if groupId not in memberships:
            Group().addUser(group, user, level=AccessType.READ)
            logger.info('oidc: added %s to the Girder group %r.',
                        user['login'], group['name'])

    if not settings.get(PluginSettings.GROUPS_AUTHORITATIVE):
        return user

    staleIds = [groupId for groupId in memberships if groupId not in desired]
    if staleIds:
        # The marker in the query is what keeps a hand-made group the user also
        # belongs to out of this.
        stale = list(Group().find({
            '_id': {'$in': staleIds},
            'oidc.provider': PROVIDER,
        }))
        for group in stale:
            Group().removeUser(group, user)
            logger.info('oidc: removed %s from the Girder group %r.',
                        user['login'], group['name'])
    return user
