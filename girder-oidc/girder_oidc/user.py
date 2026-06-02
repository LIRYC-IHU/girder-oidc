import re

from girder.exceptions import RestException, ValidationException
from girder.models.setting import Setting
from girder.models.user import User
from girder.settings import SettingKey

from .settings import PluginSettings

PROVIDER = 'oidc'


def _generateLogins(email, firstName, lastName, userName=None):
    """Yield candidate login names for a new user, in order of preference."""
    if userName:
        yield userName
        yield re.sub(r'[\W_]+', '', userName)
        for i in range(1, 6):
            yield '%s%d' % (userName, i)

    prefix = email.split('@')[0]
    yield prefix
    yield re.sub(r'[\W_]+', '', prefix)

    yield '%s%s' % (firstName, lastName)
    for i in range(1, 6):
        yield '%s%s%d' % (firstName, lastName, i)


def _testLogin(login):
    try:
        User()._validateLogin(login)
    except ValidationException:
        return False
    return not User().findOne({'login': login})


def _deriveLogin(email, firstName, lastName, userName=None):
    for login in _generateLogins(email, firstName, lastName, userName):
        login = login.lower()
        if _testLogin(login):
            return login
    raise RestException(
        'Could not generate a unique login for %s.' % email, code=400)


def _resolveNames(firstName, lastName, fullName, userName, email):
    """Girder requires non-empty first/last names, but many IdPs omit the
    given_name/family_name claims. Fall back to the full ``name`` claim, then
    the username, then the email local-part so account creation never fails."""
    first = (firstName or '').strip()
    last = (lastName or '').strip()
    if not first or not last:
        parts = (fullName or '').split()
        if not first and parts:
            first = parts[0]
        if not last and len(parts) > 1:
            last = ' '.join(parts[1:])
    base = (userName or email.split('@')[0]).strip()
    return first or base, last or base


def claimGrantsAdmin(claims, claimName, claimValue):
    """Decide whether an ID token's claims confer Girder site-admin.

    Returns ``None`` when admin mapping is disabled (no claim configured), so the
    caller can leave the existing admin flag untouched. Otherwise returns a bool:
    list claims match on membership, scalar claims on equality, and a blank
    configured value matches any truthy claim (e.g. a boolean ``is_admin``)."""
    if not claimName:
        return None
    actual = claims.get(claimName)
    if isinstance(actual, (list, tuple, set)):
        if claimValue:
            return claimValue in [str(v) for v in actual]
        return len(actual) > 0
    if claimValue:
        return str(actual) == claimValue
    return bool(actual)


def createOrReuseUser(oidcId, email, firstName='', lastName='', userName=None,
                      fullName=None, admin=None):
    """
    Look up the Girder user for an OIDC identity, creating one if needed.

    Matches first on the stored ``(provider, id)`` pair, then on email, and
    finally creates a passwordless user (subject to the auto-create and
    registration-policy settings). Mirrors the girder-oauth provisioning model.

    ``admin`` is the site-admin flag derived from the ID token (see
    :func:`claimGrantsAdmin`). ``None`` means admin mapping is disabled and the
    existing flag is left as-is; a bool fully syncs it (grant or revoke).
    """
    settings = Setting()

    query = {'oidc.provider': PROVIDER, 'oidc.id': oidcId}
    user = User().findOne(query)
    setId = not user

    if not user:
        user = User().findOne({'email': email.lower()})

    dirty = False
    if not user:
        if not settings.get(PluginSettings.AUTO_CREATE_USERS):
            raise RestException(
                'No Girder account is linked to this identity, and automatic '
                'account creation is disabled. Contact an administrator.', code=403)

        policy = settings.get(SettingKey.REGISTRATION_POLICY)
        if policy == 'closed' and not settings.get(PluginSettings.IGNORE_REGISTRATION_POLICY):
            raise RestException(
                'Registration on this instance is closed. Contact an '
                'administrator to create an account for you.', code=403)

        first, last = _resolveNames(firstName, lastName, fullName, userName, email)
        login = _deriveLogin(email, first, last, userName)
        user = User().createUser(
            login=login, password=None, firstName=first, lastName=last,
            email=email, admin=bool(admin))
    else:
        if email.lower() != user['email']:
            user['email'] = email.lower()
            dirty = True
        if firstName and firstName != user['firstName']:
            user['firstName'] = firstName
            dirty = True
        if lastName and lastName != user['lastName']:
            user['lastName'] = lastName
            dirty = True
        if admin is not None and bool(admin) != bool(user.get('admin')):
            user['admin'] = bool(admin)
            dirty = True

    if setId:
        user.setdefault('oidc', []).append({'provider': PROVIDER, 'id': oidcId})
        dirty = True

    if dirty:
        user = User().save(user)

    return user
