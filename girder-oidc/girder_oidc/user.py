import contextlib
import functools
import logging
import re
import threading

from girder.exceptions import RestException, ValidationException
from girder.models.setting import Setting
from girder.models.user import User
from girder.settings import SettingKey

from .settings import PluginSettings

# Girder 5 no longer exposes a `girder.logger`; its logging is configured on the
# root logger, so a module logger propagates into the same handlers.
logger = logging.getLogger(__name__)

PROVIDER = 'oidc'

# Set only for the duration of the `User().createUser` call we make below. The
# `email.verification` hook fires from inside that call, before we have had a
# chance to attach the `oidc` marker to the document, so inspecting the user is
# not enough to recognise our own provisioning -- hence a flag. Thread-local
# because girder serves each request on its own thread: a concurrent local
# registration must keep its verification email.
_provisioning = threading.local()


@contextlib.contextmanager
def _provisioningOidcUser():
    _provisioning.active = True
    try:
        yield
    finally:
        _provisioning.active = False


_SUPPRESSION_MARKER = '_oidcVerificationSuppressed'


def installVerificationEmailSuppression():
    """Stop girder mailing "please verify your address" for OIDC accounts.

    The address on an account provisioned here belongs to the identity provider,
    which has already vouched for it -- that is a precondition for reaching
    account creation at all -- and we mark the account verified straight after.
    The mail would ask the user to confirm, through Girder, something Girder has
    no say over, and on an instance with ``EMAIL_VERIFICATION`` set to
    ``required`` it would additionally lock every SSO user out until they
    clicked it.

    girder grew an ``email.verification`` event for exactly this opt-out, but
    only in 5.0.14; the plugin supports ``girder>=5``, and 5.0.9 -- the version
    this project's own image pins -- calls ``_sendVerificationEmail``
    unconditionally from ``createUser``. Wrapping the method is the one
    interception point common to both. Local registrations are untouched: the
    wrapper only bows out while :data:`_provisioning` is set, which happens on
    this thread for the duration of our own ``createUser`` call.
    """
    original = getattr(User, '_sendVerificationEmail', None)
    if original is None:
        # Renamed or removed upstream. Not fatal -- an account still ends up
        # verified, girder just also mails about it -- so warn and move on.
        logger.warning(
            'oidc: girder has no User._sendVerificationEmail to wrap; OIDC '
            'accounts may receive a redundant email-verification message.')
        return
    if getattr(original, _SUPPRESSION_MARKER, False):
        return  # already installed; plugin load runs repeatedly under pytest

    @functools.wraps(original)
    def wrapper(self, user):
        if getattr(_provisioning, 'active', False):
            return
        return original(self, user)

    setattr(wrapper, _SUPPRESSION_MARKER, True)
    User._sendVerificationEmail = wrapper


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


def claimAssertsVerifiedEmail(claims):
    """Whether the ID token positively asserts that the email is verified.

    The spec says boolean, but providers in the wild also send the string
    'true'/'false', so normalise those rather than treating a genuine assertion
    as missing. Anything else (absent, null, false) counts as unverified.
    """
    value = claims.get('email_verified')
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == 'true'
    return False


def _isLastAdmin(user):
    """True when ``user`` is the only site admin left."""
    return User().findOne({'admin': True, '_id': {'$ne': user['_id']}}) is None


def createOrReuseUser(oidcId, email, firstName='', lastName='', userName=None,
                      fullName=None, admin=None, emailVerified=False):
    """
    Look up the Girder user for an OIDC identity, creating one if needed.

    Matches first on the stored ``(provider, id)`` pair, then on email, and
    finally creates a passwordless user (subject to the auto-create and
    registration-policy settings). Mirrors the girder-oauth provisioning model.

    ``admin`` is the site-admin flag derived from the ID token (see
    :func:`claimGrantsAdmin`). ``None`` means admin mapping is disabled and the
    existing flag is left as-is; a bool fully syncs it (grant or revoke), except
    that the last remaining admin is never demoted -- that would leave the
    instance with no way back in short of editing the database.

    ``emailVerified`` is the ID token's ``email_verified`` claim. Anything we do
    on the strength of the email address alone -- matching an existing account,
    creating one, updating a stored address -- happens only when the provider
    vouched for it, or when an administrator has set
    ``oidc.trust_unverified_email``. Without that, whoever can set an address at
    the provider can claim the matching Girder account.
    """
    settings = Setting()
    # Normalise once: girder's User.validate lowercases and strips on save, so
    # comparing a raw claim against a stored address would otherwise report a
    # spurious change on every login.
    email = (email or '').strip().lower()
    emailIsTrusted = bool(emailVerified) or bool(
        settings.get(PluginSettings.TRUST_UNVERIFIED_EMAIL))

    # $elemMatch, so that the provider and the id must come from the *same*
    # array element once a second provider is added.
    query = {'oidc': {'$elemMatch': {'provider': PROVIDER, 'id': oidcId}}}
    user = User().findOne(query)
    setId = not user

    if not user:
        if not emailIsTrusted:
            # Refuse outright rather than falling back to Girder's own email
            # verification: that would mail a confirmation link to an address
            # the provider itself would not vouch for, which is precisely the
            # address an attacker would have supplied.
            raise RestException(
                'Single sign-on could not complete: your identity provider did '
                'not confirm %s as a verified address, and Girder will not '
                'match or create an account from an unverified one. Ask your '
                'administrator to have the address verified at the provider.'
                % email, code=403)
        user = User().findOne({'email': email})

    dirty = False
    created = not user
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
        with _provisioningOidcUser():
            user = User().createUser(
                login=login, password=None, firstName=first, lastName=last,
                email=email, admin=bool(admin))

    if not created:
        if emailIsTrusted and email != user['email']:
            user['email'] = email
            dirty = True
        if firstName and firstName != user['firstName']:
            user['firstName'] = firstName
            dirty = True
        if lastName and lastName != user['lastName']:
            user['lastName'] = lastName
            dirty = True
        if admin is not None and bool(admin) != bool(user.get('admin')):
            if not admin and _isLastAdmin(user):
                logger.warning(
                    'oidc: not revoking site-admin from %s -- it is the last '
                    'admin account. Grant admin to another user first, or fix '
                    'the admin claim at the provider.', user['login'])
            else:
                user['admin'] = bool(admin)
                dirty = True

    if emailIsTrusted and email == user['email'] \
            and not user.get('emailVerified'):
        # The provider owns this address and vouched for it, so record that.
        # Otherwise an instance with EMAIL_VERIFICATION set to 'required' has
        # `User().verifyLogin` reject every OIDC login, since `createUser`
        # always starts an account at emailVerified=False.
        #
        # This also holds under `oidc.trust_unverified_email`: enabling it is an
        # administrator asserting that the provider verifies every address it
        # emits and merely omits the claim, so the assertion carries here too.
        user['emailVerified'] = True
        dirty = True

    if setId:
        user.setdefault('oidc', []).append({'provider': PROVIDER, 'id': oidcId})
        dirty = True

    if dirty:
        user = User().save(user)

    return user
