"""Server-side guards that lock down self-service account management for
externally managed (OIDC-linked) accounts.

The profile, password, and two-factor settings of such accounts are owned by the
identity provider, so Girder must refuse to mutate them even if a client posts
straight to the REST API (the web client hides the controls, but that is not a
security boundary)."""

from girder import events
from girder.api import access
from girder.api.rest import getCurrentUser
from girder.exceptions import RestException
from girder.models.user import User

PROFILE_FIELDS = ('firstName', 'lastName', 'email')

# Every one of these hooks carries an @access decorator, and that is load-bearing
# rather than decorative. Girder runs `Resource._defaultAccess` over each handler
# bound to a `rest.*.before` event and, finding no `accessLevel` attribute, falls
# back to requiring site-admin -- for the *whole route*, not just for our hook.
# Undecorated guards would therefore lock ordinary local users out of editing
# their own profile or changing their own password. `access.public` is the right
# level here: it makes us defer, and girder still enforces the core route's own
# access level afterwards.


def isExternallyManaged(user):
    return bool(user and user.get('oidc'))


def _targetUser(event):
    """The user a request acts on: the ``:id`` route token if present (admin and
    self ``:id`` endpoints), otherwise the current user (self password change)."""
    userId = event.info.get('id')
    if userId:
        return User().load(userId, force=True)
    return getCurrentUser()


@access.public
def _guardProfile(event):
    # These routes are authenticated-only; girder rejects an anonymous caller
    # right after this hook. Bailing out early keeps us from answering "this
    # account is SSO-managed" to someone who is not even logged in.
    if getCurrentUser() is None:
        return
    user = _targetUser(event)
    if not isExternallyManaged(user):
        return
    params = event.info.get('params', {})
    for field in PROFILE_FIELDS:
        value = params.get(field)
        if value is not None and str(value) != str(user.get(field, '')):
            raise RestException(
                'This profile is managed by your identity provider and cannot '
                'be edited here.', code=403)


@access.public
def _guardPassword(event):
    if getCurrentUser() is None:
        return
    if isExternallyManaged(_targetUser(event)):
        raise RestException(
            'This account signs in through an identity provider and has no '
            'password to change.', code=403)


@access.public
def _guardOtp(event):
    if getCurrentUser() is None:
        return
    if isExternallyManaged(_targetUser(event)):
        raise RestException(
            'Two-factor authentication is managed by your identity provider.',
            code=403)


_NO_RESET_MESSAGE = ('This account signs in through an identity provider. Use '
                     'the provider to sign in; there is no Girder password to '
                     'reset.')

# Both halves of girder's temporary-access ("forgot my password") flow are
# @access.public, and the second one hands out a *full* session token before any
# password is set. Left open, anyone who controls the mailbox could get a Girder
# session for an externally-managed account without ever passing through the
# identity provider -- and so without whatever MFA or conditional access it
# enforces. These two guards therefore have to work for anonymous callers, which
# is why neither bails out on a missing current user.


@access.public
def _guardTemporaryPasswordRequest(event):
    """``PUT /user/password/temporary``: identifies the account by email rather
    than by a route id, so it needs its own lookup."""
    email = (event.info.get('params', {}).get('email') or '').strip().lower()
    if not email:
        return
    if isExternallyManaged(User().findOne({'email': email})):
        raise RestException(_NO_RESET_MESSAGE, code=403)


@access.public
def _guardTemporaryPasswordRedeem(event):
    """``GET /user/password/temporary/:id``: ``:id`` is the user id."""
    userId = event.info.get('id')
    if not userId:
        return
    if isExternallyManaged(User().load(userId, force=True)):
        raise RestException(_NO_RESET_MESSAGE, code=403)


def bindAccountGuards():
    events.bind('rest.put.user/:id.before', 'oidc', _guardProfile)
    events.bind('rest.put.user/password.before', 'oidc', _guardPassword)
    events.bind('rest.put.user/:id/password.before', 'oidc', _guardPassword)
    events.bind('rest.put.user/password/temporary.before', 'oidc',
                _guardTemporaryPasswordRequest)
    events.bind('rest.get.user/password/temporary/:id.before', 'oidc',
                _guardTemporaryPasswordRedeem)
    events.bind('rest.post.user/:id/otp.before', 'oidc', _guardOtp)
    events.bind('rest.put.user/:id/otp.before', 'oidc', _guardOtp)
