"""Server-side guards that lock down self-service account management for
externally managed (OIDC-linked) accounts.

The profile, password, and two-factor settings of such accounts are owned by the
identity provider, so Girder must refuse to mutate them even if a client posts
straight to the REST API (the web client hides the controls, but that is not a
security boundary)."""

from girder import events
from girder.api.rest import getCurrentUser
from girder.exceptions import RestException
from girder.models.user import User

PROFILE_FIELDS = ('firstName', 'lastName', 'email')


def isExternallyManaged(user):
    return bool(user and user.get('oidc'))


def _targetUser(event):
    """The user a request acts on: the ``:id`` route token if present (admin and
    self ``:id`` endpoints), otherwise the current user (self password change)."""
    userId = event.info.get('id')
    if userId:
        return User().load(userId, force=True)
    return getCurrentUser()


def _guardProfile(event):
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


def _guardPassword(event):
    if isExternallyManaged(_targetUser(event)):
        raise RestException(
            'This account signs in through an identity provider and has no '
            'password to change.', code=403)


def _guardOtp(event):
    if isExternallyManaged(_targetUser(event)):
        raise RestException(
            'Two-factor authentication is managed by your identity provider.',
            code=403)


def bindAccountGuards():
    events.bind('rest.put.user/:id.before', 'oidc', _guardProfile)
    events.bind('rest.put.user/password.before', 'oidc', _guardPassword)
    events.bind('rest.put.user/:id/password.before', 'oidc', _guardPassword)
    events.bind('rest.post.user/:id/otp.before', 'oidc', _guardOtp)
    events.bind('rest.put.user/:id/otp.before', 'oidc', _guardOtp)
