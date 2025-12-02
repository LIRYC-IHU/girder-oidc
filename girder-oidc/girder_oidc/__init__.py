from girder import events
from girder.constants import SortDir
from girder.exceptions import ValidationException
from girder.models.user import User
from girder.plugin import GirderPlugin

from . import rest, providers


def checkOidcUser(event):
    """
    If an OIDC user without a password tries to log in with a password, we
    want to give them a useful error message.
    """
    user = event.info['user']
    if user.get('oidc'):
        raise ValidationException(
            "You don't have a password. Please log in with OIDC, or use the password reset link.")


class OidcPlugin(GirderPlugin):
    DISPLAY_NAME = 'OIDC/Keycloak Login'
    CLIENT_SOURCE_PATH = 'web_client'
    description = 'Authenticate users via OIDC (Keycloak)'

    def load(self, info):
        User().ensureIndex((
            (('oidc.provider', SortDir.ASCENDING),
             ('oidc.id', SortDir.ASCENDING)), {}))

        events.bind('no_password_login_attempt', 'oidc', checkOidcUser)

        info['apiRoot'].oidc = rest.Oidc()
