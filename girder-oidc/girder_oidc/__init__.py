from pathlib import Path

from girder import events
from girder.constants import AccessType, SortDir
from girder.exceptions import ValidationException
from girder.models.user import User
from girder.plugin import GirderPlugin, registerPluginStaticContent

from . import rest
from .account_guard import bindAccountGuards


def checkOidcUser(event):
    """
    Give OIDC users a useful message if they try to log in with a password they
    don't have.
    """
    user = event.info['user']
    if user.get('oidc'):
        raise ValidationException(
            "You don't have a password. Please log in with OIDC, or use the "
            'password reset link.')


class OidcPlugin(GirderPlugin):
    DISPLAY_NAME = 'OIDC Login'

    def load(self, info):
        User().ensureIndex((
            (('oidc.provider', SortDir.ASCENDING),
             ('oidc.id', SortDir.ASCENDING)), {}))

        events.bind('no_password_login_attempt', 'oidc', checkOidcUser)

        # Let clients (and the account page) see that an account is OIDC-linked.
        # ADMIN level: visible to the user themselves and to site admins only.
        User().exposeFields(level=AccessType.ADMIN, fields='oidc')

        bindAccountGuards()

        info['apiRoot'].oidc = rest.Oidc()

        registerPluginStaticContent(
            plugin='oidc',
            css=['/style.css'],
            js=['/girder-plugin-oidc.umd.cjs'],
            staticDir=Path(__file__).parent / 'web_client' / 'dist',
            tree=info['serverRoot'],
        )
