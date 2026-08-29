from pathlib import Path

from girder import events
from girder.constants import AccessType, SortDir
from girder.exceptions import ValidationException
from girder.models.group import Group
from girder.models.user import User
from girder.plugin import GirderPlugin, registerPluginStaticContent

from . import rest
from .account_guard import bindAccountGuards
from .user import installVerificationEmailSuppression


def checkOidcUser(event):
    """
    Give OIDC users a useful message if they try to log in with a password they
    don't have.
    """
    user = event.info['user']
    if user.get('oidc'):
        # Deliberately not pointing at the password reset link: that flow is
        # blocked for externally-managed accounts (see account_guard), so it
        # would only send the user to a dead end.
        raise ValidationException(
            "You don't have a Girder password. Please use the single sign-on "
            'button to log in.')


class OidcPlugin(GirderPlugin):
    DISPLAY_NAME = 'OIDC Login'

    def load(self, info):
        User().ensureIndex((
            (('oidc.provider', SortDir.ASCENDING),
             ('oidc.id', SortDir.ASCENDING)), {}))

        # Mirrored groups are looked up by their marker on every login.
        Group().ensureIndex((
            (('oidc.provider', SortDir.ASCENDING),
             ('oidc.claim', SortDir.ASCENDING)), {}))

        events.bind('no_password_login_attempt', 'oidc', checkOidcUser)

        # Accounts provisioned from OIDC get no "verify your email" mail from
        # girder: the provider already vouched for the address and we mark it
        # verified. Local registrations still get theirs.
        installVerificationEmailSuppression()

        # Let clients (and the account page) see that an account is OIDC-linked.
        # ADMIN level: visible to the user themselves and to site admins only.
        User().exposeFields(level=AccessType.ADMIN, fields='oidc')
        # Likewise for groups: lets an admin tell a mirrored group apart from
        # one maintained by hand.
        Group().exposeFields(level=AccessType.ADMIN, fields='oidc')

        bindAccountGuards()

        info['apiRoot'].oidc = rest.Oidc()

        registerPluginStaticContent(
            plugin='oidc',
            css=['/style.css'],
            js=['/girder-plugin-oidc.umd.cjs'],
            staticDir=Path(__file__).parent / 'web_client' / 'dist',
            tree=info['serverRoot'],
        )
