"""Exchange of a provider-issued access token for a read-only Girder token.

A resource server that sits in front of Girder -- an MCP server, typically --
lets its users sign in through the identity provider with their own OAuth
client (Claude Code, an MCP inspector, ...). It receives an access token issued
for *its* audience, and needs a Girder token to query the API on the user's
behalf. This module is the bridge, exposed as ``POST /oidc/token_exchange``.

What the exchange guarantees:

* only the resource server can call it: it must present the shared secret
  ``OIDC_TOKEN_EXCHANGE_SECRET`` (header ``X-Token-Exchange-Secret``). A client
  holding an access token cannot obtain a Girder token by itself;
* the access token is genuine and meant for the configured audience -- never
  Girder's own client id, so a token issued for Girder's login cannot be traded
  in (see :meth:`OidcClient.validateAccessToken`);
* it was issued to an allowed client (``azp``) and grants the required scope;
* it only ever reaches an account the identity is ALREADY linked to by ``sub``.
  Nothing is created, matched by email or linked here: the first SSO login into
  Girder, with all its checks, remains the only way an identity gets an account;
* the instance's access rules still hold: the required claim, a disabled or
  unapproved account, an unverified address where verification is required;
* it never yields more than the Girder account already has, and less where the
  provider no longer agrees: a site admin whose access token does not carry the
  admin claim, or a member of a mirrored group the token no longer lists, is
  refused rather than handed a token reaching that data;
* the result is a ``core.data.read`` token, at most
  ``oidc.token_exchange_minutes`` long and never outliving the access token.

What it deliberately does NOT do: write anything about the user. The admin flag
and mirrored groups are synchronised at interactive login only -- an access
token may legitimately lack the claims an ID token carries (mappers are
configured per token type), and syncing from it could strip a user's groups.
"""

import datetime
import hashlib
import hmac
import logging
import os

import cherrypy

from girder.constants import TokenScope
from girder.exceptions import AccessException, RestException
from girder.models.setting import Setting
from girder.models.token import Token
from girder.models.user import User

from .client import OidcClient
from .groups import revokedMirroredGroups
from .settings import RESERVED_AUDIENCES, PluginSettings, parseClientList
from .user import PROVIDER, claimGrantsAccess, claimGrantsAdmin

logger = logging.getLogger(__name__)

EXCHANGE_SCOPE = TokenScope.DATA_READ

# A cached exchanged token is only handed out again while it still has this
# long to live; closer to expiry, a fresh one is minted.
_REUSE_MARGIN = datetime.timedelta(seconds=30)


def _digest(accessToken):
    return hashlib.sha256(accessToken.encode('utf-8')).hexdigest()


# The exchange is reserved to the resource server(s) Girder trusts: they prove
# it with this secret, shared out of band (environment only, never in the
# database, so neither the settings API nor a database dump reveals it). Without
# it, any client allowed to obtain an access token could trade it for a Girder
# token itself and query Girder directly -- around the resource server and its
# audit journal.
SECRET_ENV = 'OIDC_TOKEN_EXCHANGE_SECRET'
SECRET_HEADER = 'X-Token-Exchange-Secret'
MIN_SECRET_LENGTH = 16


def _configuredSecret():
    """The configured secret, or None when unusable (absent, short, or not plain
    printable ASCII -- HTTP servers strip header whitespace and decode headers as
    latin-1, so such a value could never be matched and would only confuse)."""
    value = os.environ.get(SECRET_ENV, '')
    if len(value) < MIN_SECRET_LENGTH or value != value.strip() or not value.isascii() \
            or not value.isprintable():
        return None
    return value


def secretConfigured():
    return _configuredSecret() is not None


def checkCallerSecret(presented):
    """Refuse (403) unless ``presented`` is the configured exchange secret.

    The caller gets the same answer whether the secret is wrong or not configured
    at all; the difference only goes to the server log.
    """
    expected = _configuredSecret()
    if expected is None:
        logger.error('oidc: token exchange refused -- %s is not set, shorter than %d '
                     'characters, or not plain ASCII.', SECRET_ENV, MIN_SECRET_LENGTH)
        raise RestException('Token exchange is reserved to the resource server.', code=403)
    if not isinstance(presented, str) or not hmac.compare_digest(
            presented.encode('latin-1', 'replace'), expected.encode('ascii')):
        logger.warning('oidc: token exchange refused -- %s caller secret from %s.',
                       'missing' if not presented else 'wrong',
                       getattr(cherrypy.request.remote, 'ip', '?'))
        raise RestException('Token exchange is reserved to the resource server.', code=403)


def exchangeAccessToken(accessToken, callerSecret=None):
    """Validate ``accessToken`` and return a read-only Girder token document.

    ``callerSecret`` is what the caller presented in the
    ``X-Token-Exchange-Secret`` header; it is
    checked first, before anything about the token is looked at.

    Raises ``RestException``: 403 when the feature is off, the caller is not
    the resource server, or the identity is not admitted; 401 when the access
    token itself is not acceptable.
    """
    settings = Setting()
    if not settings.get(PluginSettings.ENABLED):
        raise RestException('OIDC login is not enabled.', code=403)
    checkCallerSecret(callerSecret)
    # Settings forced through GIRDER_SETTING_* bypass the validators: accept
    # strings only, and treat anything else as a misconfiguration.
    def _text(key):
        value = settings.get(key)
        if value is None:
            return ''
        if not isinstance(value, str):
            raise RestException('Token exchange is misconfigured: %s must be a '
                                'string.' % key, code=403)
        return value.strip()

    audience = _text(PluginSettings.TOKEN_EXCHANGE_AUDIENCE)
    if not audience:
        raise RestException('Token exchange is not enabled.', code=403)
    if audience == _text(PluginSettings.CLIENT_ID) \
            or audience in RESERVED_AUDIENCES:
        # The setting validator refuses both, but the client id can be changed
        # afterwards: keep the guarantee at the point of use.
        raise RestException(
            'Token exchange is misconfigured: its audience is not dedicated to '
            'the service.', code=403)
    scope = _text(PluginSettings.TOKEN_EXCHANGE_SCOPE)
    clients = parseClientList(_text(PluginSettings.TOKEN_EXCHANGE_CLIENTS))
    if not scope or not clients:
        raise RestException(
            'Token exchange is misconfigured: set the required scope and the '
            'allowed clients.', code=403)

    claims = OidcClient().validateAccessToken(accessToken, audience, scope)
    sub = claims['sub']

    # The client the token was issued TO. Without this check, any application
    # of the realm able to obtain the audience could exchange its users' tokens.
    issuedTo = claims.get('azp') or claims.get('client_id')
    if not isinstance(issuedTo, str) or issuedTo not in clients:
        logger.warning('oidc: token exchange refused for sub=%s -- issued to '
                       'client %r, which is not allowed to exchange.', sub, issuedTo)
        raise RestException(
            'This application is not allowed to access Girder.', code=403)

    if not claimGrantsAccess(
            claims, settings.get(PluginSettings.REQUIRED_CLAIM),
            settings.get(PluginSettings.REQUIRED_CLAIM_VALUE)):
        logger.info('oidc: token exchange refused for sub=%s -- missing the '
                    'configured access claim.', sub)
        raise RestException(
            'This identity has not been granted access to this Girder instance.',
            code=403)

    user = User().findOne({'oidc': {'$elemMatch': {'provider': PROVIDER, 'id': sub}}})
    if user is None:
        raise RestException(
            'No Girder account is linked to this identity yet. Sign in to Girder '
            'once with single sign-on, then try again.', code=403)

    try:
        User().verifyLogin(user)
    except AccessException as e:
        raise RestException('This Girder account cannot be used: %s' % e, code=403)

    isAdmin = claimGrantsAdmin(
        claims, settings.get(PluginSettings.ADMIN_CLAIM),
        settings.get(PluginSettings.ADMIN_CLAIM_VALUE))
    if user.get('admin') and isAdmin is False:
        logger.warning(
            'oidc: token exchange refused for %s -- a site admin in Girder, but '
            'the access token does not carry the admin claim.', user['login'])
        raise RestException(
            'Your site-admin rights are no longer confirmed by the identity '
            'provider. Sign in to Girder again to update them, or ask your '
            'administrator to add the admin claim to access tokens.', code=403)

    # A token must not reach collections the provider has taken away. Group
    # memberships are only WRITTEN at interactive login, so refuse here when the
    # access token no longer confers one the user still holds.
    revoked = revokedMirroredGroups(user, claims)
    if revoked is None:
        raise RestException(
            'Group membership cannot be checked: the access token does not carry '
            'the groups claim. Ask your administrator to add it to access tokens.',
            code=403)
    if revoked:
        logger.info('oidc: token exchange refused for %s -- no longer in %s at the '
                    'provider.', user['login'], ', '.join(revoked))
        raise RestException(
            'Your group memberships have changed at the identity provider. Sign in '
            'to Girder again to update them, then try again.', code=403)

    now = datetime.datetime.now(datetime.timezone.utc)
    digest = _digest(accessToken)
    existing = Token().findOne({
        'oidcExchange': digest,
        'userId': user['_id'],
        'expires': {'$gt': now + _REUSE_MARGIN},
    })
    if existing is not None:
        return existing

    notAfter = datetime.datetime.fromtimestamp(int(claims['exp']), datetime.timezone.utc)
    minutes = settings.get(PluginSettings.TOKEN_EXCHANGE_MINUTES)
    if isinstance(minutes, bool) or not isinstance(minutes, int) \
            or not 1 <= minutes <= PluginSettings.TOKEN_EXCHANGE_MAX_MINUTES:
        raise RestException('Token exchange is misconfigured: invalid token '
                            'lifetime.', code=403)
    expires = min(now + datetime.timedelta(minutes=minutes), notAfter)
    lifetime = (expires - now).total_seconds()
    # Explicit, because `Token().createToken(days=0)` silently falls back to the
    # session cookie lifetime (180 days by default).
    if lifetime <= 0:
        raise RestException('Invalid access token: expired.', code=401)

    token = Token().createToken(user=user, days=lifetime / 86400, scope=EXCHANGE_SCOPE)
    # createToken recomputes "now" a moment later: pin the exact bound.
    token['expires'] = expires
    token['oidcExchange'] = digest
    token['oidcExchangeClient'] = issuedTo
    token = Token().save(token)
    logger.info('oidc: exchanged an access token from client %r for a read-only '
                'token of %s, valid %d s.', token['oidcExchangeClient'],
                user['login'], int(lifetime))
    return token
