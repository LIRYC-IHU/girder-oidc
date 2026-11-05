import os
import re
from urllib.parse import urlparse

from girder.exceptions import ValidationException
from girder.utility import setting_utilities

# Hosts for which a plaintext provider URL is tolerated: a dev stack on the
# loopback interface can't be intercepted by a network attacker.
_LOCAL_HOSTS = frozenset({'localhost', '127.0.0.1', '::1'})


class PluginSettings:
    """Setting keys for the OIDC plugin."""

    ENABLED = 'oidc.enabled'
    CLIENT_ID = 'oidc.client_id'
    CLIENT_SECRET = 'oidc.client_secret'
    # Browser-facing base URL of the OIDC provider; this is the issuer and the
    # value that `iss` in the ID token is validated against.
    PUBLIC_URL = 'oidc.public_url'
    # Optional server-to-server base URL (discovery / token / JWKS). Blank means
    # "same as PUBLIC_URL". Useful when the provider is reachable at a different
    # URL from inside the network than from the browser (dev stacks, proxies).
    INTERNAL_URL = 'oidc.internal_url'
    SCOPES = 'oidc.scopes'
    BUTTON_LABEL = 'oidc.button_label'
    # Whether signing out of Girder also ends the session at the provider
    # (OpenID Connect RP-Initiated Logout). With this on, the logout button
    # sends the browser to the provider's ``end_session_endpoint`` after the
    # Girder session is destroyed, which signs the user out of every other
    # application sharing that provider session too. Turn it off to keep logout
    # local to Girder.
    PROPAGATE_LOGOUT = 'oidc.propagate_logout'
    AUTO_CREATE_USERS = 'oidc.auto_create_users'
    IGNORE_REGISTRATION_POLICY = 'oidc.ignore_registration_policy'
    # Whether to act on the ``email`` claim when the provider does not assert
    # ``email_verified``. Matching a Girder account by an unverified address
    # lets anyone who can set that address at the provider take the account
    # over, so this defaults to False. Only enable it for a provider that
    # vouches for every address it emits.
    TRUST_UNVERIFIED_EMAIL = 'oidc.trust_unverified_email'
    # Optional: name of an ID-token claim that gates access to this instance at
    # all. Blank disables the check, so every identity the provider is willing
    # to authenticate may log in.
    REQUIRED_CLAIM = 'oidc.required_claim'
    # Value the required claim must match, with the same matching rules as the
    # admin claim below.
    REQUIRED_CLAIM_VALUE = 'oidc.required_claim_value'
    # Optional: name of an ID-token claim that confers Girder site-admin. Blank
    # disables admin mapping entirely.
    ADMIN_CLAIM = 'oidc.admin_claim'
    # Value the admin claim must match. For a list claim (e.g. groups/roles) this
    # is the required member; for a scalar it is the required value; blank means
    # "claim is truthy" (e.g. a boolean is_admin claim).
    ADMIN_CLAIM_VALUE = 'oidc.admin_claim_value'
    # Optional: name of an ID-token claim whose values are mirrored into Girder
    # groups, so that provider-side groups can be used in collection ACLs. Blank
    # disables group synchronisation entirely.
    GROUPS_CLAIM = 'oidc.groups_claim'
    # Prefix put in front of a claim value when the matching Girder group is
    # created, e.g. 'IdP: '. Useful to keep mirrored groups apart from the ones
    # an administrator maintains by hand (a name collision is refused, not
    # adopted).
    GROUP_NAME_PREFIX = 'oidc.group_name_prefix'
    # Whether the provider is authoritative over the groups it mirrors: with
    # this on, a user who no longer carries a group in their token is removed
    # from it at the next login. Groups the plugin did not create are never
    # touched either way.
    GROUPS_AUTHORITATIVE = 'oidc.groups_authoritative'
    # Token exchange for resource servers (e.g. an MCP server): an access token
    # the provider issued to ANOTHER client, for this audience, is traded for a
    # short-lived read-only Girder token of the linked account. Blank disables
    # the endpoint. Must differ from the client id, so that tokens issued for
    # Girder's own login can never be replayed through it.
    TOKEN_EXCHANGE_AUDIENCE = 'oidc.token_exchange_audience'
    # OAuth scope the access token must grant (`scope`/`scp` claim). Required
    # for the exchange to run: the audience alone is not a narrow enough gate.
    TOKEN_EXCHANGE_SCOPE = 'oidc.token_exchange_scope'
    # Upper bound on the lifetime of an exchanged Girder token, in minutes; it
    # never outlives the access token it was exchanged for either.
    TOKEN_EXCHANGE_MINUTES = 'oidc.token_exchange_minutes'
    # Client ids (the token's `azp`) allowed to exchange, space- or
    # comma-separated. Required: otherwise any client of the realm that can
    # obtain the audience -- another application, a direct-grant client that
    # skips MFA -- could trade its users' tokens for Girder access.
    TOKEN_EXCHANGE_CLIENTS = 'oidc.token_exchange_clients'

    TOKEN_EXCHANGE_MAX_MINUTES = 1440


@setting_utilities.default(PluginSettings.ENABLED)
def _defaultEnabled():
    return False


@setting_utilities.default(PluginSettings.CLIENT_ID)
def _defaultClientId():
    return os.environ.get('OIDC_CLIENT_ID', '')


@setting_utilities.default(PluginSettings.CLIENT_SECRET)
def _defaultClientSecret():
    return os.environ.get('OIDC_CLIENT_SECRET', '')


@setting_utilities.default(PluginSettings.PUBLIC_URL)
def _defaultPublicUrl():
    return os.environ.get('OIDC_PUBLIC_URL', '')


@setting_utilities.default(PluginSettings.INTERNAL_URL)
def _defaultInternalUrl():
    return os.environ.get('OIDC_INTERNAL_URL', '')


@setting_utilities.default(PluginSettings.SCOPES)
def _defaultScopes():
    return 'openid profile email'


@setting_utilities.default(PluginSettings.BUTTON_LABEL)
def _defaultButtonLabel():
    return 'Log in with OIDC'


@setting_utilities.default(PluginSettings.PROPAGATE_LOGOUT)
def _defaultPropagateLogout():
    return True


@setting_utilities.default(PluginSettings.AUTO_CREATE_USERS)
def _defaultAutoCreateUsers():
    return True


@setting_utilities.default(PluginSettings.IGNORE_REGISTRATION_POLICY)
def _defaultIgnoreRegistrationPolicy():
    return False


@setting_utilities.default(PluginSettings.TRUST_UNVERIFIED_EMAIL)
def _defaultTrustUnverifiedEmail():
    return False


@setting_utilities.default(PluginSettings.REQUIRED_CLAIM)
def _defaultRequiredClaim():
    return ''


@setting_utilities.default(PluginSettings.REQUIRED_CLAIM_VALUE)
def _defaultRequiredClaimValue():
    return ''


@setting_utilities.default(PluginSettings.ADMIN_CLAIM)
def _defaultAdminClaim():
    return ''


@setting_utilities.default(PluginSettings.ADMIN_CLAIM_VALUE)
def _defaultAdminClaimValue():
    return ''


@setting_utilities.default(PluginSettings.GROUPS_CLAIM)
def _defaultGroupsClaim():
    return ''


@setting_utilities.default(PluginSettings.GROUP_NAME_PREFIX)
def _defaultGroupNamePrefix():
    return ''


@setting_utilities.default(PluginSettings.GROUPS_AUTHORITATIVE)
def _defaultGroupsAuthoritative():
    return True


@setting_utilities.default(PluginSettings.TOKEN_EXCHANGE_AUDIENCE)
def _defaultTokenExchangeAudience():
    return ''


@setting_utilities.default(PluginSettings.TOKEN_EXCHANGE_SCOPE)
def _defaultTokenExchangeScope():
    return ''


@setting_utilities.default(PluginSettings.TOKEN_EXCHANGE_CLIENTS)
def _defaultTokenExchangeClients():
    return ''


@setting_utilities.default(PluginSettings.TOKEN_EXCHANGE_MINUTES)
def _defaultTokenExchangeMinutes():
    return 60


@setting_utilities.validator({
    PluginSettings.CLIENT_ID,
    PluginSettings.CLIENT_SECRET,
    PluginSettings.SCOPES,
    PluginSettings.BUTTON_LABEL,
    PluginSettings.REQUIRED_CLAIM,
    PluginSettings.REQUIRED_CLAIM_VALUE,
    PluginSettings.ADMIN_CLAIM,
    PluginSettings.ADMIN_CLAIM_VALUE,
    PluginSettings.GROUPS_CLAIM,
    PluginSettings.GROUP_NAME_PREFIX,
})
def _validateStringSettings(doc):
    if not isinstance(doc['value'], str):
        raise ValidationException('Value must be a string.', 'value')


@setting_utilities.validator({
    PluginSettings.ENABLED,
    PluginSettings.AUTO_CREATE_USERS,
    PluginSettings.IGNORE_REGISTRATION_POLICY,
    PluginSettings.TRUST_UNVERIFIED_EMAIL,
    PluginSettings.GROUPS_AUTHORITATIVE,
    PluginSettings.PROPAGATE_LOGOUT,
})
def _validateBooleanSettings(doc):
    if not isinstance(doc['value'], bool):
        raise ValidationException('Value must be a boolean.', 'value')


def _parseProviderUrl(doc):
    """Shared shape check for the two provider URL settings. Blank is allowed
    (the plugin refuses to start a login flow without a provider URL)."""
    value = doc['value']
    if not isinstance(value, str):
        raise ValidationException('Value must be a string.', 'value')
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise ValidationException(
            'Provider URL must be an absolute http(s) URL.', 'value')
    return parsed


@setting_utilities.validator(PluginSettings.PUBLIC_URL)
def _validatePublicUrl(doc):
    parsed = _parseProviderUrl(doc)
    if parsed is None:
        return
    # This URL carries the browser through the authorization redirect and is the
    # issuer the ID token is checked against; over plaintext both are forgeable.
    if parsed.scheme != 'https' and (parsed.hostname or '') not in _LOCAL_HOSTS:
        raise ValidationException(
            'The browser-facing provider URL must use https (plain http is '
            'only accepted for localhost, for development).', 'value')


@setting_utilities.validator(PluginSettings.INTERNAL_URL)
def _validateInternalUrl(doc):
    _parseProviderUrl(doc)


@setting_utilities.validator({
    PluginSettings.TOKEN_EXCHANGE_AUDIENCE,
    PluginSettings.TOKEN_EXCHANGE_SCOPE,
})
def _validateTokenExchangeNames(doc):
    """A single audience / scope name: no whitespace, so a value can never be
    read as a list of several (which would widen what is accepted)."""
    value = doc['value']
    if not isinstance(value, str):
        raise ValidationException('Value must be a string.', 'value')
    value = value.strip()
    if any(c.isspace() for c in value):
        raise ValidationException('Value must be a single name, without spaces.', 'value')
    if doc['key'] == PluginSettings.TOKEN_EXCHANGE_AUDIENCE and value:
        # Imported here: girder.models.setting imports this module's validators.
        from girder.models.setting import Setting
        if value == (Setting().get(PluginSettings.CLIENT_ID) or '').strip():
            raise ValidationException(
                'The token-exchange audience must differ from the client id: '
                "tokens issued for Girder's own login must not be exchangeable.",
                'value')
        if value in RESERVED_AUDIENCES:
            raise ValidationException(
                'The token-exchange audience must be dedicated to the service: '
                '"%s" is put in tokens by the provider itself.' % value, 'value')
    doc['value'] = value


# Audiences keycloak adds on its own (e.g. `account` to almost every access
# token): accepting one would make every token of the realm exchangeable.
RESERVED_AUDIENCES = frozenset({
    'account', 'realm-management', 'broker', 'security-admin-console',
    'admin-cli', 'admin-console',
})


def parseClientList(value):
    """`"a, b c"` → `["a", "b", "c"]` (order kept, duplicates dropped)."""
    out = []
    for name in re.split(r'[\s,]+', value or ''):
        if name and name not in out:
            out.append(name)
    return out


@setting_utilities.validator(PluginSettings.TOKEN_EXCHANGE_CLIENTS)
def _validateTokenExchangeClients(doc):
    value = doc['value']
    if not isinstance(value, str):
        raise ValidationException('Value must be a string.', 'value')
    doc['value'] = ' '.join(parseClientList(value))


@setting_utilities.validator(PluginSettings.TOKEN_EXCHANGE_MINUTES)
def _validateTokenExchangeMinutes(doc):
    value = doc['value']
    if isinstance(value, bool) or not isinstance(value, int) \
            or not 1 <= value <= PluginSettings.TOKEN_EXCHANGE_MAX_MINUTES:
        raise ValidationException(
            'Value must be an integer between 1 and %d.'
            % PluginSettings.TOKEN_EXCHANGE_MAX_MINUTES, 'value')
