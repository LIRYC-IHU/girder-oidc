import os
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
    AUTO_CREATE_USERS = 'oidc.auto_create_users'
    IGNORE_REGISTRATION_POLICY = 'oidc.ignore_registration_policy'
    # Whether to act on the ``email`` claim when the provider does not assert
    # ``email_verified``. Matching a Girder account by an unverified address
    # lets anyone who can set that address at the provider take the account
    # over, so this defaults to False. Only enable it for a provider that
    # vouches for every address it emits.
    TRUST_UNVERIFIED_EMAIL = 'oidc.trust_unverified_email'
    # Optional: name of an ID-token claim that confers Girder site-admin. Blank
    # disables admin mapping entirely.
    ADMIN_CLAIM = 'oidc.admin_claim'
    # Value the admin claim must match. For a list claim (e.g. groups/roles) this
    # is the required member; for a scalar it is the required value; blank means
    # "claim is truthy" (e.g. a boolean is_admin claim).
    ADMIN_CLAIM_VALUE = 'oidc.admin_claim_value'


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


@setting_utilities.default(PluginSettings.AUTO_CREATE_USERS)
def _defaultAutoCreateUsers():
    return True


@setting_utilities.default(PluginSettings.IGNORE_REGISTRATION_POLICY)
def _defaultIgnoreRegistrationPolicy():
    return False


@setting_utilities.default(PluginSettings.TRUST_UNVERIFIED_EMAIL)
def _defaultTrustUnverifiedEmail():
    return False


@setting_utilities.default(PluginSettings.ADMIN_CLAIM)
def _defaultAdminClaim():
    return ''


@setting_utilities.default(PluginSettings.ADMIN_CLAIM_VALUE)
def _defaultAdminClaimValue():
    return ''


@setting_utilities.validator({
    PluginSettings.CLIENT_ID,
    PluginSettings.CLIENT_SECRET,
    PluginSettings.SCOPES,
    PluginSettings.BUTTON_LABEL,
    PluginSettings.ADMIN_CLAIM,
    PluginSettings.ADMIN_CLAIM_VALUE,
})
def _validateStringSettings(doc):
    if not isinstance(doc['value'], str):
        raise ValidationException('Value must be a string.', 'value')


@setting_utilities.validator({
    PluginSettings.ENABLED,
    PluginSettings.AUTO_CREATE_USERS,
    PluginSettings.IGNORE_REGISTRATION_POLICY,
    PluginSettings.TRUST_UNVERIFIED_EMAIL,
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
