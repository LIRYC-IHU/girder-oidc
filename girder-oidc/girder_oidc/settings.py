import os

from girder.exceptions import ValidationException
from girder.utility import setting_utilities


class PluginSettings:
    """Settings keys for OIDC plugin."""
    
    KEYCLOAK_URL = 'oidc.keycloak_url'
    KEYCLOAK_PUBLIC_URL = 'oidc.keycloak_public_url'
    KEYCLOAK_REALM = 'oidc.keycloak_realm'
    CLIENT_ID = 'oidc.client_id'
    CLIENT_SECRET = 'oidc.client_secret'
    ENABLE = 'oidc.enable'
    AUTO_CREATE_USERS = 'oidc.auto_create_users'
    ALLOW_REGISTRATION = 'oidc.allow_registration'
    IGNORE_REGISTRATION_POLICY = 'oidc.ignore_registration_policy'
    GROUP_MAPPING = 'oidc.group_mapping'


@setting_utilities.default(PluginSettings.KEYCLOAK_URL)
def _defaultKeycloakUrl():
    return os.environ.get('KEYCLOAK_URL', 'https://keycloak:8443')


@setting_utilities.default(PluginSettings.KEYCLOAK_PUBLIC_URL)
def _defaultKeycloakPublicUrl():
    return os.environ.get('KEYCLOAK_PUBLIC_URL', os.environ.get('KEYCLOAK_URL', 'https://localhost:8443'))


@setting_utilities.default(PluginSettings.KEYCLOAK_REALM)
def _defaultKeycloakRealm():
    return 'girder'


@setting_utilities.default(PluginSettings.CLIENT_ID)
def _defaultClientId():
    return ''


@setting_utilities.default(PluginSettings.CLIENT_SECRET)
def _defaultClientSecret():
    return ''


@setting_utilities.default(PluginSettings.ENABLE)
def _defaultEnable():
    return False


@setting_utilities.default(PluginSettings.AUTO_CREATE_USERS)
def _defaultAutoCreateUsers():
    return True


@setting_utilities.default(PluginSettings.ALLOW_REGISTRATION)
def _defaultAllowRegistration():
    return False


@setting_utilities.default(PluginSettings.IGNORE_REGISTRATION_POLICY)
def _defaultIgnoreRegistrationPolicy():
    return False


@setting_utilities.default(PluginSettings.GROUP_MAPPING)
def _defaultGroupMapping():
    return {}


@setting_utilities.validator({
    PluginSettings.KEYCLOAK_URL,
    PluginSettings.KEYCLOAK_PUBLIC_URL,
    PluginSettings.KEYCLOAK_REALM,
    PluginSettings.CLIENT_ID,
    PluginSettings.CLIENT_SECRET,
})
def _validateStringSettings(doc):
    if not isinstance(doc['value'], str):
        raise ValidationException('Value must be a string.')


@setting_utilities.validator({
    PluginSettings.ENABLE,
    PluginSettings.AUTO_CREATE_USERS,
    PluginSettings.ALLOW_REGISTRATION,
    PluginSettings.IGNORE_REGISTRATION_POLICY,
})
def _validateBooleanSettings(doc):
    if not isinstance(doc['value'], bool):
        raise ValidationException('Value must be a boolean.')


@setting_utilities.validator(PluginSettings.GROUP_MAPPING)
def _validateGroupMapping(doc):
    if not isinstance(doc['value'], dict):
        raise ValidationException('Value must be a dictionary.')
