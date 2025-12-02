"""Tests for OIDC configuration endpoints."""

import pytest
from girder.models.setting import Setting
from girder.test import base
from girder.constants import AccessType

from girder_oidc.settings import PluginSettings


class TestOidcConfiguration(base.TestCase):
    """Test OIDC configuration endpoints."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.admin_user = self.model('user').createUser(
            login='admin', email='admin@example.com', firstName='Admin',
            lastName='User', password='password')
        self.user = self.model('user').createUser(
            login='user', email='user@example.com', firstName='Regular',
            lastName='User', password='password')

    def testGetConfiguration(self):
        """Test GET /oidc/configuration returns current settings."""
        self.ensureUserIsAdmin(self.admin_user)
        
        # Set some configuration
        Setting().set(PluginSettings.KEYCLOAK_URL, 'https://keycloak:8443')
        Setting().set(PluginSettings.KEYCLOAK_PUBLIC_URL, 'https://localhost:8443')
        Setting().set(PluginSettings.KEYCLOAK_REALM, 'test-realm')
        Setting().set(PluginSettings.CLIENT_ID, 'test-client')
        Setting().set(PluginSettings.ENABLE, True)
        Setting().set(PluginSettings.AUTO_CREATE_USERS, True)
        
        resp = self.request('/oidc/configuration', user=self.admin_user)
        self.assertStatusOk(resp)
        
        config = resp.json
        self.assertEqual(config['keycloakUrl'], 'https://keycloak:8443')
        self.assertEqual(config['keycloakPublicUrl'], 'https://localhost:8443')
        self.assertEqual(config['keycloakRealm'], 'test-realm')
        self.assertEqual(config['clientId'], 'test-client')
        self.assertTrue(config['enable'])
        self.assertTrue(config['autoCreateUsers'])

    def testGetConfigurationForbidden(self):
        """Test regular users cannot get configuration."""
        resp = self.request('/oidc/configuration', user=self.user)
        self.assertStatus(resp, 403)

    def testGetConfigurationAnonymousForbidden(self):
        """Test anonymous users cannot get configuration."""
        resp = self.request('/oidc/configuration')
        self.assertStatus(resp, 401)

    def testSetConfiguration(self):
        """Test PUT /oidc/configuration updates settings."""
        self.ensureUserIsAdmin(self.admin_user)
        
        config_data = {
            'keycloakUrl': 'https://keycloak.example.com:8443',
            'keycloakPublicUrl': 'https://auth.example.com:8443',
            'keycloakRealm': 'production',
            'clientId': 'my-client',
            'clientSecret': 'secret123',
            'enable': True,
            'autoCreateUsers': False,
            'allowRegistration': True,
            'ignoreRegistrationPolicy': False
        }
        
        resp = self.request('/oidc/configuration', method='PUT',
                           user=self.admin_user, data=config_data)
        self.assertStatusOk(resp)
        
        # Verify settings were saved
        self.assertEqual(
            Setting().get(PluginSettings.KEYCLOAK_URL),
            'https://keycloak.example.com:8443'
        )
        self.assertEqual(
            Setting().get(PluginSettings.KEYCLOAK_PUBLIC_URL),
            'https://auth.example.com:8443'
        )
        self.assertEqual(
            Setting().get(PluginSettings.KEYCLOAK_REALM),
            'production'
        )
        self.assertFalse(Setting().get(PluginSettings.AUTO_CREATE_USERS))
        self.assertTrue(Setting().get(PluginSettings.ALLOW_REGISTRATION))

    def testSetConfigurationForbidden(self):
        """Test regular users cannot set configuration."""
        config_data = {
            'keycloakUrl': 'https://keycloak:8443',
            'keycloakPublicUrl': 'https://localhost:8443',
            'keycloakRealm': 'test',
            'clientId': 'test',
            'clientSecret': 'secret',
            'enable': True,
            'autoCreateUsers': True,
            'allowRegistration': False,
            'ignoreRegistrationPolicy': False
        }
        
        resp = self.request('/oidc/configuration', method='PUT',
                           user=self.user, data=config_data)
        self.assertStatus(resp, 403)

    def testConfigurationDefaults(self):
        """Test default configuration values."""
        self.ensureUserIsAdmin(self.admin_user)
        
        # Clear all settings
        for key in [PluginSettings.KEYCLOAK_URL, PluginSettings.KEYCLOAK_PUBLIC_URL,
                   PluginSettings.KEYCLOAK_REALM, PluginSettings.CLIENT_ID,
                   PluginSettings.ENABLE]:
            try:
                Setting().unset(key)
            except:
                pass
        
        resp = self.request('/oidc/configuration', user=self.admin_user)
        self.assertStatusOk(resp)
        
        config = resp.json
        # Should have defaults from environment or hardcoded values
        self.assertIsNotNone(config['keycloakUrl'])
        self.assertIsNotNone(config['keycloakPublicUrl'])
        self.assertIsNotNone(config['keycloakRealm'])
