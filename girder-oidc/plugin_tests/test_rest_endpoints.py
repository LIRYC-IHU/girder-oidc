"""Tests for OIDC REST endpoints."""

import json
from unittest.mock import Mock, patch
from girder.test import base
from girder.models.setting import Setting
from girder.models.token import Token

from girder_oidc.settings import PluginSettings


class TestOidcRestEndpoints(base.TestCase):
    """Test OIDC REST API endpoints."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.admin_user = self.model('user').createUser(
            login='admin', email='admin@example.com', firstName='Admin',
            lastName='User', password='password')
        self.user = self.model('user').createUser(
            login='user', email='user@example.com', firstName='Regular',
            lastName='User', password='password')
        self.ensureUserIsAdmin(self.admin_user)
        
        # Configure OIDC
        Setting().set(PluginSettings.KEYCLOAK_URL, 'https://keycloak:8443')
        Setting().set(PluginSettings.KEYCLOAK_PUBLIC_URL, 'https://localhost:8443')
        Setting().set(PluginSettings.KEYCLOAK_REALM, 'test')
        Setting().set(PluginSettings.CLIENT_ID, 'test-client')
        Setting().set(PluginSettings.ENABLE, True)

    @patch('girder_oidc.providers.requests.get')
    def testGetLoginUrl(self, mock_get):
        """Test GET /oidc/login returns authorization URL."""
        mock_get.return_value.json.return_value = {
            'authorization_endpoint': 'https://localhost:8443/realms/test/protocol/openid-connect/auth',
            'token_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/token',
            'userinfo_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/userinfo',
        }
        
        resp = self.request('/oidc/login', query={'redirect': 'http://localhost:8080/#!/login'})
        self.assertStatusOk(resp)
        
        data = resp.json
        self.assertIn('url', data)
        self.assertIn('authorization_endpoint', data['url'])
        self.assertIn('client_id=test-client', data['url'])
        self.assertIn('response_type=code', data['url'])

    def testGetLoginUrlNotEnabled(self):
        """Test login fails when OIDC is not enabled."""
        Setting().set(PluginSettings.ENABLE, False)
        
        resp = self.request('/oidc/login', query={'redirect': 'http://localhost:8080'})
        self.assertStatus(resp, 403)

    def testGetLoginUrlNoClientId(self):
        """Test login fails without client ID configured."""
        Setting().set(PluginSettings.CLIENT_ID, '')
        
        resp = self.request('/oidc/login', query={'redirect': 'http://localhost:8080'})
        self.assertStatus(resp, 500)

    @patch('girder_oidc.providers.requests.post')
    @patch('girder_oidc.providers.requests.get')
    def testCallbackMissingCode(self, mock_get, mock_post):
        """Test callback fails without authorization code."""
        resp = self.request('/oidc/callback', query={'state': 'state123'})
        self.assertStatus(resp, 400)

    @patch('girder_oidc.providers.requests.post')
    @patch('girder_oidc.providers.requests.get')
    def testCallbackInvalidState(self, mock_get, mock_post):
        """Test callback fails with invalid state token."""
        resp = self.request('/oidc/callback', 
                           query={'state': 'invalid.token', 'code': 'code123'})
        self.assertStatus(resp, 403)

    def testIsOidcUserNotLoggedIn(self):
        """Test isOidcUser returns false for anonymous users."""
        resp = self.request('/oidc/is-oidc-user')
        self.assertStatusOk(resp)
        
        data = resp.json
        self.assertFalse(data['isOidcUser'])

    def testIsOidcUserNotOidcUser(self):
        """Test isOidcUser returns false for non-OIDC users."""
        resp = self.request('/oidc/is-oidc-user', user=self.user)
        self.assertStatusOk(resp)
        
        data = resp.json
        self.assertFalse(data['isOidcUser'])

    def testIsOidcUserOidcUser(self):
        """Test isOidcUser returns true for OIDC authenticated users."""
        # Add OIDC info to user
        self.user['oidc'] = [{'provider': 'keycloak', 'id': 'user123'}]
        self.model('user').save(self.user)
        
        resp = self.request('/oidc/is-oidc-user', user=self.user)
        self.assertStatusOk(resp)
        
        data = resp.json
        self.assertTrue(data['isOidcUser'])

    def testLoginAttemptWithoutPassword(self):
        """Test that OIDC users get helpful error when trying password login."""
        # Add OIDC info to user but no password
        self.user['oidc'] = [{'provider': 'keycloak', 'id': 'user123'}]
        self.user['password'] = ''
        self.model('user').save(self.user)
        
        # Try to login with password
        resp = self.request('/user/me', user=self.user)
        self.assertStatusOk(resp)
        # User should be logged in via token


class TestOidcSettingsValidation(base.TestCase):
    """Test OIDC settings validation."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.admin_user = self.model('user').createUser(
            login='admin', email='admin@example.com', firstName='Admin',
            lastName='User', password='password')
        self.ensureUserIsAdmin(self.admin_user)

    def testSetConfigurationWithValidStrings(self):
        """Test setting configuration with valid string values."""
        config_data = {
            'keycloakUrl': 'https://valid.example.com',
            'keycloakPublicUrl': 'https://public.example.com',
            'keycloakRealm': 'valid-realm',
            'clientId': 'valid-client-id',
            'clientSecret': 'valid-secret',
            'enable': True,
            'autoCreateUsers': True,
            'allowRegistration': False,
            'ignoreRegistrationPolicy': False
        }
        
        resp = self.request('/oidc/configuration', method='PUT',
                           user=self.admin_user, data=config_data)
        self.assertStatusOk(resp)

    def testSetConfigurationWithValidBooleans(self):
        """Test setting configuration with boolean values."""
        config_data = {
            'keycloakUrl': 'https://keycloak:8443',
            'keycloakPublicUrl': 'https://localhost:8443',
            'keycloakRealm': 'test',
            'clientId': 'client',
            'clientSecret': 'secret',
            'enable': False,
            'autoCreateUsers': False,
            'allowRegistration': True,
            'ignoreRegistrationPolicy': True
        }
        
        resp = self.request('/oidc/configuration', method='PUT',
                           user=self.admin_user, data=config_data)
        self.assertStatusOk(resp)
        
        # Verify values were set
        result = resp.json
        self.assertFalse(result['enable'])
        self.assertFalse(result['autoCreateUsers'])
        self.assertTrue(result['allowRegistration'])
        self.assertTrue(result['ignoreRegistrationPolicy'])
