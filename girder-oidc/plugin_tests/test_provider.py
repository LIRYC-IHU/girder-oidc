"""Tests for Keycloak provider."""

import os
import pytest
from unittest.mock import Mock, patch, MagicMock
from girder.models.setting import Setting
from girder.exceptions import RestException
from girder.models.user import User

from girder_oidc.providers import KeycloakProvider
from girder_oidc.settings import PluginSettings


class TestKeycloakProvider:
    """Test Keycloak OIDC provider."""

    def setup_method(self):
        """Set up test fixtures."""
        # Clear environment variables
        for key in ['KEYCLOAK_URL', 'KEYCLOAK_PUBLIC_URL']:
            if key in os.environ:
                del os.environ[key]

    def test_init_from_parameters(self):
        """Test provider initialization with explicit parameters."""
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        assert provider.keycloakUrl == 'https://keycloak:8443'
        assert provider.keycloakPublicUrl == 'https://localhost:8443'
        assert provider.realm == 'test'
        assert provider.clientId == 'client'

    def test_init_from_env_variables(self):
        """Test provider initialization from environment variables."""
        os.environ['KEYCLOAK_URL'] = 'https://env-keycloak:8443'
        os.environ['KEYCLOAK_PUBLIC_URL'] = 'https://env-public:8443'
        
        provider = KeycloakProvider()
        
        assert provider.keycloakUrl == 'https://env-keycloak:8443'
        assert provider.keycloakPublicUrl == 'https://env-public:8443'

    def test_url_normalization(self):
        """Test that URLs are normalized (trailing slashes removed)."""
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443/',
            keycloakPublicUrl='https://localhost:8443/',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        assert provider.keycloakUrl == 'https://keycloak:8443'
        assert provider.keycloakPublicUrl == 'https://localhost:8443'

    def test_realm_url_construction(self):
        """Test realm URL is constructed correctly."""
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='my-realm',
            clientId='client',
            clientSecret='secret'
        )
        
        assert provider.realmUrl == 'https://keycloak:8443/realms/my-realm'
        assert provider.realmPublicUrl == 'https://localhost:8443/realms/my-realm'

    @patch('girder_oidc.providers.requests.get')
    def test_get_well_known_config(self, mock_get):
        """Test fetching well-known OIDC configuration."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'authorization_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/auth',
            'token_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/token',
            'userinfo_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/userinfo',
        }
        mock_get.return_value = mock_response
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        config = provider.getWellKnownConfig()
        
        assert 'authorization_endpoint' in config
        assert 'token_endpoint' in config
        mock_get.assert_called_once()

    @patch('girder_oidc.providers.requests.get')
    def test_get_authorization_url(self, mock_get):
        """Test authorization URL generation."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'authorization_endpoint': 'https://localhost:8443/realms/test/protocol/openid-connect/auth',
            'token_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/token',
            'userinfo_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/userinfo',
        }
        mock_get.return_value = mock_response
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='my-client',
            clientSecret='secret'
        )
        
        auth_url = provider.getAuthorizationUrl('state123', 'https://girder/callback')
        
        assert 'client_id=my-client' in auth_url
        assert 'state=state123' in auth_url
        assert 'redirect_uri=' in auth_url
        assert 'https://localhost:8443' in auth_url  # Should use public URL

    @patch('girder_oidc.providers.requests.post')
    @patch('girder_oidc.providers.requests.get')
    def test_get_token(self, mock_get, mock_post):
        """Test token exchange."""
        mock_get.return_value.json.return_value = {
            'token_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/token',
            'authorization_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/auth',
            'userinfo_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/userinfo',
        }
        
        mock_post.return_value.json.return_value = {
            'access_token': 'token123',
            'token_type': 'Bearer',
            'expires_in': 3600,
        }
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        token_data = provider.getToken('code123', 'https://girder/callback')
        
        assert token_data['access_token'] == 'token123'
        mock_post.assert_called_once()

    @patch('girder_oidc.providers.requests.get')
    def test_get_user_info(self, mock_get):
        """Test fetching user information."""
        mock_get.side_effect = [
            Mock(json=lambda: {
                'token_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/token',
                'authorization_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/auth',
                'userinfo_endpoint': 'https://keycloak:8443/realms/test/protocol/openid-connect/userinfo',
            }),
            Mock(json=lambda: {
                'sub': 'user123',
                'email': 'user@example.com',
                'given_name': 'John',
                'family_name': 'Doe',
            })
        ]
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        user_info = provider.getUserInfo('token123')
        
        assert user_info['sub'] == 'user123'
        assert user_info['email'] == 'user@example.com'
        assert user_info['given_name'] == 'John'

    @patch('girder_oidc.providers.requests.get')
    def test_fix_url_for_public(self, mock_get):
        """Test URL replacement for public URLs."""
        mock_get.return_value.json.return_value = {
            'authorization_endpoint': 'https://keycloak:8443/realms/test/auth',
            'token_endpoint': 'https://keycloak:8443/realms/test/token',
            'userinfo_endpoint': 'https://keycloak:8443/realms/test/userinfo',
        }
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        fixed_url = provider._fixUrlForPublic('https://keycloak:8443/realms/test/auth')
        assert fixed_url == 'https://localhost:8443/realms/test/auth'

    def test_fix_url_for_public_no_change(self):
        """Test URL replacement when URLs are the same."""
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://keycloak:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        original_url = 'https://keycloak:8443/realms/test/auth'
        fixed_url = provider._fixUrlForPublic(original_url)
        assert fixed_url == original_url
