"""Tests for OIDC user management."""

from unittest.mock import Mock, patch
from girder.test import base
from girder.exceptions import RestException
from girder.models.setting import Setting
from girder.models.user import User
from girder.settings import SettingKey

from girder_oidc.providers import KeycloakProvider
from girder_oidc.settings import PluginSettings


class TestOidcUserManagement(base.TestCase):
    """Test OIDC user creation and management."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        # Enable auto-create by default
        Setting().set(PluginSettings.AUTO_CREATE_USERS, True)
        Setting().set(PluginSettings.ALLOW_REGISTRATION, False)

    def testCreateUserFromOidc(self):
        """Test creating a new Girder user from OIDC credentials."""
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        user_info = {
            'sub': 'oidc-user-123',
            'email': 'newuser@example.com',
            'given_name': 'New',
            'family_name': 'User'
        }
        
        user = provider.createOrUpdateUser(user_info)
        
        self.assertIsNotNone(user)
        self.assertEqual(user['email'], 'newuser@example.com')
        self.assertEqual(user['firstName'], 'New')
        self.assertEqual(user['lastName'], 'User')
        self.assertTrue(user.get('oidc'))
        self.assertEqual(user['oidc'][0]['provider'], 'keycloak')
        self.assertEqual(user['oidc'][0]['id'], 'oidc-user-123')

    def testUpdateExistingOidcUser(self):
        """Test updating an existing OIDC user."""
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        # Create initial user
        initial_info = {
            'sub': 'oidc-user-456',
            'email': 'user@example.com',
            'given_name': 'John',
            'family_name': 'Doe'
        }
        user1 = provider.createOrUpdateUser(initial_info)
        user_id = user1['_id']
        
        # Update same user with new info
        updated_info = {
            'sub': 'oidc-user-456',
            'email': 'user@example.com',
            'given_name': 'Jonathan',
            'family_name': 'Doe'
        }
        user2 = provider.createOrUpdateUser(updated_info)
        
        self.assertEqual(user2['_id'], user_id)
        self.assertEqual(user2['firstName'], 'Jonathan')
        # Should only have one OIDC entry
        self.assertEqual(len(user2['oidc']), 1)

    def testCreateUserByEmailLookup(self):
        """Test updating user found by email."""
        # Create a user without OIDC
        existing_user = self.model('user').createUser(
            login='existing', email='existing@example.com',
            firstName='Existing', lastName='User', password='password'
        )
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        # Create OIDC entry for same email
        user_info = {
            'sub': 'oidc-user-789',
            'email': 'existing@example.com',
            'given_name': 'Existing',
            'family_name': 'User'
        }
        
        user = provider.createOrUpdateUser(user_info)
        
        self.assertEqual(user['_id'], existing_user['_id'])
        self.assertTrue(user.get('oidc'))
        self.assertEqual(user['oidc'][0]['provider'], 'keycloak')

    def testCreateUserAutoCreateDisabled(self):
        """Test that creation fails when auto-create is disabled."""
        Setting().set(PluginSettings.AUTO_CREATE_USERS, False)
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        user_info = {
            'sub': 'oidc-user-new',
            'email': 'newuser@example.com',
            'given_name': 'New',
            'family_name': 'User'
        }
        
        with self.assertRaises(RestException) as cm:
            provider.createOrUpdateUser(user_info)
        
        self.assertEqual(cm.exception.code, 403)

    def testCreateUserClosedRegistration(self):
        """Test user creation respects closed registration policy."""
        Setting().set(PluginSettings.AUTO_CREATE_USERS, True)
        Setting().set(PluginSettings.ALLOW_REGISTRATION, False)
        Setting().set(SettingKey.REGISTRATION_POLICY, 'closed')
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        user_info = {
            'sub': 'oidc-user-closed',
            'email': 'newuser@example.com',
            'given_name': 'New',
            'family_name': 'User'
        }
        
        with self.assertRaises(RestException) as cm:
            provider.createOrUpdateUser(user_info)
        
        self.assertEqual(cm.exception.code, 403)

    def testCreateUserIgnoreRegistrationPolicy(self):
        """Test ignoring closed registration policy."""
        Setting().set(PluginSettings.AUTO_CREATE_USERS, True)
        Setting().set(PluginSettings.ALLOW_REGISTRATION, False)
        Setting().set(PluginSettings.IGNORE_REGISTRATION_POLICY, True)
        Setting().set(SettingKey.REGISTRATION_POLICY, 'closed')
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        user_info = {
            'sub': 'oidc-user-ignore',
            'email': 'newuser@example.com',
            'given_name': 'New',
            'family_name': 'User'
        }
        
        # Should succeed even though registration is closed
        user = provider.createOrUpdateUser(user_info)
        self.assertIsNotNone(user)

    def testCreateUserMissingEmail(self):
        """Test that user creation fails without email."""
        Setting().set(PluginSettings.AUTO_CREATE_USERS, True)
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        user_info = {
            'sub': 'oidc-user-noemail',
            'given_name': 'No',
            'family_name': 'Email'
        }
        
        with self.assertRaises(RestException) as cm:
            provider.createOrUpdateUser(user_info)
        
        self.assertEqual(cm.exception.code, 502)

    def testCreateUserMissingSubject(self):
        """Test that user creation fails without subject claim."""
        Setting().set(PluginSettings.AUTO_CREATE_USERS, True)
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        user_info = {
            'email': 'user@example.com',
            'given_name': 'Test',
            'family_name': 'User'
        }
        
        with self.assertRaises(RestException) as cm:
            provider.createOrUpdateUser(user_info)
        
        self.assertEqual(cm.exception.code, 502)

    def testUniqueLoginGeneration(self):
        """Test that login names are made unique."""
        Setting().set(PluginSettings.AUTO_CREATE_USERS, True)
        
        provider = KeycloakProvider(
            keycloakUrl='https://keycloak:8443',
            keycloakPublicUrl='https://localhost:8443',
            realm='test',
            clientId='client',
            clientSecret='secret'
        )
        
        # Create first user with email prefix
        user_info1 = {
            'sub': 'oidc-user-1',
            'email': 'john@example.com',
            'given_name': 'John',
            'family_name': 'Doe'
        }
        user1 = provider.createOrUpdateUser(user_info1)
        self.assertEqual(user1['login'], 'john')
        
        # Create another user with same email prefix
        user_info2 = {
            'sub': 'oidc-user-2',
            'email': 'john.smith@example.com',
            'given_name': 'John',
            'family_name': 'Smith'
        }
        user2 = provider.createOrUpdateUser(user_info2)
        self.assertEqual(user2['login'], 'john1')
