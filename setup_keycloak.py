#!/usr/bin/env python3
"""
Setup script for Keycloak test realm and user.

This script creates a test realm and OIDC client in Keycloak,
and adds test users for development purposes.

Usage:
    python setup_keycloak.py [options]

Options:
    --keycloak-url      Keycloak base URL (default: https://localhost:8443)
    --admin-user        Admin username (default: admin)
    --admin-password    Admin password (default: admin)
    --realm-name        Realm name to create (default: girder)
    --client-id         Client ID (default: girder)
    --redirect-uri      Redirect URI (default: http://localhost:8080/api/v1/oidc/callback)
    --test-user         Test username (default: testuser)
    --test-password     Test password (default: testpass123)
    --test-email        Test email (default: test@example.com)
"""

import os
import sys
import json
import argparse
import requests
from urllib.parse import urljoin
import time


def _getVerifySetting():
    """
    Get the SSL verification setting from environment.
    
    Returns True (use system certs) if REQUESTS_CA_BUNDLE is not set or points to a non-existent file.
    Returns the path if it exists and is readable.
    """
    ca_bundle = os.path.join(os.environ.get('TLS_CERT'), 'rootCA.pem') if os.environ.get('TLS_CERT') else None
    if ca_bundle and os.path.isfile(ca_bundle):
        return ca_bundle
    return True


class KeycloakSetup:
    """Helper class for Keycloak setup operations."""
    
    def __init__(self, keycloak_url, admin_user, admin_password):
        """
        Initialize Keycloak client.
        
        :param keycloak_url: Base URL of Keycloak
        :param admin_user: Admin username
        :param admin_password: Admin password
        """
        self.keycloak_url = keycloak_url.rstrip('/')
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.token = None
        self.token_expires = 0
        
    def _ensure_running(self, max_retries=30):
        """Wait for Keycloak to be ready."""
        print("Waiting for Keycloak to be ready...")
        verify = _getVerifySetting()
        for i in range(max_retries):
            try:
                resp = requests.get(
                    f'{self.keycloak_url}/admin/realms',
                    timeout=5,
                    verify=verify
                )
                if resp.status_code in [200, 401, 403]:
                    print("✓ Keycloak is ready")
                    return True
            except requests.RequestException as e:
                if i < max_retries - 1:
                    print(f"  Waiting... ({i+1}/{max_retries})")
                    time.sleep(1)
                continue
        
        raise Exception("Keycloak did not respond after 30 seconds")
    
    def _get_token(self):
        """Get admin token if not cached or expired."""
        if self.token and time.time() < self.token_expires:
            return self.token
        
        print("Authenticating with Keycloak...")
        verify = _getVerifySetting()
        resp = requests.post(
            f'{self.keycloak_url}/realms/master/protocol/openid-connect/token',
            data={
                'grant_type': 'password',
                'client_id': 'admin-cli',
                'username': self.admin_user,
                'password': self.admin_password,
            },
            timeout=10,
            verify=verify
        )
        
        if resp.status_code != 200:
            print(f"✗ Authentication failed: {resp.text}")
            raise Exception(f"Failed to authenticate: {resp.status_code}")
        
        data = resp.json()
        self.token = data['access_token']
        self.token_expires = time.time() + data['expires_in'] - 60
        print("✓ Authenticated")
        return self.token
    
    def _request(self, method, endpoint, **kwargs):
        """Make authenticated request to Keycloak."""
        token = self._get_token()
        url = urljoin(f'{self.keycloak_url}/', endpoint.lstrip('/'))
        
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {token}'
        kwargs['headers'] = headers
        
        # Disable SSL verification for self-signed certificates
        if 'verify' not in kwargs:
            kwargs['verify'] = False
        
        return requests.request(method, url, timeout=10, **kwargs)
    
    def create_realm(self, realm_name):
        """
        Create a new realm.
        
        :param realm_name: Name of the realm
        :return: True if successful or already exists
        """
        print(f"\nCreating realm '{realm_name}'...")
        
        # Check if realm exists
        resp = self._request('GET', f'/admin/realms/{realm_name}')
        if resp.status_code == 200:
            print(f"✓ Realm '{realm_name}' already exists")
            return True
        
        # Create realm
        resp = self._request(
            'POST',
            '/admin/realms',
            json={
                'realm': realm_name,
                'enabled': True,
                'displayName': f'{realm_name.capitalize()} Realm',
                'userManagedAccessAllowed': False,
            }
        )
        
        if resp.status_code == 201:
            print(f"✓ Created realm '{realm_name}'")
            return True
        else:
            print(f"✗ Failed to create realm: {resp.text}")
            return False
    
    def create_client(self, realm_name, client_id, client_secret, redirect_uri):
        """
        Create OIDC client in realm.
        
        :param realm_name: Realm name
        :param client_id: Client ID
        :param client_secret: Client secret
        :param redirect_uri: Redirect URI
        :return: Client data or None
        """
        print(f"\nCreating OIDC client '{client_id}'...")
        
        # Check if client exists
        resp = self._request(
            'GET',
            f'/admin/realms/{realm_name}/clients',
            params={'clientId': client_id}
        )
        
        if resp.status_code == 200:
            clients = resp.json()
            if clients:
                print(f"✓ Client '{client_id}' already exists")
                return clients[0]
        
        # Create client
        resp = self._request(
            'POST',
            f'/admin/realms/{realm_name}/clients',
            json={
                'clientId': client_id,
                'enabled': True,
                'clientAuthenticatorType': 'client-secret',
                'redirectUris': [redirect_uri],
                'webOrigins': [redirect_uri.rsplit('/', 1)[0]],
                'publicClient': False,
                'standardFlowEnabled': True,
                'implicitFlowEnabled': False,
                'directAccessGrantsEnabled': False,
                'serviceAccountsEnabled': False,
                'protocol': 'openid-connect',
                'attributes': {
                    'oidc.ciba.grant.enabled': 'false',
                    'client.secret.creation.time': '1234567890',
                }
            }
        )
        
        if resp.status_code == 201:
            location = resp.headers.get('Location')
            if location:
                # Get the created client
                resp = self._request('GET', location)
                if resp.status_code == 200:
                    client = resp.json()
                    print(f"✓ Created client '{client_id}'")
                    return client
        else:
            print(f"✗ Failed to create client: {resp.text}")
            return None
    
    def create_user(self, realm_name, username, email, first_name, last_name, password):
        """
        Create a user in realm.
        
        :param realm_name: Realm name
        :param username: Username
        :param email: Email address
        :param first_name: First name
        :param last_name: Last name
        :param password: Password
        :return: User data or None
        """
        print(f"\nCreating user '{username}'...")
        
        # Check if user exists
        resp = self._request(
            'GET',
            f'/admin/realms/{realm_name}/users',
            params={'username': username}
        )
        
        if resp.status_code == 200:
            users = resp.json()
            if users:
                print(f"✓ User '{username}' already exists")
                return users[0]
        
        # Create user
        resp = self._request(
            'POST',
            f'/admin/realms/{realm_name}/users',
            json={
                'username': username,
                'email': email,
                'firstName': first_name,
                'lastName': last_name,
                'enabled': True,
                'emailVerified': True,
                'attributes': {},
            }
        )
        
        if resp.status_code == 201:
            location = resp.headers.get('Location')
            if location:
                # Get the created user
                resp = self._request('GET', location)
                if resp.status_code == 200:
                    user = resp.json()
                    print(f"✓ Created user '{username}'")
                    
                    # Set password
                    resp = self._request(
                        'PUT',
                        f'/admin/realms/{realm_name}/users/{user["id"]}/reset-password',
                        json={
                            'type': 'password',
                            'value': password,
                            'temporary': False,
                        }
                    )
                    
                    if resp.status_code == 204:
                        print(f"✓ Set password for user '{username}'")
                    
                    return user
        else:
            print(f"✗ Failed to create user: {resp.text}")
            return None


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Setup Keycloak test realm and user'
    )
    parser.add_argument(
        '--keycloak-url',
        default='https://localhost:8443',
        help='Keycloak base URL'
    )
    parser.add_argument(
        '--admin-user',
        default='admin',
        help='Admin username'
    )
    parser.add_argument(
        '--admin-password',
        default='admin',
        help='Admin password'
    )
    parser.add_argument(
        '--realm-name',
        default='girder',
        help='Realm name'
    )
    parser.add_argument(
        '--client-id',
        default='girder',
        help='Client ID'
    )
    parser.add_argument(
        '--redirect-uri',
        default='http://localhost:8080/api/v1/oidc/callback',
        help='Redirect URI'
    )
    parser.add_argument(
        '--test-user',
        default='testuser',
        help='Test username'
    )
    parser.add_argument(
        '--test-password',
        default='testpass123',
        help='Test password'
    )
    parser.add_argument(
        '--test-email',
        default='test@example.com',
        help='Test email'
    )
    
    args = parser.parse_args()
    
    try:
        setup = KeycloakSetup(
            args.keycloak_url,
            args.admin_user,
            args.admin_password
        )
        
        # Wait for Keycloak to start
        setup._ensure_running()
        
        # Create realm
        if not setup.create_realm(args.realm_name):
            sys.exit(1)
        
        # Create client
        client = setup.create_client(
            args.realm_name,
            args.client_id,
            args.client_secret,
            args.redirect_uri
        )
        if not client:
            sys.exit(1)
        
        # Create test user
        user = setup.create_user(
            args.realm_name,
            args.test_user,
            args.test_email,
            'Test',
            'User',
            args.test_password
        )
        if not user:
            sys.exit(1)
        
        # Print summary
        print("\n" + "="*60)
        print("✓ Keycloak setup complete!")
        print("="*60)
        print(f"\nRealm: {args.realm_name}")
        print(f"Client ID: {args.client_id}")
        print(f"Client Secret: {args.client_secret}")
        print(f"Redirect URI: {args.redirect_uri}")
        print(f"\nTest User:")
        print(f"  Username: {args.test_user}")
        print(f"  Password: {args.test_password}")
        print(f"  Email: {args.test_email}")
        print("\nKeycloak Admin: http://localhost:8081/admin")
        print(f"Girder: http://localhost:8080")
        print("="*60)
        
    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
