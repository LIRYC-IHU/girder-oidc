import json
import os
import requests
from urllib.parse import urlencode

from girder.api.rest import getApiUrl
from girder.exceptions import RestException, ValidationException
from girder.models.setting import Setting
from girder.models.user import User
from girder.settings import SettingKey

from ..settings import PluginSettings


def _getVerifySetting():
    """
    Get the SSL verification setting from environment.
    
    Returns True (use system certs) if REQUESTS_CA_BUNDLE is not set or points to a non-existent file.
    Returns the path if it exists and is readable.
    """
    ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE')
    if ca_bundle and os.path.isfile(ca_bundle):
        return ca_bundle
    return True


class KeycloakProvider:
    """
    OIDC provider for Keycloak.
    
    This provider implements the OpenID Connect protocol for authentication
    with a Keycloak instance.
    """
    
    def __init__(self, keycloakUrl=None, keycloakPublicUrl=None, realm=None, clientId=None, clientSecret=None):
        """
        Initialize the Keycloak OIDC provider.
        
        :param keycloakUrl: Internal Keycloak URL (for server-to-server communication)
        :param keycloakPublicUrl: Public Keycloak URL (for browser redirects)
        :param realm: Keycloak realm name
        :param clientId: OIDC client ID
        :param clientSecret: OIDC client secret
        """
        # Check parameters first, then environment variables, then database settings
        self.keycloakUrl = keycloakUrl or os.environ.get('KEYCLOAK_URL') or Setting().get(PluginSettings.KEYCLOAK_URL)
        # Public URL: prefer parameter, then env var, then setting, then fall back to internal URL
        self.keycloakPublicUrl = keycloakPublicUrl or os.environ.get('KEYCLOAK_PUBLIC_URL') or Setting().get(PluginSettings.KEYCLOAK_PUBLIC_URL) or self.keycloakUrl
        
        self.realm = realm or Setting().get(PluginSettings.KEYCLOAK_REALM)
        self.clientId = clientId or Setting().get(PluginSettings.CLIENT_ID)
        self.clientSecret = clientSecret or Setting().get(PluginSettings.CLIENT_SECRET)
        
        # Normalize URLs
        self.keycloakUrl = self.keycloakUrl.rstrip('/')
        self.keycloakPublicUrl = self.keycloakPublicUrl.rstrip('/')
        self.realmUrl = f'{self.keycloakUrl}/realms/{self.realm}'
        self.realmPublicUrl = f'{self.keycloakPublicUrl}/realms/{self.realm}'
    
    def _fixUrlForPublic(self, url):
        """
        Replace internal Keycloak URL with public URL in a given URL string.
        
        :param url: URL that may contain the internal Keycloak URL
        :returns: URL with public URL substituted if needed
        """
        if self.keycloakUrl != self.keycloakPublicUrl and url:
            return url.replace(self.keycloakUrl, self.keycloakPublicUrl)
        return url
        
    def getWellKnownConfig(self):
        """
        Fetch the OpenID Connect well-known configuration from Keycloak.
        
        :returns: Configuration dictionary with endpoints and capabilities
        """
        url = f'{self.realmUrl}/.well-known/openid-configuration'
        try:
            resp = requests.get(url, timeout=10, verify=_getVerifySetting())
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            raise RestException(f'Failed to fetch Keycloak config: {str(e)}', code=502)
    
    def getAuthorizationUrl(self, state, redirectUri):
        """
        Get the Keycloak authorization URL for initiating the OIDC flow.
        
        :param state: CSRF state token
        :param redirectUri: Callback URI
        :returns: Authorization URL
        """
        config = self.getWellKnownConfig()
        authUrl = self._fixUrlForPublic(config['authorization_endpoint'])
        
        params = {
            'client_id': self.clientId,
            'response_type': 'code',
            'scope': 'openid profile email',
            'redirect_uri': redirectUri,
            'state': state,
        }
        
        return f'{authUrl}?{urlencode(params)}'
    
    def getToken(self, code, redirectUri):
        """
        Exchange authorization code for access token.
        
        :param code: Authorization code from Keycloak
        :param redirectUri: Callback URI
        :returns: Token response dictionary
        """
        config = self.getWellKnownConfig()
        tokenUrl = config['token_endpoint']
        
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': self.clientId,
            'client_secret': self.clientSecret,
            'redirect_uri': redirectUri,
        }
        
        try:
            resp = requests.post(tokenUrl, data=payload, timeout=10, verify=_getVerifySetting())
            resp.raise_for_status()
            token_data = resp.json()
            return token_data
        
        except requests.RequestException as e:
            raise RestException(f'Failed to get token: {str(e)}', code=502)
    
    def getUserInfo(self, accessToken):
        """
        Fetch user information from Keycloak using the access token.
        
        :param accessToken: OIDC access token
        :returns: User information dictionary
        """
        config = self.getWellKnownConfig()
        userinfoUrl = config['userinfo_endpoint']
        
        headers = {'Authorization': f'Bearer {accessToken}'}
        verify_setting = _getVerifySetting()
        
        try:
            resp = requests.get(userinfoUrl, headers=headers, timeout=10, verify=verify_setting)
            resp.raise_for_status()
            user_data = resp.json()
            return user_data
        except requests.RequestException as e:
            raise RestException(f'Failed to get user info: {str(e)}', code=502)
    
    def createOrUpdateUser(self, userInfo):
        """
        Create or update a Girder user based on OIDC user information.
        
        :param userInfo: User information from Keycloak
        :returns: Girder user document
        """
        oauthId = userInfo.get('sub')
        email = userInfo.get('email')
        firstName = userInfo.get('given_name', '')
        lastName = userInfo.get('family_name', '')
        
        if not oauthId:
            raise RestException('No subject claim in token', code=502)
        
        if not email:
            raise RestException('No email in user info', code=502)
        
        # Try finding by OIDC ID first
        query = {
            'oidc.provider': 'keycloak',
            'oidc.id': oauthId
        }
        user = User().findOne(query)
        
        if user:
            # Update existing user
            user['email'] = email
            user['firstName'] = firstName
            user['lastName'] = lastName
            return User().save(user)
        
        # Try finding by email
        user = User().findOne({'email': email})
        
        if not user:
            # Check if registration is allowed
            policy = Setting().get(SettingKey.REGISTRATION_POLICY)
            allowRegistration = Setting().get(PluginSettings.ALLOW_REGISTRATION)
            
            if policy == 'closed' and not allowRegistration:
                raise RestException(
                    'User registration is disabled',
                    code=403
                )
            
            # Check auto-create setting
            if not Setting().get(PluginSettings.AUTO_CREATE_USERS):
                raise RestException(
                    'User auto-creation is disabled. Please contact an administrator.',
                    code=403
                )
            
            # Create login from email prefix
            login = email.split('@')[0]
            
            # Ensure unique login
            counter = 1
            originalLogin = login
            while User().findOne({'login': login}):
                login = f'{originalLogin}{counter}'
                counter += 1
            
            # Create user
            user = User().createUser(
                login=login,
                email=email,
                firstName=firstName,
                lastName=lastName,
                password=None,  # OIDC users don't have passwords
            )
        
        # Store OIDC information
        if 'oidc' not in user:
            user['oidc'] = []
        
        # Add or update OIDC provider info
        oidcInfo = {
            'provider': 'keycloak',
            'id': oauthId,
        }
        
        # Check if this provider already exists
        user['oidc'] = [o for o in user['oidc'] if o.get('provider') != 'keycloak']
        user['oidc'].append(oidcInfo)
        
        return User().save(user)
