import cherrypy
import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from girder import events
from girder.constants import AccessType, SortDir
from girder.exceptions import RestException, ValidationException
from girder.api.describe import Description, autoDescribeRoute
from girder.api.rest import Resource, getApiUrl
from girder.api import access
from girder.models.setting import Setting
from girder.models.user import User
from girder.models.token import Token

from .providers import KeycloakProvider
from .settings import PluginSettings


class Oidc(Resource):
    """REST API endpoints for OIDC authentication."""
    
    def __init__(self):
        super().__init__()
        self.resourceName = 'oidc'
        
        self.route('GET', ('configuration',), self.getConfiguration)
        self.route('PUT', ('configuration',), self.setConfiguration)
        self.route('GET', ('login',), self.getLoginUrl)
        self.route('GET', ('callback',), self.callback)
        self.route('GET', ('is-oidc-user',), self.isOidcUser)
    
    def _createStateToken(self, redirect):
        """
        Create a CSRF token for the OIDC flow.
        
        :param redirect: URL to redirect to after authentication
        :returns: State token
        """
        csrfToken = Token().createToken(days=0.25)
        
        # The delimiter is arbitrary, but a dot doesn't need to be URL-encoded
        state = f'{csrfToken["_id"]}.{redirect}'
        return state
    
    def _validateStateToken(self, state):
        """
        Validate and consume a CSRF token.
        
        :param state: State token from OIDC callback
        :returns: Redirect URL
        :raises RestException: If token is invalid or expired
        """
        csrfTokenId, _, redirect = state.partition('.')
        
        token = Token().load(csrfTokenId, objectId=False, level=AccessType.READ)
        if token is None:
            raise RestException('Invalid CSRF token', code=403)
        
        Token().remove(token)
        
        if token['expires'] < datetime.datetime.utcnow():
            raise RestException('Expired CSRF token', code=403)
        
        if not redirect:
            raise RestException('No redirect location in state', code=400)
        
        return redirect
    
    @access.admin
    @autoDescribeRoute(
        Description('Get OIDC configuration (without secrets).')
    )
    def getConfiguration(self):
        """Get OIDC configuration for the admin panel."""
        return {
            'keycloakUrl': Setting().get(PluginSettings.KEYCLOAK_URL) or '',
            'keycloakPublicUrl': Setting().get(PluginSettings.KEYCLOAK_PUBLIC_URL) or '',
            'keycloakRealm': Setting().get(PluginSettings.KEYCLOAK_REALM) or '',
            'clientId': Setting().get(PluginSettings.CLIENT_ID) or '',
            'enable': Setting().get(PluginSettings.ENABLE) or False,
            'autoCreateUsers': Setting().get(PluginSettings.AUTO_CREATE_USERS) or False,
            'allowRegistration': Setting().get(PluginSettings.ALLOW_REGISTRATION) or False,
            'ignoreRegistrationPolicy': Setting().get(PluginSettings.IGNORE_REGISTRATION_POLICY) or False,
        }
    
    @access.admin
    @autoDescribeRoute(
        Description('Set OIDC configuration.')
        .param('keycloakUrl', 'Keycloak internal URL (for server-to-server communication)', dataType='string')
        .param('keycloakPublicUrl', 'Keycloak public URL (for browser redirects)', dataType='string')
        .param('keycloakRealm', 'Keycloak realm name', dataType='string')
        .param('clientId', 'OIDC client ID', dataType='string')
        .param('clientSecret', 'OIDC client secret', dataType='string')
        .param('enable', 'Enable OIDC authentication', dataType='boolean')
        .param('autoCreateUsers', 'Automatically create users', dataType='boolean')
        .param('allowRegistration', 'Allow registration from OIDC', dataType='boolean')
        .param('ignoreRegistrationPolicy', 'Ignore closed registration policy', dataType='boolean')
    )
    def setConfiguration(self, keycloakUrl, keycloakPublicUrl, keycloakRealm, clientId, clientSecret,
                        enable, autoCreateUsers, allowRegistration, ignoreRegistrationPolicy):
        """Set OIDC configuration (admin only)."""
        Setting().set(PluginSettings.KEYCLOAK_URL, keycloakUrl)
        Setting().set(PluginSettings.KEYCLOAK_PUBLIC_URL, keycloakPublicUrl)
        Setting().set(PluginSettings.KEYCLOAK_REALM, keycloakRealm)
        Setting().set(PluginSettings.CLIENT_ID, clientId)
        Setting().set(PluginSettings.CLIENT_SECRET, clientSecret)
        Setting().set(PluginSettings.ENABLE, enable)
        Setting().set(PluginSettings.AUTO_CREATE_USERS, autoCreateUsers)
        Setting().set(PluginSettings.ALLOW_REGISTRATION, allowRegistration)
        Setting().set(PluginSettings.IGNORE_REGISTRATION_POLICY, ignoreRegistrationPolicy)
        
        return self.getConfiguration()
    
    @access.public
    @autoDescribeRoute(
        Description('Get the Keycloak login URL.')
        .param('redirect', 'Where to redirect after login', dataType='string')
    )
    def getLoginUrl(self, redirect):
        """Get the Keycloak authorization URL."""
        try:
            if not Setting().get(PluginSettings.ENABLE):
                raise RestException('OIDC is not enabled', code=403)
            
            if not Setting().get(PluginSettings.CLIENT_ID):
                raise RestException('OIDC client ID is not configured', code=500)
            
            state = self._createStateToken(redirect)
            redirectUri = '/'.join((getApiUrl(), 'oidc', 'callback'))
            
            provider = KeycloakProvider()
            authUrl = provider.getAuthorizationUrl(state, redirectUri)
            
            return {'url': authUrl}
        except RestException:
            raise
        except Exception as e:
            raise RestException(f'Failed to get authorization URL: {str(e)}', code=502)
    
    
    @access.public
    @autoDescribeRoute(
        Description('OIDC callback endpoint.')
        .param('state', 'State token from authorization request', paramType='query')
        .param('code', 'Authorization code from Keycloak', paramType='query')
        .param('error', 'Error from Keycloak', paramType='query', required=False)
    )
    def callback(self, state, code, error=None):
        """Handle OIDC callback from Keycloak."""
        
        if error:
            raise RestException(f'OIDC error: {error}', code=400)
        
        if not state or not code:
            raise RestException('Missing state or code parameter', code=400)
        
        try:
            redirect = self._validateStateToken(state)
        except RestException as e:
            raise e
        
        try:
            provider = KeycloakProvider()
            redirectUri = '/'.join((getApiUrl(), 'oidc', 'callback'))
            
            # Exchange code for tokens
            tokenResp = provider.getToken(code, redirectUri)
            if 'access_token' not in tokenResp:
                raise RestException('No access token in token response', code=502)
            accessToken = tokenResp['access_token']
            
            # Get user info
            userInfo = provider.getUserInfo(accessToken)
            
            # Create or update Girder user
            user = provider.createOrUpdateUser(userInfo)
            
            # Create authentication token
            authToken = Token().createToken(user=user, days=365)
            
            # Redirect with token
            redirect = urlunparse(urlparse(redirect)._replace(
                query=urlencode({'girderToken': authToken['_id']})
            ))

            raise cherrypy.HTTPRedirect(redirect)
            
        except cherrypy.HTTPRedirect:
            raise
        except RestException as e:
            raise e
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise RestException(f'OIDC authentication failed: {str(e)}', code=502)
    
    @access.public
    @autoDescribeRoute(
        Description('Check if the current user is an OIDC user.')
    )
    def isOidcUser(self):
        """Check if current user is authenticated via OIDC."""
        try:
            user = self.getCurrentUser()
            if not user:
                return {'isOidcUser': False}
            
            # Check if user has OIDC provider info
            oidcArray = user.get('oidc', [])
            isOidc = isinstance(oidcArray, list) and len(oidcArray) > 0 and any(
                o.get('provider') == 'keycloak' for o in oidcArray
            )
            
            return {'isOidcUser': isOidc}
        except Exception as e:
            raise RestException(f'Failed to check OIDC user status: {str(e)}', code=500)
