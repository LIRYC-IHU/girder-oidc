import requests

USERNAME = 'testuser'
PASSWORD = 'testpass123'
REALM = 'girder'
CLIENT_ID = 'girder'
CLIENT_SECRET = 'qq819I9oFVYY05D4T8KOUQxis60nLBKr'
KEYCLOAK_URL = 'https://localhost:8443'
GIRDER_API_URL = 'http://localhost:8080/api/v1'

def main():
    """ We test the API endpoint to exchange an OICD token for a Girder token. """
    # First, get an OIDC token from Keycloak using direct access grant
    token_resp = requests.post(
        f'{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token',
        data={
            'grant_type': 'password',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'username': USERNAME,
            'password': PASSWORD,
            'scope': 'openid profile email',  # Explicitly request scopes
        },
        verify=False  # Insecure, for testing only
    )
    token_resp.raise_for_status()
    oidc_token = token_resp.json()['access_token']
    
    # Now exchange the OIDC token for a Girder auth token
    girder_resp = requests.post(
        f'{GIRDER_API_URL}/oidc/token',
        data={'access_token': oidc_token}
    )
    girder_resp.raise_for_status()
    girder_token = girder_resp.json()['authToken']
    
    print(f'Obtained Girder auth token: {girder_token}')

if __name__ == '__main__':
    main()