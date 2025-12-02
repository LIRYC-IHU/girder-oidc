# Girder OIDC Plugin

A Girder plugin for OpenID Connect (OIDC) authentication via Keycloak.

## Features

- OIDC/Keycloak integration with automatic user creation
- Admin panel configuration
- Secure token exchange using authorization code flow
- Automatic OIDC endpoint discovery

## Installation

```bash
pip install -e .
```

## Configuration

In the Girder admin panel, go to **OIDC/Keycloak Configuration** and set:

- **Keycloak URL (Internal)**: Internal URL for server communication (e.g., `https://keycloak:8443`)
- **Keycloak Public URL**: Public URL for browser redirects (e.g., `https://localhost:8443`)
- **Keycloak Realm**: Realm name (e.g., `girder`)
- **Client ID**: OIDC client ID
- **Client Secret**: OIDC client secret
- **Enable OIDC**: Enable authentication
- **Auto Create Users**: Create Girder users automatically
- **Allow Registration**: Allow new user registration

## Keycloak Setup

1. Create an OIDC client in Keycloak:
   - **Access Type**: `confidential`
   - **Valid Redirect URIs**: `https://your-girder-host/api/v1/oidc/callback`

2. Copy the client credentials to Girder configuration

## API Endpoints

- `GET /api/v1/oidc/configuration` - Get config (admin only)
- `PUT /api/v1/oidc/configuration` - Update config (admin only)
- `GET /api/v1/oidc/login?redirect=URL` - Get authorization URL
- `GET /api/v1/oidc/callback` - Callback from Keycloak

## Development

```bash
pytest plugin_tests/
```

## License

Apache 2.0
