# OIDC Plugin Tests

Comprehensive test suite for the Girder OIDC/Keycloak plugin.

## Test Modules

### `test_configuration.py`
Tests for OIDC configuration endpoints.

**Coverage:**
- `GET /api/v1/oidc/configuration` - Admin retrieval
- `PUT /api/v1/oidc/configuration` - Admin configuration update
- Access control (admin only)
- Default values and fallbacks

**Key Tests:**
- `testGetConfiguration` - Verify configuration retrieval
- `testSetConfiguration` - Verify configuration persistence
- `testGetConfigurationForbidden` - Regular users cannot access
- `testConfigurationDefaults` - Default values are set correctly

### `test_provider.py`
Unit tests for the Keycloak OIDC provider.

**Coverage:**
- Provider initialization
- URL handling (internal vs public)
- Well-known configuration retrieval
- Authorization URL generation
- Token exchange
- User information retrieval
- URL normalization and transformation

**Key Tests:**
- `test_init_from_parameters` - Direct initialization
- `test_init_from_env_variables` - Environment variable fallbacks
- `test_url_normalization` - Trailing slash removal
- `test_realm_url_construction` - Proper URL composition
- `test_get_authorization_url` - Correct public URL usage
- `test_get_token` - OIDC token exchange
- `test_get_user_info` - User claims retrieval
- `test_fix_url_for_public` - URL replacement logic

### `test_user_management.py`
Tests for OIDC user creation and updates.

**Coverage:**
- User creation from OIDC credentials
- User updates on repeated authentication
- Email-based user lookup
- Auto-create settings
- Registration policy enforcement
- Login uniqueness

**Key Tests:**
- `testCreateUserFromOidc` - New user creation
- `testUpdateExistingOidcUser` - User updates
- `testCreateUserByEmailLookup` - Link to existing user
- `testCreateUserAutoCreateDisabled` - Respect settings
- `testCreateUserClosedRegistration` - Honor registration policy
- `testCreateUserIgnoreRegistrationPolicy` - Policy override
- `testCreateUserMissingEmail` - Validation
- `testUniqueLoginGeneration` - Login collision handling

### `test_rest_endpoints.py`
Integration tests for REST API endpoints.

**Coverage:**
- Login URL generation
- Callback handling
- User status checks
- Configuration validation
- Access control

**Key Tests:**
- `testGetLoginUrl` - Authorization URL creation
- `testGetLoginUrlNotEnabled` - Disabled OIDC handling
- `testCallbackMissingCode` - Missing code validation
- `testCallbackInvalidState` - CSRF token validation
- `testIsOidcUser` - User type detection
- `testSetConfigurationWithValidStrings` - Configuration updates

## Running Tests

### Run All Tests
```bash
pytest plugin_tests/
```

### Run Specific Test Module
```bash
pytest plugin_tests/test_configuration.py
```

### Run Specific Test
```bash
pytest plugin_tests/test_configuration.py::TestOidcConfiguration::testGetConfiguration
```

### Run with Coverage
```bash
pytest --cov=girder_oidc plugin_tests/
```

### Run with Verbose Output
```bash
pytest -v plugin_tests/
```

## Test Requirements

The test suite uses:
- `pytest` - Test framework
- `pytest-girder` - Girder testing utilities
- `unittest.mock` - Mocking HTTP requests to Keycloak
- MongoDB - For user model tests

## Key Testing Patterns

### Mocking Keycloak Responses
```python
@patch('girder_oidc.providers.requests.get')
def test_something(self, mock_get):
    mock_get.return_value.json.return_value = {
        'authorization_endpoint': 'https://...'
    }
    # Test code
```

### Testing Admin Endpoints
```python
self.ensureUserIsAdmin(self.admin_user)
resp = self.request('/oidc/configuration', user=self.admin_user)
self.assertStatusOk(resp)
```

### Testing Access Control
```python
# Should work for admin
resp = self.request('/oidc/configuration', user=self.admin_user)
self.assertStatusOk(resp)

# Should fail for regular user
resp = self.request('/oidc/configuration', user=self.user)
self.assertStatus(resp, 403)

# Should fail for anonymous
resp = self.request('/oidc/configuration')
self.assertStatus(resp, 401)
```

## Coverage Goals

- Configuration endpoints: 95%+
- Provider class: 90%+
- User management: 85%+
- REST endpoints: 80%+

## Continuous Integration

Tests should be run:
- On every commit
- Before merging PRs
- In Docker containers to match production environment

Example CI command:
```bash
docker run -it girder-oidc-tests pytest plugin_tests/ --cov=girder_oidc
```
