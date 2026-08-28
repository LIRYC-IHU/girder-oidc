"""REST-level tests for the admin OIDC configuration endpoints: the admin-claim
settings round-trip and the "test connection" probe."""

import pytest

from pytest_girder.assertions import assertStatus, assertStatusOk

from girder.models.user import User

from girder_oidc import rest as oidc_rest


@pytest.fixture
def admin(db):
    return User().createUser(
        login='siteadmin', password='password123', firstName='Site',
        lastName='Admin', email='siteadmin@example.com', admin=True)


@pytest.fixture
def normalUser(db):
    return User().createUser(
        login='plainuser', password='password123', firstName='Plain',
        lastName='User', email='plain@example.com', admin=False)


@pytest.mark.plugin('oidc')
def test_admin_claim_settings_round_trip(server, admin):
    resp = server.request(
        path='/oidc/configuration', method='PUT', user=admin,
        params={'adminClaim': 'groups', 'adminClaimValue': 'girder-admins'})
    assertStatusOk(resp)
    assert resp.json['adminClaim'] == 'groups'
    assert resp.json['adminClaimValue'] == 'girder-admins'

    resp = server.request(path='/oidc/configuration', method='GET', user=admin)
    assertStatusOk(resp)
    assert resp.json['adminClaim'] == 'groups'
    assert resp.json['adminClaimValue'] == 'girder-admins'


@pytest.mark.plugin('oidc')
def test_required_claim_settings_round_trip(server, admin):
    # Blank by default: the access filter is opt-in.
    resp = server.request(path='/oidc/configuration', method='GET', user=admin)
    assertStatusOk(resp)
    assert resp.json['requiredClaim'] == ''
    assert resp.json['requiredClaimValue'] == ''

    resp = server.request(
        path='/oidc/configuration', method='PUT', user=admin,
        params={'requiredClaim': 'resource_access.girder.roles',
                'requiredClaimValue': 'access'})
    assertStatusOk(resp)
    assert resp.json['requiredClaim'] == 'resource_access.girder.roles'
    assert resp.json['requiredClaimValue'] == 'access'

    resp = server.request(path='/oidc/configuration', method='GET', user=admin)
    assertStatusOk(resp)
    assert resp.json['requiredClaim'] == 'resource_access.girder.roles'
    assert resp.json['requiredClaimValue'] == 'access'


@pytest.mark.plugin('oidc')
def test_trust_unverified_email_defaults_off_and_round_trips(server, admin):
    resp = server.request(path='/oidc/configuration', method='GET', user=admin)
    assertStatusOk(resp)
    assert resp.json['trustUnverifiedEmail'] is False

    resp = server.request(
        path='/oidc/configuration', method='PUT', user=admin,
        params={'trustUnverifiedEmail': True})
    assertStatusOk(resp)
    assert resp.json['trustUnverifiedEmail'] is True


@pytest.mark.plugin('oidc')
def test_client_secret_is_never_returned(server, admin):
    server.request(
        path='/oidc/configuration', method='PUT', user=admin,
        params={'clientSecret': 'super-secret'})
    resp = server.request(path='/oidc/configuration', method='GET', user=admin)
    assertStatusOk(resp)
    assert resp.json['clientSecretSet'] is True
    assert 'super-secret' not in str(resp.json)


@pytest.mark.plugin('oidc')
def test_plaintext_public_url_is_rejected(server, admin):
    """The browser-facing URL is the issuer the ID token is checked against, so
    it must not be reachable over plaintext outside localhost."""
    resp = server.request(
        path='/oidc/configuration', method='PUT', user=admin,
        params={'publicUrl': 'http://idp.example.com'})
    assertStatus(resp, 400)

    # https is fine...
    resp = server.request(
        path='/oidc/configuration', method='PUT', user=admin,
        params={'publicUrl': 'https://idp.example.com'})
    assertStatusOk(resp)

    # ...and so is plain http on localhost, for the dev stack.
    resp = server.request(
        path='/oidc/configuration', method='PUT', user=admin,
        params={'publicUrl': 'http://localhost:5556/dex'})
    assertStatusOk(resp)


@pytest.mark.plugin('oidc')
def test_non_http_provider_url_is_rejected(server, admin):
    resp = server.request(
        path='/oidc/configuration', method='PUT', user=admin,
        params={'publicUrl': 'file:///etc/passwd'})
    assertStatus(resp, 400)


@pytest.mark.plugin('oidc')
def test_public_config_leaks_nothing(server):
    """`GET /oidc/config` is unauthenticated -- it must expose only what the
    login button needs."""
    resp = server.request(path='/oidc/config', method='GET')
    assertStatusOk(resp)
    assert set(resp.json) == {'enabled', 'buttonLabel'}


@pytest.mark.plugin('oidc')
def test_test_connection_ok(server, admin, monkeypatch):
    monkeypatch.setattr(
        oidc_rest, 'probeProvider',
        lambda publicUrl, internalUrl: {
            'issuer': publicUrl, 'jwksKeys': 3,
            'authorizationEndpoint': None, 'tokenEndpoint': None,
            'userinfoEndpoint': None})
    resp = server.request(
        path='/oidc/configuration/test', method='POST', user=admin,
        params={'publicUrl': 'https://idp.example.com'})
    assertStatusOk(resp)
    assert resp.json['ok'] is True
    assert resp.json['issuer'] == 'https://idp.example.com'
    assert resp.json['jwksKeys'] == 3


@pytest.mark.plugin('oidc')
def test_test_connection_reports_failure(server, admin, monkeypatch):
    from girder.exceptions import RestException

    def boom(publicUrl, internalUrl):
        raise RestException('unreachable', code=502)
    monkeypatch.setattr(oidc_rest, 'probeProvider', boom)

    resp = server.request(
        path='/oidc/configuration/test', method='POST', user=admin,
        params={'publicUrl': 'https://idp.example.com'})
    # A failed probe is a normal 200 result the UI renders, not an HTTP error.
    assertStatusOk(resp)
    assert resp.json['ok'] is False
    assert 'unreachable' in resp.json['message']


@pytest.mark.plugin('oidc')
def test_test_connection_requires_admin(server, admin, normalUser):
    # `admin` is created first so that `normalUser` isn't auto-promoted as the
    # instance's first account; it must be a genuine non-admin for this check.
    assert normalUser['admin'] is False
    resp = server.request(
        path='/oidc/configuration/test', method='POST', user=normalUser,
        params={'publicUrl': 'https://idp.example.com'})
    assertStatus(resp, 403)
