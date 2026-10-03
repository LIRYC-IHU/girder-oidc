"""REST tests for POST /oidc/token_exchange.

The provider is simulated: a local RSA key signs access tokens, and the OIDC
client's discovery/JWKS loader is patched to publish its public half. Everything
past the signature check -- settings, account lookup, access policy, the token
that comes out -- runs for real against the test database.
"""

import datetime
import logging
import time

import pytest
from authlib.jose import JsonWebKey, jwt
from pytest_girder.assertions import assertStatus, assertStatusOk

from girder.constants import TokenScope
from girder.exceptions import RestException, ValidationException
from girder.models.folder import Folder
from girder.models.group import Group
from girder.models.setting import Setting
from girder.models.token import Token
from girder.models.user import User
from girder.settings import SettingKey

from girder_oidc.client import OidcClient
from girder_oidc.settings import PluginSettings

ISSUER = 'https://idp.example.com/realms/test'
CLIENT_ID = 'girder'
AUDIENCE = 'girder-mcp'
SUB = 'sub-alice'


@pytest.fixture
def rsaKey():
    return JsonWebKey.generate_key('RSA', 2048, {'kid': 'k1'}, is_private=True)


@pytest.fixture
def provider(rsaKey, monkeypatch):
    discovery = {'issuer': ISSUER, 'jwks_uri': ISSUER + '/certs',
                 'authorization_endpoint': ISSUER + '/auth',
                 'token_endpoint': ISSUER + '/token'}
    jwks = {'keys': [rsaKey.as_dict(is_private=False)]}
    monkeypatch.setattr(OidcClient, '_load', lambda self: (discovery, jwks))


EXCHANGE_SECRET = 'mcp-server-exchange-secret'


@pytest.fixture(autouse=True)
def callerSecret(monkeypatch):
    """The resource server's secret, configured in Girder's environment."""
    monkeypatch.setenv('OIDC_TOKEN_EXCHANGE_SECRET', EXCHANGE_SECRET)


@pytest.fixture
def configured(db, provider):
    settings = Setting()
    settings.set(PluginSettings.ENABLED, True)
    settings.set(PluginSettings.CLIENT_ID, CLIENT_ID)
    settings.set(PluginSettings.PUBLIC_URL, ISSUER)
    settings.set(PluginSettings.TOKEN_EXCHANGE_AUDIENCE, AUDIENCE)
    settings.set(PluginSettings.TOKEN_EXCHANGE_SCOPE, 'girder-mcp')
    settings.set(PluginSettings.TOKEN_EXCHANGE_CLIENTS, 'claude-code')


@pytest.fixture
def linked(user):
    """`user` is linked to SUB, as after a first single sign-on login."""
    user['oidc'] = [{'provider': 'oidc', 'id': SUB}]
    return User().save(user)


def _mint(rsaKey, **overrides):
    now = int(time.time())
    payload = {'iss': ISSUER, 'aud': [AUDIENCE, 'account'], 'sub': SUB,
               'azp': 'claude-code', 'typ': 'Bearer', 'scope': 'openid girder-mcp',
               'iat': now, 'exp': now + 300}
    payload.update(overrides)
    payload = {k: v for k, v in payload.items() if v is not None}
    return jwt.encode({'alg': 'RS256', 'kid': 'k1', 'typ': 'JWT'}, payload, rsaKey).decode()


def _exchange(server, token, secret=EXCHANGE_SECRET, **kwargs):
    headers = [('X-Token-Exchange-Secret', secret)] if secret is not None else []
    return server.request(path='/oidc/token_exchange', method='POST',
                          body='subjectToken=' + token,
                          type='application/x-www-form-urlencoded',
                          additionalHeaders=headers, **kwargs)


# --- The happy path, and what comes out of it ----------------------------------------------

@pytest.mark.plugin('oidc')
def test_exchange_yields_a_short_read_only_token(server, configured, linked, rsaKey):
    resp = _exchange(server, _mint(rsaKey))
    assertStatusOk(resp)
    assert resp.json['scope'] == [TokenScope.DATA_READ]

    token = Token().load(resp.json['token'], force=True, objectId=False)
    assert token['userId'] == linked['_id']
    assert token['scope'] == [TokenScope.DATA_READ]
    remaining = token['expires'] - datetime.datetime.now(datetime.timezone.utc)
    assert remaining <= datetime.timedelta(seconds=300)  # capped by the access token
    assert token['oidcExchangeClient'] == 'claude-code'
    # Only a digest of the access token is kept.
    assert len(token['oidcExchange']) == 64


@pytest.mark.plugin('oidc')
def test_exchanged_token_reads_but_cannot_write(server, configured, linked, rsaKey):
    girderToken = _exchange(server, _mint(rsaKey)).json['token']
    folder = Folder().find({'parentId': linked['_id'], 'name': 'Private'})[0]

    resp = server.request(path='/folder/%s' % folder['_id'], token=girderToken)
    assertStatusOk(resp)

    resp = server.request(path='/folder', method='POST', token=girderToken,
                          params={'parentId': str(folder['_id']), 'name': 'nope'})
    assertStatus(resp, 401)
    # Not an authentication token: account settings are out of reach.
    resp = server.request(path='/user/%s' % linked['_id'], method='PUT', token=girderToken,
                          params={'firstName': 'X', 'lastName': 'Y', 'email': 'x@example.com'})
    assertStatus(resp, 401)
    resp = server.request(path='/api_key', method='POST', token=girderToken,
                          params={'name': 'escalate'})
    assertStatus(resp, 401)


@pytest.mark.plugin('oidc')
def test_lifetime_is_capped_by_the_setting(server, configured, linked, rsaKey):
    Setting().set(PluginSettings.TOKEN_EXCHANGE_MINUTES, 2)
    long = _mint(rsaKey, exp=int(time.time()) + 7200)
    token = Token().load(_exchange(server, long).json['token'], force=True, objectId=False)
    remaining = token['expires'] - datetime.datetime.now(datetime.timezone.utc)
    assert datetime.timedelta(seconds=60) < remaining <= datetime.timedelta(minutes=2)


@pytest.mark.plugin('oidc')
def test_nearly_expired_token_never_falls_back_to_session_lifetime(
        server, configured, linked, rsaKey):
    """`Token().createToken(days=0)` means "default cookie lifetime" (180 days):
    an access token in its last seconds must give a token of seconds, or none."""
    now = int(time.time())
    resp = _exchange(server, _mint(rsaKey, iat=now - 300, exp=now + 2))
    if 'token' in (resp.json or {}):
        token = Token().load(resp.json['token'], force=True, objectId=False)
        remaining = token['expires'] - datetime.datetime.now(datetime.timezone.utc)
        assert remaining <= datetime.timedelta(seconds=5)
    else:
        assertStatus(resp, 401)
    # Within the 30 s validation leeway, but already past `exp`: refused.
    resp = _exchange(server, _mint(rsaKey, iat=now - 300, exp=now - 10))
    assertStatus(resp, 401)


@pytest.mark.plugin('oidc')
def test_same_access_token_reuses_its_girder_token(server, configured, linked, rsaKey):
    access = _mint(rsaKey)
    first = _exchange(server, access).json['token']
    assert _exchange(server, access).json['token'] == first
    assert Token().collection.count_documents({'oidcExchange': {'$exists': True}}) == 1
    # Another access token (another session) gets its own.
    other = _exchange(server, _mint(rsaKey, jti='another')).json['token']
    assert other != first


@pytest.mark.plugin('oidc')
def test_exchange_writes_nothing_on_the_user(server, configured, linked, rsaKey):
    Setting().set(PluginSettings.ADMIN_CLAIM, 'roles')
    Setting().set(PluginSettings.ADMIN_CLAIM_VALUE, 'girder-admin')
    Setting().set(PluginSettings.GROUPS_CLAIM, 'groups')
    before = User().load(linked['_id'], force=True)
    resp = _exchange(server, _mint(rsaKey, roles=['girder-admin'], groups=['new-group'],
                                   email='other@example.com'))
    assertStatusOk(resp)
    after = User().load(linked['_id'], force=True)
    # No promotion from the access token, no group created or joined, no email change.
    assert after['admin'] is False
    assert after.get('groups', []) == before.get('groups', [])
    assert after['email'] == before['email']
    assert Group().findOne({'name': 'new-group'}) is None


# --- Refused: the feature itself ---------------------------------------------------------

@pytest.mark.plugin('oidc')
def test_disabled_without_audience(server, configured, linked, rsaKey):
    Setting().set(PluginSettings.TOKEN_EXCHANGE_AUDIENCE, '')
    assertStatus(_exchange(server, _mint(rsaKey)), 403)


@pytest.mark.plugin('oidc')
def test_disabled_when_oidc_is_off(server, configured, linked, rsaKey):
    Setting().set(PluginSettings.ENABLED, False)
    assertStatus(_exchange(server, _mint(rsaKey)), 403)


@pytest.mark.plugin('oidc')
def test_audience_equal_to_client_id_is_refused(server, configured, linked, rsaKey):
    with pytest.raises(ValidationException):
        Setting().set(PluginSettings.TOKEN_EXCHANGE_AUDIENCE, CLIENT_ID)
    # Set the client id afterwards: the guard still holds at the point of use.
    Setting().set(PluginSettings.CLIENT_ID, AUDIENCE)
    resp = _exchange(server, _mint(rsaKey, aud=AUDIENCE))
    assertStatus(resp, 403)
    assert 'misconfigured' in resp.json['message']


@pytest.mark.plugin('oidc')
@pytest.mark.parametrize('value', ['a b', 'a\tb', 42, None])
def test_audience_setting_must_be_a_single_name(db, value):
    with pytest.raises(ValidationException):
        Setting().set(PluginSettings.TOKEN_EXCHANGE_AUDIENCE, value)


@pytest.mark.plugin('oidc')
@pytest.mark.parametrize('value', [0, -5, 1441, '60', True, 1.5])
def test_lifetime_setting_bounds(db, value):
    with pytest.raises(ValidationException):
        Setting().set(PluginSettings.TOKEN_EXCHANGE_MINUTES, value)


@pytest.mark.plugin('oidc')
def test_token_in_query_string_is_refused(server, configured, linked, rsaKey):
    # With both `params` and `body`, pytest-girder sends the params in the URL.
    resp = server.request(path='/oidc/token_exchange', method='POST',
                          params={'subjectToken': _mint(rsaKey)}, body='unused=1',
                          type='application/x-www-form-urlencoded')
    assertStatus(resp, 400)
    assert 'body' in resp.json['message']
    assert Token().collection.count_documents({'oidcExchange': {'$exists': True}}) == 0


@pytest.mark.plugin('oidc')
def test_missing_token_is_a_400(server, configured):
    resp = server.request(path='/oidc/token_exchange', method='POST')
    assertStatus(resp, 400)


# --- Refused: the token -------------------------------------------------------------------

@pytest.mark.plugin('oidc')
def test_invalid_tokens_are_401_and_mint_nothing(server, configured, linked, rsaKey):
    other = JsonWebKey.generate_key('RSA', 2048, {'kid': 'k1'}, is_private=True)
    now = int(time.time())
    for bad in (
        _mint(other),                                    # not signed by the provider
        _mint(rsaKey, aud='account'),                    # meant for someone else
        _mint(rsaKey, aud=CLIENT_ID),                    # meant for Girder's own login
        _mint(rsaKey, typ='ID'),                         # an ID token
        _mint(rsaKey, typ='Refresh'),                    # a refresh token
        _mint(rsaKey, iss='https://evil.example.com'),
        _mint(rsaKey, iat=now - 7200, exp=now - 3600),   # expired
        'not-a-jwt',
    ):
        assertStatus(_exchange(server, bad), 401)
    assert Token().collection.count_documents({'oidcExchange': {'$exists': True}}) == 0


@pytest.mark.plugin('oidc')
def test_required_scope(server, configured, linked, rsaKey):
    Setting().set(PluginSettings.TOKEN_EXCHANGE_SCOPE, 'girder-mcp')
    assertStatus(_exchange(server, _mint(rsaKey, scope='openid email')), 401)
    assertStatusOk(_exchange(server, _mint(rsaKey, scope='openid girder-mcp')))


# --- Refused: the identity ----------------------------------------------------------------

@pytest.mark.plugin('oidc')
def test_unlinked_identity_is_refused_and_nothing_is_created(server, configured, rsaKey):
    count = User().collection.count_documents({})
    resp = _exchange(server, _mint(rsaKey, sub='never-logged-in', email='new@example.com'))
    assertStatus(resp, 403)
    assert 'Sign in to Girder once' in resp.json['message']
    assert User().collection.count_documents({}) == count


@pytest.mark.plugin('oidc')
def test_no_linking_by_email(server, configured, user, rsaKey):
    """An unlinked account whose address matches the token's email claim must not
    be reachable: linking happens at interactive login only, with its own checks."""
    resp = _exchange(server, _mint(rsaKey, sub='attacker-sub', email=user['email'],
                                   email_verified=True))
    assertStatus(resp, 403)
    assert 'oidc' not in User().load(user['_id'], force=True)


@pytest.mark.plugin('oidc')
def test_other_provider_entry_does_not_match(server, configured, user, rsaKey):
    """$elemMatch: provider and id must come from the same link entry."""
    user['oidc'] = [{'provider': 'elsewhere', 'id': SUB}]
    User().save(user)
    assertStatus(_exchange(server, _mint(rsaKey)), 403)


@pytest.mark.plugin('oidc')
def test_disabled_account_is_refused(server, configured, linked, rsaKey):
    linked['status'] = 'disabled'
    User().save(linked)
    assertStatus(_exchange(server, _mint(rsaKey)), 403)


@pytest.mark.plugin('oidc')
def test_account_pending_approval_is_refused(server, configured, linked, rsaKey):
    Setting().set(SettingKey.REGISTRATION_POLICY, 'approve')
    linked['status'] = 'pending'
    User().save(linked)
    assertStatus(_exchange(server, _mint(rsaKey)), 403)


@pytest.mark.plugin('oidc')
def test_unverified_email_when_required_is_refused(server, configured, linked, rsaKey):
    Setting().set(SettingKey.EMAIL_VERIFICATION, 'required')
    linked['emailVerified'] = False
    User().save(linked)
    assertStatus(_exchange(server, _mint(rsaKey)), 403)


@pytest.mark.plugin('oidc')
def test_required_claim_is_enforced(server, configured, linked, rsaKey):
    Setting().set(PluginSettings.REQUIRED_CLAIM, 'groups')
    Setting().set(PluginSettings.REQUIRED_CLAIM_VALUE, 'girder-users')
    assertStatus(_exchange(server, _mint(rsaKey, groups=['other'])), 403)
    assertStatus(_exchange(server, _mint(rsaKey)), 403)
    assertStatusOk(_exchange(server, _mint(rsaKey, groups=['girder-users'])))


@pytest.mark.plugin('oidc')
def test_admin_needs_the_admin_claim_in_the_access_token(server, configured, linked, rsaKey):
    linked['admin'] = True
    User().save(linked)
    Setting().set(PluginSettings.ADMIN_CLAIM, 'roles')
    Setting().set(PluginSettings.ADMIN_CLAIM_VALUE, 'girder-admin')

    resp = _exchange(server, _mint(rsaKey))
    assertStatus(resp, 403)
    assert 'site-admin' in resp.json['message']
    assertStatusOk(_exchange(server, _mint(rsaKey, roles=['girder-admin'])))


@pytest.mark.plugin('oidc')
def test_admin_without_admin_mapping_keeps_girder_rights(server, configured, linked, rsaKey):
    """No admin claim configured: Girder's own flag stands, as at login."""
    linked['admin'] = True
    User().save(linked)
    assertStatusOk(_exchange(server, _mint(rsaKey)))


@pytest.mark.plugin('oidc')
def test_expired_cached_token_is_not_reused(server, configured, linked, rsaKey):
    access = _mint(rsaKey)
    first = _exchange(server, access).json['token']
    cached = Token().load(first, force=True, objectId=False)
    cached['expires'] = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=5)
    Token().save(cached)
    assert _exchange(server, access).json['token'] != first


@pytest.mark.plugin('oidc')
def test_cached_token_of_another_user_is_not_returned(server, configured, linked, admin, rsaKey):
    """The cache key is the access token AND the account it resolves to."""
    access = _mint(rsaKey)
    first = _exchange(server, access).json['token']
    cached = Token().load(first, force=True, objectId=False)
    cached['userId'] = admin['_id']
    Token().save(cached)
    second = _exchange(server, access).json['token']
    assert second != first
    assert Token().load(second, force=True, objectId=False)['userId'] == linked['_id']


@pytest.mark.plugin('oidc')
def test_configuration_round_trip(server, configured, admin):
    resp = server.request(path='/oidc/configuration', method='PUT', user=admin, params={
        'tokenExchangeAudience': ' girder-mcp ', 'tokenExchangeScope': 'girder-mcp',
        'tokenExchangeMinutes': 15})
    assertStatusOk(resp)
    assert resp.json['tokenExchangeAudience'] == 'girder-mcp'
    assert resp.json['tokenExchangeScope'] == 'girder-mcp'
    assert resp.json['tokenExchangeMinutes'] == 15
    resp = server.request(path='/oidc/configuration', method='PUT', user=admin,
                          params={'tokenExchangeAudience': CLIENT_ID})
    assertStatus(resp, 400)


# --- Audit-driven cases ------------------------------------------------------------------

@pytest.mark.plugin('oidc')
def test_scope_and_clients_are_mandatory(server, configured, linked, rsaKey):
    for key in (PluginSettings.TOKEN_EXCHANGE_SCOPE, PluginSettings.TOKEN_EXCHANGE_CLIENTS):
        previous = Setting().get(key)
        Setting().set(key, '')
        resp = _exchange(server, _mint(rsaKey))
        assertStatus(resp, 403)
        assert 'misconfigured' in resp.json['message']
        Setting().set(key, previous)
    assertStatusOk(_exchange(server, _mint(rsaKey)))


@pytest.mark.plugin('oidc')
def test_only_allowed_clients_may_exchange(server, configured, linked, rsaKey):
    """Another application of the realm that obtains the audience (scope added to
    its own login, or a direct-grant client skipping MFA) must be refused."""
    for azp in ('other-app', '', 'claude-code-evil', 'CLAUDE-CODE'):
        assertStatus(_exchange(server, _mint(rsaKey, azp=azp)), 403)
    assertStatus(_exchange(server, _mint(rsaKey, azp=None)), 403)  # no client named at all
    assert Token().collection.count_documents({'oidcExchange': {'$exists': True}}) == 0
    # RFC 9068 tokens name the client in `client_id`.
    assertStatusOk(_exchange(server, _mint(rsaKey, azp=None, client_id='claude-code')))
    # Several clients, comma or space separated.
    Setting().set(PluginSettings.TOKEN_EXCHANGE_CLIENTS, 'claude-code, mcp-inspector')
    assert Setting().get(PluginSettings.TOKEN_EXCHANGE_CLIENTS) == 'claude-code mcp-inspector'
    assertStatusOk(_exchange(server, _mint(rsaKey, azp='mcp-inspector')))


@pytest.mark.plugin('oidc')
@pytest.mark.parametrize('audience', ['account', 'realm-management', 'broker'])
def test_reserved_audiences_are_refused(server, configured, linked, rsaKey, audience):
    with pytest.raises(ValidationException):
        Setting().set(PluginSettings.TOKEN_EXCHANGE_AUDIENCE, audience)
    # Even if forced into the database, the exchange refuses to run.
    Setting().collection.update_one(
        {'key': PluginSettings.TOKEN_EXCHANGE_AUDIENCE}, {'$set': {'value': audience}})
    Setting()._get.invalidate(PluginSettings.TOKEN_EXCHANGE_AUDIENCE)
    assert Setting().get(PluginSettings.TOKEN_EXCHANGE_AUDIENCE) == audience
    assertStatus(_exchange(server, _mint(rsaKey, aud=[audience])), 403)


def _mirroredGroup(name, claimValue, creator):
    group = Group().createGroup(name, creator=creator, public=False)
    group['oidc'] = {'provider': 'oidc', 'claim': claimValue}
    return Group().save(group)


@pytest.mark.plugin('oidc')
def test_revoked_mirrored_group_refuses_the_exchange(server, configured, linked, admin,
                                                      rsaKey):
    """Removed from a group at the provider, still in its Girder mirror (sync only
    happens at login): the exchange must not hand out a token reaching its data."""
    Setting().set(PluginSettings.GROUPS_CLAIM, 'groups')
    cardio = _mirroredGroup('cardio', 'cardio', admin)
    Group().addUser(cardio, linked)

    assertStatusOk(_exchange(server, _mint(rsaKey, groups=['cardio', 'other'])))
    assertStatusOk(_exchange(server, _mint(rsaKey, groups=['/cardio'])))  # keycloak path
    resp = _exchange(server, _mint(rsaKey, groups=['other']))
    assertStatus(resp, 403)
    assert 'group memberships have changed' in resp.json['message']
    assertStatus(_exchange(server, _mint(rsaKey, groups=[])), 403)
    # Claim absent from the access token: cannot be checked, so refused.
    resp = _exchange(server, _mint(rsaKey))
    assertStatus(resp, 403)
    assert 'groups claim' in resp.json['message']
    # And nothing was written: still a member of the mirror.
    assert cardio['_id'] in User().load(linked['_id'], force=True)['groups']


@pytest.mark.plugin('oidc')
def test_group_check_ignores_hand_made_groups_and_additive_sync(
        server, configured, linked, admin, rsaKey):
    Setting().set(PluginSettings.GROUPS_CLAIM, 'groups')
    manual = Group().createGroup('manual', creator=admin, public=False)
    Group().addUser(manual, linked)
    # A hand-made group is not the provider's business.
    assertStatusOk(_exchange(server, _mint(rsaKey, groups=[])))
    mirror = _mirroredGroup('mirror', 'mirror', admin)
    Group().addUser(mirror, User().load(linked['_id'], force=True))
    assertStatus(_exchange(server, _mint(rsaKey, groups=['x'])), 403)
    # Additive-only sync: the provider does not own removals.
    Setting().set(PluginSettings.GROUPS_AUTHORITATIVE, False)
    assertStatusOk(_exchange(server, _mint(rsaKey, groups=['y'])))
    assertStatusOk(_exchange(server, _mint(rsaKey)))


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.mark.plugin('oidc')
def test_bearer_credentials_stay_out_of_the_audit_log(server, configured, linked, rsaKey):
    audit = logging.getLogger('girder_audit')
    capture = _Capture()
    audit.addHandler(capture)
    try:
        access = _mint(rsaKey)
        assertStatusOk(_exchange(server, access))
        server.request(path='/oidc/exchange', method='POST', params={'code': 'secret-code'})
        server.request(path='/oidc/config')  # control: an ordinary route IS audited
    finally:
        audit.removeHandler(capture)
    dumped = ' '.join(repr(r.__dict__) for r in capture.records)
    assert "('oidc', 'config')" in dumped
    assert access not in dumped and 'secret-code' not in dumped
    assert "'token_exchange'" not in dumped and "'exchange'" not in dumped


@pytest.mark.plugin('oidc')
def test_unknown_signing_key_is_refused(server, configured, linked):
    stranger = JsonWebKey.generate_key('RSA', 2048, {'kid': 'unknown'}, is_private=True)
    now = int(time.time())
    payload = {'iss': ISSUER, 'aud': AUDIENCE, 'sub': SUB, 'azp': 'claude-code',
               'scope': 'girder-mcp', 'iat': now, 'exp': now + 300}
    token = jwt.encode({'alg': 'RS256', 'kid': 'unknown'}, payload, stranger).decode()
    assertStatus(_exchange(server, token), 401)


@pytest.mark.plugin('oidc')
def test_unreachable_provider_is_a_502_and_mints_nothing(server, db, linked, rsaKey,
                                                          monkeypatch):
    from girder_oidc import client as oidcClient
    settings = Setting()
    settings.set(PluginSettings.ENABLED, True)
    settings.set(PluginSettings.CLIENT_ID, CLIENT_ID)
    settings.set(PluginSettings.PUBLIC_URL, 'https://down.example.com/realms/x')
    settings.set(PluginSettings.TOKEN_EXCHANGE_AUDIENCE, AUDIENCE)
    settings.set(PluginSettings.TOKEN_EXCHANGE_SCOPE, 'girder-mcp')
    settings.set(PluginSettings.TOKEN_EXCHANGE_CLIENTS, 'claude-code')
    calls = []

    def unreachable(url, **kwargs):
        calls.append(url)
        raise RestException('OIDC provider request failed: timeout', code=502)
    monkeypatch.setattr(oidcClient, '_httpGetJson', unreachable)
    OidcClient._failures.clear()
    OidcClient._cache.clear()
    try:
        assertStatus(_exchange(server, _mint(rsaKey)), 502)
        assertStatus(_exchange(server, _mint(rsaKey)), 502)
        # The failure is remembered: one fetch, not one per request.
        assert len(calls) == 1
        assert Token().collection.count_documents({'oidcExchange': {'$exists': True}}) == 0
    finally:
        OidcClient._failures.clear()
        OidcClient._cache.clear()


@pytest.mark.plugin('oidc')
@pytest.mark.parametrize('key,raw', [
    ('GIRDER_SETTING_OIDC_TOKEN_EXCHANGE_CLIENTS', '["claude-code"]'),
    ('GIRDER_SETTING_OIDC_TOKEN_EXCHANGE_AUDIENCE', '["girder-mcp"]'),
    ('GIRDER_SETTING_OIDC_TOKEN_EXCHANGE_SCOPE', '42'),
    ('GIRDER_SETTING_OIDC_TOKEN_EXCHANGE_MINUTES', '"60"'),
    ('GIRDER_SETTING_OIDC_TOKEN_EXCHANGE_MINUTES', '100000'),
])
def test_settings_forced_by_environment_are_type_checked(server, configured, linked, rsaKey,
                                                          monkeypatch, key, raw):
    """GIRDER_SETTING_* values skip the validators: a wrong type must refuse (403),
    never crash (500) nor widen what is accepted."""
    monkeypatch.setenv(key, raw)
    for k in (PluginSettings.TOKEN_EXCHANGE_CLIENTS, PluginSettings.TOKEN_EXCHANGE_AUDIENCE,
              PluginSettings.TOKEN_EXCHANGE_SCOPE, PluginSettings.TOKEN_EXCHANGE_MINUTES):
        Setting()._get.invalidate(k)
    try:
        assertStatus(_exchange(server, _mint(rsaKey)), 403)
    finally:
        monkeypatch.delenv(key)
        for k in (PluginSettings.TOKEN_EXCHANGE_CLIENTS, PluginSettings.TOKEN_EXCHANGE_AUDIENCE,
                  PluginSettings.TOKEN_EXCHANGE_SCOPE, PluginSettings.TOKEN_EXCHANGE_MINUTES):
            Setting()._get.invalidate(k)



# --- Reserved to the resource server -----------------------------------------------------

@pytest.mark.plugin('oidc')
@pytest.mark.parametrize('presented', [None, '', 'wrong', EXCHANGE_SECRET + 'x',
                                       EXCHANGE_SECRET[:-1], 'é' * 30])
def test_only_the_resource_server_may_exchange(server, configured, linked, rsaKey,
                                               monkeypatch, presented):
    """A client that holds a valid access token must not get a Girder token itself
    (it would then query Girder around the MCP server and its audit journal)."""
    loads = []
    original = OidcClient._load
    monkeypatch.setattr(OidcClient, '_load', lambda self: loads.append(1) or original(self))
    resp = _exchange(server, _mint(rsaKey), secret=presented)
    assertStatus(resp, 403)
    assert 'reserved to the resource server' in resp.json['message']
    # Refused before anything about the token is looked at: no JWKS, no token.
    assert loads == []
    assert Token().collection.count_documents({'oidcExchange': {'$exists': True}}) == 0


@pytest.mark.plugin('oidc')
@pytest.mark.parametrize('configuredSecret', [
    None, '', 'short-secret', ' padded-secret-0123456789 ', 'non-ascii-sécret-0123456789',
    'with\ttab-0123456789abcdef',
])
def test_exchange_refused_while_the_secret_is_not_usable(
        server, configured, linked, rsaKey, monkeypatch, caplog, configuredSecret):
    if configuredSecret is None:
        monkeypatch.delenv('OIDC_TOKEN_EXCHANGE_SECRET', raising=False)
    else:
        monkeypatch.setenv('OIDC_TOKEN_EXCHANGE_SECRET', configuredSecret)
    with caplog.at_level(logging.ERROR, logger='girder_oidc.token_exchange'):
        # Even a caller presenting the same (weak or unusable) value is refused...
        resp = _exchange(server, _mint(rsaKey), secret=(configuredSecret or '').strip())
    assertStatus(resp, 403)
    # ...with the same answer as a wrong secret: the reason is for the server log only.
    assert resp.json['message'] == 'Token exchange is reserved to the resource server.'
    assert 'OIDC_TOKEN_EXCHANGE_SECRET' in caplog.text


@pytest.mark.plugin('oidc')
def test_secret_is_checked_before_the_exchange_settings(server, db, linked, rsaKey):
    """Exchange settings empty: a caller without the secret still learns nothing
    more than "reserved" (no "misconfigured" detail)."""
    Setting().set(PluginSettings.ENABLED, True)
    resp = _exchange(server, _mint(rsaKey), secret='wrong')
    assertStatus(resp, 403)
    assert resp.json['message'] == 'Token exchange is reserved to the resource server.'


@pytest.mark.plugin('oidc')
def test_secret_never_appears_in_logs_or_responses(server, configured, linked, rsaKey, caplog):
    with caplog.at_level(logging.DEBUG):
        ok = _exchange(server, _mint(rsaKey))
        bad = _exchange(server, _mint(rsaKey), secret=EXCHANGE_SECRET[:-1] + 'X')
    assertStatusOk(ok)
    assertStatus(bad, 403)
    for text in (caplog.text, str(ok.json), str(bad.json)):
        assert EXCHANGE_SECRET not in text and EXCHANGE_SECRET[:-1] not in text
    assert 'wrong caller secret' in caplog.text


@pytest.mark.plugin('oidc')
def test_route_variants_are_covered_by_the_secret(server, configured, linked, rsaKey):
    """Girder routes `token_exchange/` like `token_exchange`: whatever a proxy rule
    misses, the application check still applies."""
    resp = server.request(path='/oidc/token_exchange/', method='POST',
                          body='subjectToken=' + _mint(rsaKey),
                          type='application/x-www-form-urlencoded')
    assertStatus(resp, 403)


@pytest.mark.plugin('oidc')
def test_configuration_reports_the_secret_without_revealing_it(server, configured, admin,
                                                               monkeypatch):
    resp = server.request(path='/oidc/configuration', user=admin)
    assertStatusOk(resp)
    assert resp.json['tokenExchangeSecretSet'] is True
    assert EXCHANGE_SECRET not in str(resp.json)
    monkeypatch.delenv('OIDC_TOKEN_EXCHANGE_SECRET')
    assert server.request(path='/oidc/configuration', user=admin).json[
        'tokenExchangeSecretSet'] is False
