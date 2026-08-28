"""Database-backed tests for OIDC user provisioning."""

import pytest

from girder.exceptions import RestException
from girder.models.setting import Setting
from girder.models.user import User
from girder.settings import SettingKey
from girder.utility import mail_utils

from girder_oidc.settings import PluginSettings
from girder_oidc.user import (_SUPPRESSION_MARKER, claimAssertsVerifiedEmail,
                              claimGrantsAccess, claimGrantsAdmin,
                              createOrReuseUser,
                              installVerificationEmailSuppression)


def test_claim_asserts_verified_email():
    assert claimAssertsVerifiedEmail({'email_verified': True}) is True
    assert claimAssertsVerifiedEmail({'email_verified': False}) is False
    # Providers that send the claim as a string still count as asserting it.
    assert claimAssertsVerifiedEmail({'email_verified': 'true'}) is True
    assert claimAssertsVerifiedEmail({'email_verified': 'TRUE'}) is True
    assert claimAssertsVerifiedEmail({'email_verified': 'false'}) is False
    # Absent, null or anything unexpected is not an assertion.
    assert claimAssertsVerifiedEmail({}) is False
    assert claimAssertsVerifiedEmail({'email_verified': None}) is False
    assert claimAssertsVerifiedEmail({'email_verified': 1}) is False


@pytest.mark.plugin('oidc')
def test_creates_passwordless_user(server):
    user = createOrReuseUser('sub-1', 'alice@example.com', 'Alice', 'Smith',
                             emailVerified=True)
    assert user['email'] == 'alice@example.com'
    assert user['login']
    assert user['oidc'] == [{'provider': 'oidc', 'id': 'sub-1'}]
    # No usable password was set.
    assert not User().hasPassword(user)
    # The provider vouched for the address, so girder's own email verification
    # must not stand in the way of the next login.
    assert user['emailVerified'] is True


@pytest.mark.plugin('oidc')
def test_falls_back_to_name_then_email_when_names_missing(server):
    # IdP supplied no given_name/family_name and no full name: both names must
    # still be non-empty (Girder rejects empty names) — fall back to the email.
    user = createOrReuseUser('sub-n1', 'noname@example.com', emailVerified=True)
    assert user['firstName'] == 'noname'
    assert user['lastName'] == 'noname'
    # A full `name` claim is split into first/last.
    user2 = createOrReuseUser('sub-n2', 'fn@example.com', fullName='Grace Hopper',
                              emailVerified=True)
    assert user2['firstName'] == 'Grace'
    assert user2['lastName'] == 'Hopper'


@pytest.mark.plugin('oidc')
def test_reuses_user_by_oidc_id(server):
    first = createOrReuseUser('sub-2', 'bob@example.com', 'Bob', 'B',
                              emailVerified=True)
    again = createOrReuseUser('sub-2', 'bob@example.com', 'Bob', 'B',
                              emailVerified=True)
    assert first['_id'] == again['_id']
    assert len(again['oidc']) == 1


@pytest.mark.plugin('oidc')
def test_reuses_user_by_oidc_id_without_verified_email(server):
    # Once the identity is bound, the `sub` is what identifies the account, so a
    # provider that stops sending email_verified must not lock the user out.
    first = createOrReuseUser('sub-2b', 'bob2@example.com', 'Bob', 'B',
                              emailVerified=True)
    again = createOrReuseUser('sub-2b', 'bob2@example.com', 'Bob', 'B',
                              emailVerified=False)
    assert first['_id'] == again['_id']


@pytest.mark.plugin('oidc')
def test_links_existing_user_by_email(server):
    existing = User().createUser(
        login='carol', password='password123', firstName='Carol', lastName='C',
        email='carol@example.com')
    linked = createOrReuseUser('sub-3', 'carol@example.com', 'Carol', 'C',
                               emailVerified=True)
    assert linked['_id'] == existing['_id']
    assert any(o['id'] == 'sub-3' for o in linked['oidc'])


@pytest.mark.plugin('oidc')
def test_unverified_email_cannot_claim_existing_account(server):
    """The headline account-takeover guard: an unverified email must not be
    enough to attach a new OIDC identity to somebody else's account."""
    victim = User().createUser(
        login='victim', password='password123', firstName='Vic', lastName='Tim',
        email='victim@example.com')

    with pytest.raises(RestException) as exc:
        createOrReuseUser('attacker-sub', 'victim@example.com', 'At', 'Tacker')
    assert 'verified address' in str(exc.value)

    # Nothing was linked, and the account is untouched.
    reloaded = User().load(victim['_id'], force=True)
    assert not reloaded.get('oidc')


@pytest.mark.plugin('oidc')
def test_unverified_email_cannot_create_account(server):
    with pytest.raises(RestException):
        createOrReuseUser('unverified-sub', 'nobody@example.com', 'No', 'Body')
    assert User().findOne({'email': 'nobody@example.com'}) is None


@pytest.mark.plugin('oidc')
def test_trust_unverified_email_setting_opens_the_gate(server):
    Setting().set(PluginSettings.TRUST_UNVERIFIED_EMAIL, True)
    try:
        user = createOrReuseUser('trusted-sub', 'trusted@example.com', 'Tru', 'St')
        assert user['email'] == 'trusted@example.com'
    finally:
        Setting().set(PluginSettings.TRUST_UNVERIFIED_EMAIL, False)


@pytest.mark.plugin('oidc')
def test_unverified_email_does_not_overwrite_stored_address(server):
    user = createOrReuseUser('sub-mail', 'before@example.com', 'Be', 'Fore',
                             emailVerified=True)
    # Same identity, new address, but the provider no longer vouches for it.
    again = createOrReuseUser('sub-mail', 'after@example.com', 'Be', 'Fore',
                              emailVerified=False)
    assert again['_id'] == user['_id']
    assert again['email'] == 'before@example.com'
    # With the claim, the address does follow the provider.
    updated = createOrReuseUser('sub-mail', 'after@example.com', 'Be', 'Fore',
                                emailVerified=True)
    assert updated['email'] == 'after@example.com'


def test_claim_grants_admin_semantics():
    # Disabled when no claim name is configured.
    assert claimGrantsAdmin({'groups': ['x']}, '', '') is None
    # List claim: membership.
    assert claimGrantsAdmin({'groups': ['a', 'b']}, 'groups', 'b') is True
    assert claimGrantsAdmin({'groups': ['a', 'b']}, 'groups', 'c') is False
    # List claim, blank value: any non-empty list.
    assert claimGrantsAdmin({'groups': ['a']}, 'groups', '') is True
    assert claimGrantsAdmin({'groups': []}, 'groups', '') is False
    # Scalar claim: equality.
    assert claimGrantsAdmin({'role': 'admin'}, 'role', 'admin') is True
    assert claimGrantsAdmin({'role': 'user'}, 'role', 'admin') is False
    # Scalar claim, blank value: truthiness (e.g. boolean is_admin).
    assert claimGrantsAdmin({'is_admin': True}, 'is_admin', '') is True
    assert claimGrantsAdmin({'is_admin': False}, 'is_admin', '') is False
    # Missing claim is not admin.
    assert claimGrantsAdmin({}, 'groups', 'x') is False


def test_claim_lookup_descends_into_nested_claims():
    """Per-client entitlements are nested, not top-level: keycloak puts them
    under resource_access.<client_id>.roles."""
    claims = {'resource_access': {'girder': {'roles': ['access']},
                                  'other-app': {'roles': ['access']}}}
    assert claimGrantsAccess(claims, 'resource_access.girder.roles', 'access') is True
    # The role of a *different* client must not admit anyone here.
    assert claimGrantsAccess(
        claims, 'resource_access.absent-app.roles', 'access') is False
    # A partial path that lands on a dict is not a match.
    assert claimGrantsAccess(claims, 'resource_access.girder', 'access') is False
    # A literal dotted key still wins over the path split.
    assert claimGrantsAccess({'a.b': 'yes'}, 'a.b', 'yes') is True


def test_claim_grants_access_semantics():
    # Opt-in: with no claim configured every authenticated identity is admitted.
    assert claimGrantsAccess({}, '', '') is True
    # List claim: membership.
    assert claimGrantsAccess({'groups': ['/girder-users']}, 'groups',
                             '/girder-users') is True
    assert claimGrantsAccess({'groups': ['/other']}, 'groups',
                             '/girder-users') is False
    # List claim, blank value: any non-empty list.
    assert claimGrantsAccess({'groups': ['x']}, 'groups', '') is True
    assert claimGrantsAccess({'groups': []}, 'groups', '') is False
    # Scalar claim: equality, then truthiness.
    assert claimGrantsAccess({'tier': 'staff'}, 'tier', 'staff') is True
    assert claimGrantsAccess({'tier': 'guest'}, 'tier', 'staff') is False
    assert claimGrantsAccess({'may_login': True}, 'may_login', '') is True
    assert claimGrantsAccess({'may_login': False}, 'may_login', '') is False
    # A configured claim the token does not carry refuses -- this is the whole
    # point of the filter, so it must not fail open.
    assert claimGrantsAccess({}, 'groups', '/girder-users') is False


@pytest.mark.plugin('oidc')
def test_admin_mapping_grants_and_revokes(server, admin):
    # `admin` fixture: a second site admin, so revoking below isn't blocked by
    # the last-admin guard (exercised separately).
    user = createOrReuseUser('sub-adm', 'frank@example.com', 'Frank', 'F',
                             admin=True, emailVerified=True)
    assert user['admin'] is True
    # Next login without the claim (full sync) revokes admin.
    user = createOrReuseUser('sub-adm', 'frank@example.com', 'Frank', 'F',
                             admin=False, emailVerified=True)
    assert user['admin'] is False
    # admin=None (mapping disabled) leaves the flag untouched.
    user['admin'] = True
    User().save(user)
    user = createOrReuseUser('sub-adm', 'frank@example.com', 'Frank', 'F',
                             admin=None, emailVerified=True)
    assert user['admin'] is True


@pytest.mark.plugin('oidc')
def test_last_admin_is_never_demoted(server):
    """A mis-set admin claim must not be able to strip the instance of its last
    administrator, which would leave no way back short of editing mongo."""
    user = createOrReuseUser('sub-last', 'solo@example.com', 'So', 'Lo',
                             admin=True, emailVerified=True)
    assert user['admin'] is True
    assert User().findOne({'admin': True, '_id': {'$ne': user['_id']}}) is None

    kept = createOrReuseUser('sub-last', 'solo@example.com', 'So', 'Lo',
                             admin=False, emailVerified=True)
    assert kept['admin'] is True

    # With another admin around, the revocation goes through.
    User().createUser(
        login='otheradmin', password='password123', firstName='Other',
        lastName='Admin', email='otheradmin@example.com', admin=True)
    demoted = createOrReuseUser('sub-last', 'solo@example.com', 'So', 'Lo',
                                admin=False, emailVerified=True)
    assert demoted['admin'] is False


@pytest.mark.plugin('oidc')
def test_auto_create_disabled_blocks_new_user(server):
    Setting().set(PluginSettings.AUTO_CREATE_USERS, False)
    try:
        with pytest.raises(RestException):
            createOrReuseUser('sub-4', 'dave@example.com', 'Dave', 'D',
                              emailVerified=True)
    finally:
        Setting().set(PluginSettings.AUTO_CREATE_USERS, True)


@pytest.mark.plugin('oidc')
def test_closed_registration_blocks_new_user(server):
    Setting().set(SettingKey.REGISTRATION_POLICY, 'closed')
    try:
        with pytest.raises(RestException):
            createOrReuseUser('sub-5', 'erin@example.com', 'Erin', 'E',
                              emailVerified=True)
        # ...unless the policy is explicitly ignored.
        Setting().set(PluginSettings.IGNORE_REGISTRATION_POLICY, True)
        user = createOrReuseUser('sub-5', 'erin@example.com', 'Erin', 'E',
                                 emailVerified=True)
        assert user['email'] == 'erin@example.com'
    finally:
        Setting().set(SettingKey.REGISTRATION_POLICY, 'open')
        Setting().set(PluginSettings.IGNORE_REGISTRATION_POLICY, False)


# --- Girder's own email verification -----------------------------------------
#
# An OIDC account's address belongs to the identity provider. Girder must not
# mail its "please verify your address" link for one, and must not leave the
# account in a state where `verifyLogin` refuses it. Local accounts keep the
# normal behaviour.

@pytest.fixture
def mailbox(monkeypatch):
    """Capture what girder would have emailed, instead of opening an SMTP
    connection. Patched on the module girder's user model calls through."""
    sent = []
    monkeypatch.setattr(mail_utils, 'sendMail',
                        lambda subject, text, to: sent.append((subject, to)))
    return sent


@pytest.fixture
def emailVerificationRequired():
    Setting().set(SettingKey.EMAIL_VERIFICATION, 'required')
    try:
        yield
    finally:
        Setting().set(SettingKey.EMAIL_VERIFICATION, 'disabled')


@pytest.mark.plugin('oidc')
def test_oidc_creation_sends_no_verification_email(
        server, mailbox, emailVerificationRequired):
    user = createOrReuseUser('sub-mail-1', 'verified@example.com', 'Ver', 'Ified',
                             emailVerified=True)
    assert mailbox == []
    assert user['emailVerified'] is True


@pytest.mark.plugin('oidc')
def test_oidc_user_can_log_in_when_verification_is_required(
        server, mailbox, emailVerificationRequired):
    """The flip side of not sending the mail: the account must not be left in a
    state girder then refuses to log in."""
    user = createOrReuseUser('sub-mail-2', 'loginok@example.com', 'Log', 'Inok',
                             emailVerified=True)
    # Raises AccessException('Email verification required') if we got this wrong.
    User().verifyLogin(user)


@pytest.mark.plugin('oidc')
def test_local_registration_still_sends_verification_email(
        server, mailbox, emailVerificationRequired):
    """The suppression must be scoped to our own provisioning, not global."""
    User().createUser(
        login='localmail', password='password123', firstName='Local',
        lastName='Mail', email='localmail@example.com')
    assert len(mailbox) == 1
    assert 'localmail@example.com' in mailbox[0][1]


@pytest.mark.plugin('oidc')
def test_unverified_email_is_refused_without_creating_or_mailing(
        server, mailbox, emailVerificationRequired):
    """An unverified address gets a clear refusal -- not an account, and not a
    Girder verification mail to an address the provider would not vouch for."""
    with pytest.raises(RestException) as exc:
        createOrReuseUser('sub-mail-3', 'unverified@example.com', 'Un', 'Verified',
                          emailVerified=False)
    assert 'verified address' in str(exc.value)
    assert mailbox == []
    assert User().findOne({'email': 'unverified@example.com'}) is None


@pytest.mark.plugin('oidc')
def test_verification_suppression_is_released_after_provisioning(
        server, mailbox, emailVerificationRequired):
    """The flag is thread-local and scoped by a context manager; a local
    registration right after an OIDC one must still get its mail."""
    createOrReuseUser('sub-mail-4', 'first@example.com', 'Fir', 'St',
                      emailVerified=True)
    assert mailbox == []
    User().createUser(
        login='afterwards', password='password123', firstName='After',
        lastName='Wards', email='afterwards@example.com')
    assert len(mailbox) == 1


@pytest.mark.plugin('oidc')
def test_failed_provisioning_still_releases_the_flag(
        server, mailbox, emailVerificationRequired):
    """Even when createUser raises, the suppression must not leak into the next
    local registration."""
    Setting().set(SettingKey.REGISTRATION_POLICY, 'closed')
    try:
        with pytest.raises(RestException):
            createOrReuseUser('sub-mail-5', 'blocked@example.com', 'Blo', 'Cked',
                              emailVerified=True)
    finally:
        Setting().set(SettingKey.REGISTRATION_POLICY, 'open')

    User().createUser(
        login='stillmailed', password='password123', firstName='Still',
        lastName='Mailed', email='stillmailed@example.com')
    assert len(mailbox) == 1


@pytest.mark.plugin('oidc')
def test_verification_email_suppression_is_installed(server):
    """Pins the interception point. girder only grew the `email.verification`
    event in 5.0.14, so the plugin wraps `_sendVerificationEmail` instead to
    cover `girder>=5`. If that method is ever renamed upstream the wrapper stops
    being applied and the behavioural tests above would start passing for the
    wrong reason on a version that still mails."""
    assert getattr(User._sendVerificationEmail, _SUPPRESSION_MARKER, False)


@pytest.mark.plugin('oidc')
def test_verification_suppression_install_is_idempotent(server):
    """Plugin load runs more than once under pytest; wrappers must not stack."""
    before = User._sendVerificationEmail
    installVerificationEmailSuppression()
    assert User._sendVerificationEmail is before
