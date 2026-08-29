# Girder OIDC

A Girder 5 plugin that lets users authenticate through any OpenID Connect
provider (Keycloak, Dex, Auth0, Google, ...). Login uses the browser
authorization-code flow with PKCE and nonce, and ID tokens are fully validated
(signature, issuer, audience, expiry, nonce). This repo also ships a
self-contained development stack for building and debugging the plugin locally.

## Features

- **Authorization-code flow** with PKCE (S256) and a per-login nonce; ID tokens
  are validated against the provider JWKS (signature restricted to asymmetric
  algorithms, `iss`, `aud`/`azp`, `sub`, `exp`, `nonce`) and same-origin
  redirects are enforced.
- **Login bound to the browser that started it**: the opaque `state` is paired
  with an httponly cookie, so a login cannot be completed in a browser other
  than the one that began it (login CSRF / session fixation).
- **Session token never in a URL**: the callback hands the web client a
  single-use, 60-second code, which the client redeems for the token.
- **Automatic provisioning** of passwordless Girder accounts for new
  identities, with graceful fallbacks when the provider omits name claims
  (`given_name`/`family_name` → `name` → username → email local-part).
- **Externally-managed accounts**: OIDC-linked users (and admins acting on
  them) cannot change the profile, password, or two-factor settings owned by
  the identity provider. Enforced server-side, with the controls hidden in the
  web client.
- **Access restricted by claim**: optionally require an ID-token claim before an
  identity may sign in at all, so one identity provider realm can serve several
  applications without every user of the realm getting an account here.
- **Admin mapping from token claims**: optionally derive Girder site-admin from
  an ID-token claim, kept in sync (granted *and* revoked) on every login.
- **Groups mirrored from the provider**: optionally turn a groups/roles claim
  into Girder groups, so provider-side membership grants access to collections
  through Girder's ordinary access control lists — with no per-user bookkeeping
  on the collection.
- **Admin configuration UI** with a "Test connection" button that probes the
  provider's discovery document and JWKS before you save.

## Installation

Install the plugin from PyPI into the environment running Girder, then restart
Girder:

```bash
pip install girder-oidc
```

Pin it like any other dependency when you deploy (`pip install
girder-oidc==0.5.0`); the published wheels are attached to each
[GitHub release](https://github.com/LIRYC-IHU/girder-oidc/releases) as well.

The wheel ships the pre-built web client as package data, which Girder 5 serves
straight from the installed package — there is no separate `girder build` step.
In a container, that makes the whole installation one line:

```dockerfile
FROM girder/girder:v5.0.9-py3
RUN pip install --no-cache-dir girder-oidc==0.5.0
```

To install from a checkout of this repository instead, build the web client
first — a source install has no bundle in it:

```bash
(cd girder-oidc/girder_oidc/web_client && npm ci && npm run build)
pip install ./girder-oidc
```

The plugin registers itself through the `girder.plugin` entry point; no manual
enabling step is required beyond turning OIDC on in the configuration page
(below). It requires `girder >= 5` and Python 3.10+.

## Configuration

Open the Girder Admin Console → **Plugins** → **OIDC Login**. The settings are:

| Setting | Description |
|---------|-------------|
| **Enable OIDC login** | Master switch. When on, the login button appears and the classic username/password form is collapsed behind a toggle. |
| **Client ID** / **Client secret** | OAuth2 credentials issued by your provider. The secret is write-only — leave blank to keep the current value. |
| **Provider URL (issuer)** | Browser-facing base URL of the provider. This is the issuer the ID token's `iss` is validated against. |
| **Internal provider URL** | Optional server-to-server base URL (discovery / token / JWKS). Leave blank when it's the same as the issuer; useful behind proxies or in container networks. |
| **Scopes** | Space-separated OAuth2 scopes (default `openid profile email`). |
| **Login button label** | Text shown on the OIDC login button. |
| **Automatically create Girder accounts** | Provision a new passwordless account the first time an identity logs in. |
| **Ignore closed registration policy** | Allow OIDC account creation even when Girder registration is closed. |
| **Trust the email claim without `email_verified`** | Off by default. See [Account linking](#account-linking-and-email_verified) — leaving this off is what stops an unverified address from claiming an account. |
| **Required claim** / **Required claim value** | Restrict who may sign in at all — see [Restricting access](#restricting-access-by-claim). Blank admits every identity the provider authenticates. |
| **Admin claim** / **Admin claim value** | Map Girder site-admin from a token claim — see below. |
| **Groups claim** | Claim whose values are mirrored into Girder groups — see [Groups from the provider](#groups-from-the-provider). Blank disables the mirroring. |
| **Mirrored group name prefix** | Put in front of a claim value when the Girder group is created, e.g. `IdP: `. Keeps mirrored groups in a name space of their own. |
| **The provider owns membership of mirrored groups** | On by default: a user who no longer carries a group in their token is removed from it at the next login. Off means the sync only ever adds. |

The defaults for Client ID/secret and the provider URLs can be seeded from the
environment (`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_PUBLIC_URL`,
`OIDC_INTERNAL_URL`), which is what the dev stack uses.

### Account linking and `email_verified`

An identity is matched to a Girder account first by the provider's stable `sub`,
and — the first time that identity is seen — by email address. That second step
is only as trustworthy as the address, so the plugin acts on the email claim
**only when the ID token asserts `email_verified`**. Without it, the login is
refused rather than matched.

This matters because a provider that lets a user choose their own address
(self-service sign-up, a second connector, a writable LDAP `mail` attribute)
would otherwise let anyone register `someone-else@your-lab.example` and take over
the matching Girder account — including a site admin's. The same rule governs
creating an account and updating a stored address.

**Trust the email claim without `email_verified`** switches the check off. Only
enable it for a provider that verifies every address it emits but omits the
claim; a provider where users pick their own address must not have it enabled.

#### Girder's own email verification

The two checks do not stack: address verification belongs to the provider, so
Girder's copy of it is bypassed for these accounts.

- An OIDC-provisioned account is created with `emailVerified` already set, and
  Girder's "please verify your address" email is **not** sent. Without this, an
  instance with **Email verification** set to `required` would mail every SSO
  user a confirmation link and then refuse their login until they clicked it —
  for an address the provider had already verified.

  Girder 5.0.14 added an `email.verification` event for exactly this opt-out,
  but the plugin supports `girder>=5` and 5.0.9 (the version the project's own
  images pin) has no hook at all. The plugin therefore wraps
  `User._sendVerificationEmail`, which is the one interception point common to
  both; the wrapper only stands down for the duration of the plugin's own
  `createUser` call, on that thread. `test_user.py` pins this so an upstream
  rename fails loudly instead of silently resuming the mails.
- An unverified address is refused at login with a message explaining why. No
  account is created and no mail is sent: mailing a confirmation link to an
  address the provider would not vouch for is exactly the wrong move, since that
  is the address an attacker would have supplied.
- Local (non-OIDC) registrations are untouched and still receive Girder's
  verification email as usual.

### Restricting access by claim

By default any identity the provider is willing to authenticate gets in. That is
usually not what you want when the provider's realm is shared with other
applications: without a filter, every user of the realm who clicks the login
button ends up with a Girder account (see **Automatically create Girder
accounts**).

Set **Required claim** to gate this. When it is set, a login is refused unless
the ID token carries a matching claim — before an account is created, before a
session is issued, and before anything is derived from the token. The refusal is
logged with the identity's `sub`, and the user lands back on the page they
started from with a dismissible message telling them to ask an administrator.

That last part is general: every way the callback can fail after the login is
established as genuine — a refusal here, an unverified address, an error the
provider reports, a failed token exchange — is handed to the web client as a
`girderOidcError` query param and shown as an alert. The callback is a top-level
browser navigation, so the alternative is a raw JSON error document in the
address bar. Failures *before* that point (an unknown or expired `state`, a
login completed in a different browser) still answer a plain HTTP error, since
at that stage the request is not known to belong to a real login.

The claim name may use dots to descend into nested claims, which is what
per-client entitlements normally look like. With Keycloak, giving the Girder
client a client role `access` and enabling *Add to ID token* on the built-in
*client roles* mapper produces:

```json
"resource_access": { "girder": { "roles": ["access"] } }
```

so **Required claim** = `resource_access.girder.roles` and **Required claim
value** = `access` admits exactly the users holding that role, and no one else.
A flat `groups` claim works the same way (**Required claim value** =
`/girder-users`). Matching follows the same rules as the admin claim below.

This is a refusal *after* authentication: the user signs in at the provider and
is then turned away by Girder. To stop them at the provider instead — no
password prompt, no token issued — the check has to live there as well, e.g. a
Keycloak authentication flow that denies access to users without the role. The
two are complementary rather than redundant: the provider-side check gives a
cleaner refusal, while this one still applies when a user is removed from the
group, and travels with the plugin to providers you do not administer.

### Admin mapping from claims

If **Admin claim** is set, the Girder site-admin flag is synchronised to that
claim on every OIDC login (granted when it matches, **revoked** when it does
not). Only accounts that go through an OIDC login are affected; purely local
accounts are never touched.

Two things to keep in mind:

- The **last remaining site admin is never demoted**, even when the claim says
  so. Otherwise a mis-set claim could leave the instance with no administrator
  and no way back short of editing MongoDB. The refusal is logged.
- Point **Admin claim** at something users cannot set themselves. A `groups` or
  `roles` claim is only safe if group membership is administered centrally; on a
  provider where users create their own groups, this is a self-service route to
  Girder site-admin.

Leave **Admin claim** blank to disable the feature and manage admin status
manually.

Matching depends on the shape of the claim and the optional **Admin claim
value**:

| Claim shape | Admin claim value | Matches when |
|-------------|-------------------|--------------|
| List (e.g. `groups`, `roles`) | set | the value is a member of the list |
| List | blank | the list is non-empty |
| Scalar (e.g. `role`) | set | the value equals the claim |
| Scalar / boolean (e.g. `is_admin`) | blank | the claim is truthy |

### Groups from the provider

Girder already knows how to give a set of people access to something: groups are
first-class entries in every ACL, and a collection shared with a group is
readable by its members and shows up in their listings. What was missing was the
link between "group at the provider" and "group in Girder" — that is all this
feature adds. The permission model itself is untouched.

Set **Groups claim** (typically `groups`, or `resource_access.<client>.roles` for
Keycloak client roles) and, at every login, each value of that claim gets a
Girder group:

- a group is created the first time a value is seen, private, and stamped with a
  marker recording the claim value it mirrors;
- the user is added to the groups their token carries, and — unless you turn
  **The provider owns membership of mirrored groups** off — removed from the
  mirrored ones it no longer carries;
- the marker, not the name, is what ties a group to the provider, so you can
  rename a mirrored group in Girder without breaking the link.

Granting access is then the ordinary Girder gesture, done once: **collection →
Access control → add the group → pick a level**, ticking *include subfolders* to
push it down an existing tree. Folders created afterwards inherit their parent's
ACL, and nothing has to be written per user.

Keycloak emits group *paths* (`/liryc/recherche`); the leading slash is dropped
and the rest kept, since that is what makes the value unique. To get the claim at
all, add a *Group Membership* mapper (or *Client Roles* for roles) to the Girder
client and tick **Add to ID token**.

Three behaviours are worth knowing before you turn this on:

- **Groups you create by hand are never touched.** Only groups carrying the
  plugin's marker are added to or removed from. If a claim value collides with
  the name of a group that is not one of ours, the value is *ignored* rather than
  taken over, and the refusal is logged — an existing "Chercheurs" group must not
  silently start taking its members from the provider. Set a **Mirrored group
  name prefix** to keep the two name spaces apart.
- **A missing claim revokes nothing.** A token that carries no groups claim at
  all is treated as "no information" (and logged as a warning), not as "this user
  is in no group" — otherwise switching a mapper off at the provider would strip
  every membership on the instance, one login at a time. A claim that is present
  and empty *does* revoke.
- **Membership refreshes at login, not continuously.** Someone removed from a
  group at the provider keeps their Girder access until their next sign-in. If
  that window matters, shorten Girder's session lifetime (Admin console →
  Server configuration → **Cookie lifetime**) so logins happen more often.

### Account lockdown

For OIDC-linked accounts the identity provider owns the profile, password, and
two-factor settings. The plugin rejects edits to first/last name, email,
password, and OTP at the REST layer (HTTP 403) for both the account owner and
site admins, and hides the corresponding controls in the account page.

Girder's "forgot my password" flow is blocked for these accounts too. That flow
issues a full session token before any password is set, so leaving it open would
be a way into an OIDC account that never passes through the provider — and so
skips whatever MFA or conditional access the provider enforces.

The lockdown applies only to OIDC-linked accounts: purely local users keep full
self-service over their profile, password, and 2FA. That is worth stating
explicitly because it is easy to break — Girder requires every handler bound to
a `rest.*.before` event to declare an access level, and silently escalates the
whole route to site-admin-only when one does not. The guards in
`account_guard.py` are decorated for that reason, and `plugin_tests/
test_account_guard.py` pins the behaviour with a non-admin user.

### Transport

The browser-facing **Provider URL** must be `https` (plain `http` is accepted
only for `localhost`, for the dev stack): it carries the authorization redirect
and is the issuer the ID token is checked against. Endpoints advertised by the
provider's discovery document are refused if they downgrade to plaintext, since
the token request carries the client secret.

## Development environment

The dev stack (`docker-compose.dev.yml`) runs over plain HTTP — no TLS, no
certificates — and uses [Dex](https://dexidp.io/) as a lightweight OIDC provider:

| Service | URL | Notes |
|---------|-----|-------|
| **Girder** | http://localhost:8080 | Plugin bind-mounted, editable install |
| **Dex** | http://localhost:5556/dex | OIDC provider; static test user |
| **web** | — | Vite `build --watch` of the web client |
| **MongoDB** | internal only | Data persistence |

Dex is reached at **two** URLs: `http://dex:5556/dex` from inside the Girder
container (server-to-server) and `http://localhost:5556/dex` from the host
browser (this is also the token `issuer`). The plugin rewrites the public origin
to the internal one for its own server-side calls (discovery, token, JWKS).

### Quick start

```bash
make up            # build the shared image, start girder + dex + web + mongo
make logs          # tail all logs (or: make logs-girder / logs-dex / logs-web)
```

Then:

1. **Create the Girder admin account** at http://localhost:8080 (first visit
   becomes the admin).
2. **Enable OIDC** in the Girder Admin Panel → Plugins → "OIDC Login". The client
   ID/secret and provider URLs are pre-filled from the compose environment
   (`OIDC_CLIENT_ID=girder`, `OIDC_CLIENT_SECRET=girder-dev-secret`,
   public `http://localhost:5556/dex`, internal `http://dex:5556/dex`), so you
   only need to tick **Enable** and save.
3. **Log in with OIDC** using the pre-provisioned Dex test user:
   - Email: `testuser@example.com`
   - Password: `testpass123`

The OAuth client and test user are defined in `dex/config.yaml`.

> The base image `girder/girder:v5.0.9-py3` is published for `linux/amd64` only.
> On Apple Silicon `docker compose build` mis-resolves its single-arch manifest,
> so `make` builds the shared image with `docker build --platform linux/amd64`
> and the compose services reference it by name.

### Dev loop

| Command | What it does |
|---------|--------------|
| `make up` | Build + start the stack |
| `make down` | Stop the stack (keeps volumes) |
| `make logs` / `make logs-girder` / `make logs-dex` / `make logs-web` | Tail logs |
| `make shell` | Shell into the Girder container |
| `make test` | Run the plugin test suite (pytest-girder) in a container |
| `make clean` | Stop the stack **and delete volumes** (wipes data) |

The web client is rebuilt automatically: the `web` service runs Vite in
`build --watch` mode, so editing anything under `web_client/` regenerates
`web_client/dist/` — just refresh the browser. Python edits under
`girder-oidc/girder_oidc/` are picked up by Girder's dev autoreloader (or
`docker compose -f docker-compose.dev.yml restart girder`); the package is
installed editable.

To change the OIDC fixtures (client, test user), edit `dex/config.yaml` then
`docker compose -f docker-compose.dev.yml restart dex`.

### Tests without the stack

`make test` runs the suite in the container, against the girder version the dev
image pins. To run it directly instead — which is also what CI does, against the
newest girder 5.x — point pytest at any running mongod:

```bash
pip install "girder>=5" "authlib>=1.3,<2" pytest pytest-girder
pip install -e ./girder-oidc
(cd girder-oidc && pytest -q plugin_tests --mongo-uri mongodb://localhost:27017)
```

`pytest --mock-db` is not an option: mongomock does not implement the tz-aware
codec options girder 5 uses. Running both this and `make test` is worth the
minute it costs — the two exercise different girder versions, and APIs the plugin
touches (the `email.verification` event, `girder.logger`) differ between them.

## Releases and packaging

Two GitHub Actions workflows drive this:

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `.github/workflows/ci.yml` | push to `main`, pull requests | Runs the plugin test suite against a real MongoDB on the floor and ceiling of the supported Python range, and builds the wheel + sdist (web client included) as a smoke test. |
| `.github/workflows/release.yml` | a `v*` tag (or manual dispatch) | Rebuilds the distributions, refuses to continue if the tag disagrees with the version in `pyproject.toml`, creates the GitHub release with generated notes, and attaches the wheel and sdist. |

Cutting a release is therefore:

```bash
# bump `version` in girder-oidc/pyproject.toml first, then:
git tag -a v0.5.0 -m 'v0.5.0'
git push origin v0.5.0
```

Both build jobs assert that the wheel actually contains
`girder_oidc/web_client/dist/`: a wheel without it installs cleanly and then
fails when Girder loads the plugin, which is not a failure worth discovering in
production.

Publishing to PyPI is opt-in and off by default — a release produces GitHub
assets, and `twine upload` stays manual. To let the workflow do it, configure
[trusted publishing](https://docs.pypi.org/trusted-publishers/) for this
repository on PyPI (workflow `release.yml`, environment `pypi`) and set the
repository variable `PUBLISH_TO_PYPI` to `true`. No API token is stored either
way.

## Funding
This project was financed by the french Agence Nationale de la Recherche (ANR) - ANR-23-RHUS-0015
