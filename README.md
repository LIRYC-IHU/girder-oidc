# Girder OIDC

A Girder 5 plugin that lets users authenticate through any OpenID Connect
provider (Keycloak, Dex, Auth0, Google, ...). Login uses the browser
authorization-code flow with PKCE and nonce, and ID tokens are fully validated
(signature, issuer, audience, expiry, nonce). This repo also ships a
self-contained development stack for building and debugging the plugin locally.

## Features

- **Authorization-code flow** with PKCE (S256) and a per-login nonce; ID tokens
  are validated against the provider JWKS (signature, `iss`, `aud`, `exp`,
  `nonce`) and same-origin redirects are enforced.
- **Automatic provisioning** of passwordless Girder accounts for new
  identities, with graceful fallbacks when the provider omits name claims
  (`given_name`/`family_name` → `name` → username → email local-part).
- **Externally-managed accounts**: OIDC-linked users (and admins acting on
  them) cannot change the profile, password, or two-factor settings owned by
  the identity provider. Enforced server-side, with the controls hidden in the
  web client.
- **Admin mapping from token claims**: optionally derive Girder site-admin from
  an ID-token claim, kept in sync (granted *and* revoked) on every login.
- **Admin configuration UI** with a "Test connection" button that probes the
  provider's discovery document and JWKS before you save.

## Installation

Install the plugin into the environment running Girder, then restart Girder:

```bash
pip install girder-oidc
```

Or from a checkout of this repository:

```bash
pip install ./girder-oidc
```

The plugin registers itself through the `girder.plugin` entry point; no manual
enabling step is required beyond turning OIDC on in the configuration page
(below).

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
| **Admin claim** / **Admin claim value** | Map Girder site-admin from a token claim — see below. |

The defaults for Client ID/secret and the provider URLs can be seeded from the
environment (`OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_PUBLIC_URL`,
`OIDC_INTERNAL_URL`), which is what the dev stack uses.

### Admin mapping from claims

If **Admin claim** is set, the Girder site-admin flag is synchronised to that
claim on every OIDC login (granted when it matches, **revoked** when it does
not). This only ever affects OIDC-linked accounts — local accounts, including
the bootstrap admin, are never touched. Leave **Admin claim** blank to disable
the feature and manage admin status manually.

Matching depends on the shape of the claim and the optional **Admin claim
value**:

| Claim shape | Admin claim value | Matches when |
|-------------|-------------------|--------------|
| List (e.g. `groups`, `roles`) | set | the value is a member of the list |
| List | blank | the list is non-empty |
| Scalar (e.g. `role`) | set | the value equals the claim |
| Scalar / boolean (e.g. `is_admin`) | blank | the claim is truthy |

### Account lockdown

For OIDC-linked accounts the identity provider owns the profile, password, and
two-factor settings. The plugin rejects edits to first/last name, email,
password, and OTP at the REST layer (HTTP 403) for both the account owner and
site admins, and hides the corresponding controls in the account page.

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

## Funding
This project was financed by the french Agence Nationale de la Recherche (ANR) - ANR-23-RHUS-0015
