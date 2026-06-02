# Girder OIDC

A Girder 5 plugin that lets users authenticate through any OpenID Connect
provider (Keycloak, Dex, Auth0, Google, ...). Login uses the browser
authorization-code flow with PKCE and nonce, and ID tokens are fully validated
(signature, issuer, audience, expiry, nonce). This repo also ships a
self-contained development stack for building and debugging the plugin locally.

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
