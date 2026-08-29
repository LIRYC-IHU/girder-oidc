# girder-oidc

Authenticate [Girder 5](https://girder.readthedocs.io/) users through any OpenID
Connect provider — Keycloak, Dex, Auth0, Entra ID, Google, ...

Login uses the browser authorization-code flow with PKCE and a per-login nonce,
and ID tokens are validated against the provider's JWKS (signature restricted to
asymmetric algorithms, `iss`, `aud`/`azp`, `sub`, `exp`, `nonce`).

## Installation

```bash
pip install girder-oidc
```

Install it into the environment that runs Girder, then restart Girder. The
plugin registers itself through the `girder.plugin` entry point and its wheel
ships the pre-built web client as package data, so no `girder build` step is
needed.

Requires `girder >= 5` and Python 3.10+.

## Configuration

Everything is configured from the Girder Admin Console → **Plugins** → **OIDC
Login**: client credentials, the provider URL (browser-facing, and optionally a
separate server-to-server one), scopes, and the login button label. A **Test
connection** button probes the provider's discovery document and JWKS before you
save. Client ID/secret and provider URLs can be seeded from `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET`, `OIDC_PUBLIC_URL` and `OIDC_INTERNAL_URL`.

Register `https://<your-girder-host>/api/v1/oidc/callback` as a redirect URI
with your provider (the configuration page shows the exact value to use).

Beyond signing users in, the plugin can map what the provider says about an
identity onto Girder:

| Feature | What it does |
|---------|--------------|
| **Automatic provisioning** | Creates a passwordless Girder account the first time an identity signs in, matching an existing account by the provider's `sub` and — only when the token asserts `email_verified` — by email address. |
| **Access restricted by claim** | Refuses login outright unless the ID token carries a configured claim, so one provider realm can serve several applications without every user of the realm getting an account here. |
| **Admin mapping** | Derives the Girder site-admin flag from a claim, granted *and* revoked at each login (never demoting the last remaining admin). |
| **Group synchronisation** | Mirrors the provider's groups into Girder groups, so provider-side group membership can grant access to collections and folders through Girder's ordinary access control lists. |
| **Account lockdown** | Profile, password, 2FA and the "forgot my password" flow are refused server-side for OIDC-linked accounts: the provider owns them. |

Claim names may use dots to descend into nested claims, e.g.
`resource_access.girder.roles` for a Keycloak per-client role.

## Documentation

Full documentation — the reasoning behind the security choices, the group
synchronisation rules, Keycloak mapper examples, and a self-contained
development stack — lives in the repository:
<https://github.com/LIRYC-IHU/girder-oidc>.

## License

Apache 2.0.

## Funding

This project was financed by the french Agence Nationale de la Recherche (ANR) —
ANR-23-RHUS-0015.
