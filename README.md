# CloakTail

The self-service developer portal for Keycloak SAML.


A self-service portal where developers register, create SAML clients in Keycloak, and test their Keycloak connection. Built with Express, htmx and [Basecoat](https://basecoatui.com) (shadcn/ui styling without React).

## What it does

- **Public landing page** (`/` when signed out, `/guide` when signed in): features, how it works, how to register, how to test, and common problems.
- **Disclaimer** at `/disclaimer`, summarised in every page footer. Developers must accept it to sign up.
- **Certificate generator** at `/tools/certificate`: creates an RSA key pair (2048/3072/4096 bit) and a self-signed PEM certificate for signed requests or encrypted assertions. Keys are generated on the server, shown once, sent with `Cache-Control: no-store` and never stored. It is limited to 10 per developer per 10 minutes. The page also shows the equivalent OpenSSL command for production keys.

- **Developer sign-up:** the portal's own sign-up form creates the account in the portal realm (`ep`). New accounts get the `developer` role.
- **Sign-in:** through Keycloak with SAML 2.0.
- **Applications:** a developer registers a **SAML** service provider (SP), by filling a form or importing SP metadata XML, or an **OpenID Connect** client (confidential or public). The portal creates the client in a separate **sandbox realm** (`ep-dev`). Developers see and change only their own applications.
- **Connection details:** each SAML application page shows:
  - The IdP metadata URL, entity ID, SSO/SLO URLs and signing certificate
  - The IdP-initiated login link
  - A ready-to-copy passport-saml config

  Each OIDC application page shows:
  - The issuer, discovery document and every endpoint (authorization, token, userinfo, JWKS, end session)
  - The client ID and, for confidential clients, the client secret (only to those who may edit the app), with **Regenerate secret**
  - A ready-to-copy openid-client config
- **Test connection:** the portal acts as the developer's app for one login, and the developer signs in as a sandbox test user.
  - **SAML:** it sends an AuthnRequest with their entity ID and the portal's own ACS (`/saml/test/acs`), then shows pass/fail checks for status, issuer, destination, audience, signatures and expected attributes, the Name ID and session index, every attribute received, and the raw XML.
  - **OIDC:** it runs the authorization code flow with PKCE as their client, with the portal's own redirect URI (`/oidc/test/callback`), redeems the code (with the client secret for confidential clients) and calls userinfo. It shows pass/fail checks for the code exchange, the ID token signature (against the realm JWKS), issuer, audience, `azp`, expiry, nonce and `at_hash`, plus the decoded ID token, access token and userinfo claims. Only the decoded claims are stored, never the tokens.

  The portal adds its own test ACS / redirect URI, on every domain of the profile, to each client, and hides it from the form. The last 10 runs are kept per application.
- **Test users:** each developer manages a few accounts in the sandbox realm to sign in with during tests. The same page lists **Migrated users**: everyone their applications moved into the sandbox realm through user migration (username, the application's user id, application, when, and whether a person linked the account by hand), newest first, with a filter. **Delete** removes a migrated user from Keycloak and from CloakTail's record, so the application can migrate them again (it must clear its own migrated flag for them too). A user someone linked by hand to an existing account can only be **unlinked**: the record goes, the account stays, since it may be someone else's.
- **Portal administration:** user management (in `ep`) and portal roles and permissions, as before.
- **User migration** for registered applications: an application sends its existing users to `/migrate` once, right after they sign in the old way. On one page they choose a new password and add an authenticator app, then go straight back to the application, signed in. From their next sign-in they use Keycloak (see [User migration](#user-migration)).
- **Developer REST API** at `/api/v1`: everything above that a developer does (applications, secrets, user migration, test logins, test users, certificates) for scripts and AI coding agents, with API credentials from **API credentials** (`/api-credentials`). See [Developer REST API](#developer-rest-api).
- **Admin console** at `/admin`: configures the Keycloak connection at runtime. Administrators are local accounts stored in the portal database, not Keycloak users, so the console still works when the Keycloak settings are wrong.

Why a separate sandbox realm: a developer controls their client's ACS URL, so a client in `ep` could receive the identity of real `ep` users. The sandbox realm has only test users, and the portal's service account there can't touch production clients.

## Run

```bash
npm install
cp .env.example .env       # fill in SESSION_SECRET (Keycloak is configured in /admin, not here)
npm run build:css          # or: npm run watch:css
npm run dev                # http://localhost:3000
```

Put your own Keycloak username in `ADMIN_USERS` so you get the `admin` portal role.

On first start there is no administrator and no Keycloak connection:

1. Open `/admin`. It leads to the setup page, which asks for the **setup token** printed in the server log (`docker logs <container>` in Docker). Or set `ADMIN_BOOTSTRAP_USERNAME` and `ADMIN_BOOTSTRAP_PASSWORD` (see below).
2. In **Keycloak profiles**, create a profile (or import one), run the checks, and give it its domains (for example `BASE_URL`).
3. On the profile's page, open **SAML signing certificate**, generate the profile's certificate and import it into the portal SAML client of that profile's Keycloak.

Until a profile serves the domain, every page except `/admin` answers 421; until the profile has a signing certificate, Keycloak sign-in shows "not set up yet".

## User migration

Lets a developer move the users of their **registered application** into Keycloak, without a bulk import and without their old passwords. Each application sets it up on its own page: **Applications → (app) → User migration** (`/apps/<id>/migration`). Its owner, or an administrator with `apps.manage_all`, configures it. The page also holds this guide, with the application's values and Node.js / Python code filled in, and the history of requests, including rejected ones and why.

Migrated users are created in the profile's sandbox realm, where the application's client lives, by the sandbox service account. No email is sent, and emails are not marked verified.

**What a user sees:**

1. They sign in to the application with their old password, as today.
2. The application sends them to CloakTail. On one page they see their profile, choose a new password and, with **Require OTP**, scan a QR code with an authenticator app and enter a code from it. CloakTail creates their Keycloak account with both the password and the authenticator.
3. They go straight back to the application, already signed in: they proved who they are moments ago, so there is no second sign-in.
4. From their next sign-in, the application sends them to Keycloak: the new password, then a code from the app. Keycloak has nothing left to set up.

### Developer guide: redirecting a user

**0. Set it up.** On the application's User migration page:
- Enter the **return URLs**, where users come back to.
- Choose how your requests are signed:
  - **Migration secret (HS256):** the default.
  - **Public key (PEM):** RS256, PS256, ES256 or EdDSA.
  - **JWKS URL:** with `kid`.
- Leave **Require OTP** on so new users add an authenticator app while they choose their new password.
- Copy the **migration secret** into your app's server configuration (e.g. `CLOAKTAIL_MIGRATION_SECRET`). It always signs the results; with the default method it also signs your requests.

**1. Check the old password as you do today.** When it's right and the user isn't migrated yet (keep a flag such as `migrated_at`), don't start a session. Keep a short pre-login session with the user's id and `state` (lasting at least 30 minutes, the time CloakTail gives the user), and send them to CloakTail. Users you've already migrated go straight to Keycloak (step 4).

**2. Redirect to CloakTail with a signed request**: `https://<portal domain>/migrate/start?request=<JWT>`. Or auto-submit a form `POST` with a `request` field, which keeps the token out of logs and history.

| Claim | Value |
|---|---|
| `iss` | The application's client ID (OIDC client ID or SAML entity ID) |
| `aud` | `https://<portal domain>/migrate` |
| `iat`, `exp` | Now, and at most 10 minutes later |
| `jti` | A new random id for every request. Each is accepted once. |
| `sub` | The user's id in your application. Kept in Keycloak as the `legacy_id` attribute. |
| `preferred_username` | Their Keycloak username (stored lowercase) |
| `email`, `given_name`, `family_name` | Optional. Shown to the user read-only and copied as they are. |
| `return_url` | One of your return URLs |
| `state` | A random value kept in the user's session; it comes back in the result |

The user sees their profile, chooses a new password and, with **Require OTP**, adds an authenticator app; they can also cancel. A request that fails any check never redirects. The user sees "This link can't be used", and the reason appears in the application's request history.

**3. Handle the result** at `return_url?result=<JWT>`. Check its HS256 signature with the migration secret, that `aud` is your client ID, that `exp` hasn't passed (results are valid for 5 minutes), and that `state` matches the session. Then act on `status`:

| `status` | Meaning | Your app |
|---|---|---|
| `created` | The Keycloak account exists with the new password | Mark the user migrated and let them in at once: they already signed in with their old password |
| `already_migrated` | You migrated this user before; no password was asked | Mark the user migrated, then step 4 |
| `conflict` | A different Keycloak account has this username or email | Tell the user; someone must sort it out |
| `cancelled`, `expired`, `error` | No account was created | Let them in the old way this time; ask again next time |

The result also carries `sub`, `preferred_username`, `keycloak_id` and `request_jti`.

After `created`, turn the pre-login session into the user's session, as a successful old-password sign-in would. An application that needs Keycloak tokens straight away may start a Keycloak sign-in instead.

**4. Sign migrated users in with Keycloak** from their next sign-in (and after `already_migrated`), through the application's usual OIDC or SAML sign-in. With OIDC, pass `login_hint=<preferred_username>`; with SAML, put the username in the AuthnRequest's Subject NameID. The old password no longer lets them in. With **Require OTP**, users add their authenticator app on CloakTail's migration page, and Keycloak asks for a code from it.

### For coding agents

`GET /migrate/spec.md` is the whole protocol written for a coding agent that implements it in an application: rules (MUST/SHOULD), JSON schemas of the request and result, stable error codes with fixes, and acceptance tests. It is the same for every application and is linked from `/llms.txt`. The migration page has a ready-made prompt pointing to it.

Three endpoints let the agent test its work without a browser. All take `{"request": "<JWT>"}` and only answer requests signed by a registered application with user migration set up (also while it is turned off). They create no users and don't use up the `jti`:

- `POST /migrate/check` validates the request as `/migrate/start` would, returning `{ ok, error: { code, message }, app }`. `app` is the application's own settings (return URLs, signing method, OTP), shown once the signature checks out. Unknown client IDs and bad signatures both get `invalid_request`, so client IDs can't be probed.
- `POST /migrate/simulate` with a `status` returns a result for that status, signed with the migration secret and marked `simulated: true`, to test the return URL handler.
- `POST /migrate/status` says whether CloakTail already migrated the request's user, with a signed `already_migrated` result when it did, so an application can recover a result the browser never brought back.

Rejected requests in the history now start with the same error code (`aud_mismatch: …`).

### Sandbox realm setup (administrators)

- **Realm settings → General → Unmanaged attributes:** set *Admin can edit* or *Enabled*, or declare `legacy_id`, `migrated_from` and `migrated_at` in **Realm settings → User profile**. Otherwise Keycloak drops them, and a returning user gets `conflict` instead of `already_migrated`. The profile's sandbox **Check connection** tests this, and developers see a warning on their migration page.
- **OTP:** with **Require OTP**, users add their authenticator app on `/migrate` and are created with the OTP credential (HmacSHA1, 6 digits, 30 seconds, stored on the credential, so the realm's OTP policy doesn't change it). The page checks the code with `POST /migrate/otp` before submitting, so a mistyped code doesn't clear the password fields; the server checks it again on submit. The secret stays in the user's CloakTail session (PostgreSQL) until the account is created. CloakTail removes *Configure OTP* from the new user when the realm adds it as a default action, so Keycloak doesn't ask for a second authenticator. The realm's browser flow must ask for OTP when a user has one (the default *Conditional OTP*).
- **Realm settings → Login → Email as username:** keep it **Off**. When it's on, Keycloak replaces `preferred_username` with the email, so users must sign in with their email and the application's `login_hint` doesn't match.
- **Realm settings → User profile:** if first and last name are required, users whose application sent no `given_name` or `family_name` are asked for them at their first Keycloak sign-in.
- The realm's password policy applies; its messages are shown on the password field.

Deleting an application deletes its migration setup and history; migrated users stay in Keycloak.

**Migration record.** CloakTail keeps its own record of which Keycloak user each application user (`sub`) became (`app_migrated_users`, filled in from the request history on upgrade). It decides `already_migrated`, so a returning user is recognised even when the realm drops the migration attributes or the username changed; the attributes are only a copy. An application that lost a result (the browser never came back) asks `POST /migrate/status` with a signed request and gets a signed `already_migrated` result. A `conflict` is resolved by linking the existing Keycloak account to the `sub` (`PUT /api/v1/apps/{id}/migration/users/{sub}`). Migration warnings are objects with a `code`, `who_can_fix`, `impact` and `ignorable_if`; a JWKS URL is fetched and checked when settings are saved.

## Developer REST API

Everything a developer does on the application, test user and certificate pages, as JSON over HTTP at `/api/v1`. The admin console and portal user/role management aren't part of it.

**Credentials.** On **API credentials** (`/api-credentials`, for users with `apps.own`), a developer creates a credential: a client ID (`ctc_…`) and a secret (`cts_…`, shown once, stored as a SHA-256 hash), with scopes and an expiry. At most 10 per developer. A credential acts as its developer on the domains of the Keycloak profile it was made on. Every call checks the developer's *current* permissions, so taking away their role, or revoking the credential, stops it at once. Deleting the developer deletes their credentials.

| Scope | Allows |
|---|---|
| `apps:read` | List and read applications, test runs, user migration settings and history |
| `apps:write` | Register, change and delete applications; set up user migration; start tests; rotate secrets |
| `secrets:read` | Read OIDC client secrets and migration secrets |
| `test_users` | Manage sandbox test users |
| `tools` | Generate SAML certificates |

**Tokens.** `POST /api/v1/oauth/token` with `grant_type=client_credentials` (HTTP Basic or `client_id`/`client_secret` in the body) returns a bearer token valid for 15 minutes, signed with a key derived from `SETTINGS_KEY`. The API takes no cookies, so it needs no CSRF token.

**Documents.**

- `GET /api/v1/openapi.json`: OpenAPI 3.1, with request schemas built from the same field definitions the API reads bodies with (`src/api/fields.js`).
- `/developers` (public page): what the API is for, how to hand a credential to a coding agent, and the agent guide rendered as HTML. `/developers/api` (public page): the API reference, Swagger UI served from `swagger-ui-dist`; **Authorize** takes a client ID and secret. Both are in the public navigation, the sidebar and the sitemap; `/api/v1/docs` redirects to the reference.
- `GET /api/v1/agent.md`: the guide for coding agents. It gives the order of calls to add OIDC login, SAML SSO and user migration to an application, how to choose values, how to handle secrets (env vars only, write straight to a git-ignored `.env`, never print or commit), how to hand a test login to a person, and every error code. It is linked from `/llms.txt`.

Neither document names a host. The guide writes every URL as `$CLOAKTAIL_URL/…` and tells the agent to take the base URL from where it fetched the guide (or from `CLOAKTAIL_URL` in its environment); the OpenAPI `servers` and `tokenUrl` are relative. So the same documents are right on every domain. URLs in API responses are absolute, built from the request's own domain.

A developer gives an agent the credential through environment variables (`CLOAKTAIL_URL`, `CLOAKTAIL_CLIENT_ID`, `CLOAKTAIL_CLIENT_SECRET`) and a prompt such as *"Use CloakTail to add OpenID Connect login to this app. First read https://…/api/v1/agent.md."* The credentials page has both, ready to copy.

**Secrets as files.** `GET /api/v1/apps/{id}/env` returns every variable an application needs (`OIDC_*` or `SAML_*`, plus `CLOAKTAIL_URL` and `CLOAKTAIL_MIGRATION_SECRET` with migration) as `.env` lines, and the secret endpoints take `?format=dotenv`, so agents write secrets to files without seeing them. The agent guide's shell helpers (`ct_token`, `env_merge`) need only curl and node or python3, pass the credential to curl on stdin, and merge `.env` idempotently.

**Discovery.** API responses carry RFC 8631 `Link` headers (`service-desc`, `service-doc`), `/.well-known/api-catalog` is an RFC 9727 catalog, and the public pages `/developers` and `/developers/api` (endpoint reference rendered on the server, JSON-LD, in the sitemap) link the documents with `<link rel>`.

**Errors** are RFC 9457 problem details (`application/problem+json`) with a stable `code`, a `detail` that says how to fix it, and `field` for validation errors. A repeated create answers `409 duplicate_client_id` with `existing_app_id` when the app is the caller's, so agents can retry safely. Limits: 60 token requests per IP and 1000 calls per credential per 15 minutes (in memory, per instance).

The HTML pages and the API share one service layer (`src/services/`) for validation, quotas and Keycloak calls.

## Admin console

`/admin` is separate from the Keycloak sign-in and from portal roles. Its accounts live in the `admin_accounts` table.

- **Keycloak profiles** (`/admin/keycloak`). The Keycloak connection is stored only in the database (table `keycloak_profiles`), never in `.env`.
  - A profile holds the Keycloak URL, both realms, the SAML client ID, the pinned IdP certificate, and both service accounts' client IDs and secrets. Keep one per environment, e.g. *Local*, *Staging* and *Production*.
  - **Domains:** each profile serves the domains listed on its page (e.g. `https://portal.example.com`), so several Keycloaks can be served side by side. A request uses the profile mapped to its scheme and host; any other host gets `421 Misdirected Request`, except that `/admin` always answers on `BASE_URL`. Changes apply at once, without a restart: the SAML strategies are rebuilt.
  - **Separate data:** users, roles and role assignments, applications and test users belong to one profile, and are only visible on its domains. A Keycloak sign-in is only valid on the domains of the profile it came from. Each new profile starts with the default roles.
  - **Portal SAML client:** for every domain, add `<domain>/*` to *Valid redirect URIs* and *Valid post logout redirect URIs*, and leave *Master SAML Processing URL* empty (when set, Keycloak posts every response to that one URL).
  - **Connection checks** test any profile, in use or not, even before it is saved: each section of the profile form (**Keycloak server**, **Portal realm**, **Sandbox realm**) has a **Check connection** button, and **Check all connections** runs them all. They cover the server, both realms, the portal realm's signing certificate, the sandbox's OpenID Connect discovery document and keys, and both service accounts with their permissions. The checks use the values in the form, saved or not; an empty secret field uses the stored secret. Test a profile before you give it domains.
  - A profile that serves domains can't be deleted. Deleting one also deletes its users, roles and application and test user records from CloakTail; Keycloak keeps its realms.
  - **Duplicate** copies a profile, including its secrets but not its domains, as a starting point for another environment.
  - Client secrets are encrypted at rest (AES-256-GCM, key from `SETTINGS_KEY` or else `SESSION_SECRET`) and are never sent back to the browser.
  - **Upgrading** from a single active profile: the active profile serves `BASE_URL` and keeps every existing user, role, application and test user.
- **SAML signing certificate**, one per profile (`/admin/keycloak/profiles/<id>/signing`, linked from the profile's page and the *Signing* column of the list). On a profile's domains, CloakTail signs its SAML login and logout requests with that profile's key pair, so its Keycloak can keep *Client signature required* on. Each profile, and so each Keycloak, has its own key.
  - **Generate** creates an RSA key pair (2048, 3072 or 4096 bit) and a self-signed certificate (1 to 10 years). You can also **import** an existing PEM pair; it must be RSA, at least 2048 bits, with an unencrypted key that matches the certificate.
  - The key pairs are stored in the database (table `sp_keys`, by `profile_id`), with the private key encrypted like the profile secrets. The private key is never shown or downloadable. The certificate can be copied or downloaded, and is also published in `/saml/metadata` on the profile's domains.
  - **Rotation:** while a profile's certificate is active, a new one is *pending*. Import the pending certificate into that profile's portal SAML client, then **Activate** it; the old key is deleted. Sign-ins on its domains fail between those two steps, so do them together.
  - The page and the server log warn when a certificate of a profile in use expires within 30 days.
  - Profile exports, imports and **Duplicate** don't include the signing key: give the new profile its own.
  - **Upgrading** from one shared certificate: every existing profile starts with a copy of it, so sign-in keeps working. Rotate each profile's key when convenient. An existing `certs/sp-key.pem` + `certs/sp-cert.pem` pair (from the old `npm run gen:sp-cert`) is moved into the database once, for every profile, on the first start with a profile and no stored key. After that the files are not read.
- **Export and import** profiles as JSON, to back them up or copy them between CloakTail instances.
  - Export one profile from its page, or all of them from the list. Client secrets are left out unless you tick *Include client secrets*; they are then in plain text, so store the file safely.
  - Import reads the file in the browser and validates every profile first. Nothing is imported if any profile is invalid. Imported profiles serve no domains until you add them; overwriting a profile keeps its domains. Exports never contain domains.
  - For a name that already exists, choose: **keep both** (imported as "Name (2)"), **overwrite** (secrets missing from the file are kept), or **skip**.
  - File format:
    ```json
    {
      "format": "cloaktail-keycloak-profiles",
      "version": 1,
      "exportedAt": "2026-10-01T09:00:00.000Z",
      "includesSecrets": false,
      "profiles": [{
        "name": "Local",
        "description": "Keycloak on my machine",
        "settings": {
          "url": "http://localhost:8080", "realm": "ep", "samlIssuer": "samlclient", "idpCert": "",
          "adminClientId": "samlclient-admin", "sandboxRealm": "ep-dev", "sandboxAdminClientId": "devportal-admin"
        },
        "secrets": { "adminClientSecret": "…", "sandboxAdminClientSecret": "…" }
      }]
    }
    ```
    `secrets` is present only when exported with secrets.
- **Upgrading from `.env` settings:** on the first start without any profile, the old `KEYCLOAK_*`, `SAML_ISSUER`, `SAML_IDP_CERT` and `SANDBOX_*` values (from `.env` or the earlier admin settings) become the profile "Default", serving `BASE_URL`. After that, `.env` is not read for them, so remove those lines.
- **First administrator**, as in Keycloak. While no administrator exists, every `/admin` page leads to `/admin/setup`. Create the first one in either of these ways:
  - **Setup page.** It needs the one-time setup token printed in the server log at startup. The token changes on every restart and stops working once an administrator exists. It stops whoever first reaches the URL from taking over the console. A "localhost only" rule like Keycloak's doesn't hold behind Docker port mapping or a reverse proxy.
  - **Environment variables** `ADMIN_BOOTSTRAP_USERNAME` and `ADMIN_BOOTSTRAP_PASSWORD`, for unattended deploys (like Keycloak's `KC_BOOTSTRAP_ADMIN_*`). They are used only when no administrator exists, and the password must be changed at first sign-in. You can remove them afterwards.
- **Administrators** (`/admin/accounts`): add or delete administrators. New accounts get a temporary password.
- **Security:**
  - Passwords are hashed with scrypt.
  - An account locks for 15 minutes after 10 failed sign-ins, and there is also a per-IP limit.
  - Admin sessions last at most 2 hours, and end at once when the password changes or the account is deleted.
- **Locked out?** `npm run admin -- reset <username>` (in Docker: `docker exec <container> npm run admin -- reset <username>`) sets a new temporary password and unlocks the account. `npm run admin -- list` lists the accounts.

Still in `.env`: `BASE_URL`, `SESSION_SECRET` / `SETTINGS_KEY`, sign-up options and limits.

## Keycloak setup

| Realm | Client | Protocol | Purpose |
|---|---|---|---|
| `ep` | `samlclient` | SAML | Signs users in to the portal |
| `ep` | `samlclient-admin` | OIDC, service account | Developer sign-up and admin user management |
| `ep-dev` | `devportal-admin` | OIDC, service account | Creates developers' SAML and OIDC clients and test users |

### Realm `ep`: SAML client `samlclient`

**Clients → Create client**

*General settings*
- Client type: **SAML**
- Client ID: `samlclient`

*Login settings*

| Field | Value |
|---|---|
| Root URL | `http://localhost:3000` |
| Home URL | `http://localhost:3000/` |
| Valid redirect URIs | `http://localhost:3000/*` |
| Valid post logout redirect URIs | `http://localhost:3000/*` |
| IDP-Initiated SSO URL name | `samlclient` (optional) |
| IDP Initiated SSO Relay State | `/` (optional) |
| Master SAML Processing URL | `http://localhost:3000/saml/acs` |

**Several domains** on one profile: add each domain's `/*` to *Valid redirect URIs* and *Valid post logout redirect URIs*, and leave *Master SAML Processing URL* empty. When it is set, Keycloak always posts the SAML response to that one domain, wherever the user signed in.

After saving, open the client:

- **Settings → SAML capabilities**
  - Name ID format: `username`
  - Force name ID format: **On**
- **Settings → Signature and Encryption**
  - Sign documents: **On**
  - Sign assertions: **On**
  - Algorithm: `RSA_SHA256`
- **Keys**
  - Client signature required: **On**
  - **Import key:** Archive format **Certificate PEM**, then upload the certificate from the admin console (**Keycloak profiles → your profile → SAML signing certificate → Download**). The portal signs its login and logout requests with the matching private key.
- **Advanced**
  - Assertion Consumer Service POST Binding URL: `http://localhost:3000/saml/acs`
  - Logout Service POST Binding URL: `http://localhost:3000/saml/logout/callback`
- **Client scopes → `samlclient-dedicated` → Configure a new mapper → User Property**, three times:

  | Name | Property | SAML Attribute Name |
  |---|---|---|
  | email | `email` | `email` |
  | firstName | `firstName` | `firstName` |
  | lastName | `lastName` | `lastName` |

### Realm `ep`: service account `samlclient-admin`

1. **Clients → Create client:** OpenID Connect, Client ID `samlclient-admin`.
2. Capability config: Client authentication **On**. Tick only **Service accounts roles**.
3. **Service accounts roles → Assign role → Filter by clients**, then add these `realm-management` roles:
   - `view-users`
   - `query-users`
   - `manage-users`
4. **Credentials** tab: copy the secret into the Keycloak profile (*portal service account client secret*).

### Sandbox realm `ep-dev`

1. **Create realm:** name it `ep-dev` (or any name; set it as the profile's sandbox realm).
2. **Realm settings → Login:** User registration **Off**. Test users are created only by the portal.
3. Create the service account client in `ep-dev`:
   1. **Clients → Create client:** OpenID Connect, Client ID `devportal-admin`.
   2. Client authentication **On**. Tick only **Service accounts roles**.
   3. **Service accounts roles → Assign role → Filter by clients**, then add these `realm-management` roles:
      - `view-clients`
      - `query-clients`
      - `manage-clients`
      - `view-users`
      - `query-users`
      - `manage-users`
   4. **Credentials:** copy the secret into the Keycloak profile (*sandbox service account client secret*).

`manage-clients` covers every client in `ep-dev`, including `devportal-admin` itself. The portal only edits or deletes clients recorded as owned by the current developer. Keep the secret server-side.

## How developer clients are configured

For each application, the portal creates a Keycloak SAML client with these settings:

- **Client ID:** the developer's entity ID. Entity IDs are first-come-first-served; Keycloak rejects duplicates.
- **ACS and logout URLs:** from the form. Wildcards are rejected.
- **Valid redirect URIs:** the ACS URL, the logout URL and the portal's test ACS (`<domain>/saml/test/acs` for each domain of the profile). A client created before a domain was added gets that domain's test ACS the first time it is tested from that domain.
- **Name ID format:** the developer's choice, with *force Name ID format* turned on.
- **Signing:** response and/or assertion signed with RSA-SHA256. At least one of the two is required.
- **Optional hardening:** signed AuthnRequests (with the developer's certificate) and encrypted assertions.
- **Attributes:** User Property mappers named `portal-attr-*` for the chosen attributes.
- **Bindings:** POST binding forced. A random IdP-initiated SSO URL name is generated.

**Test connection limitations:**
- Clients that require signed requests can't be tested from the portal, because only the developer's app holds that signing key. Use the IdP-initiated link instead.
- With encrypted assertions, the portal can check the response but can't read the assertion.

## Permissions

| Permission | Allows | Roles |
|---|---|---|
| `dashboard.view` | Dashboard | all |
| `apps.own` | Own applications and test users | developer |
| `apps.view_all` | View every developer's applications | admin |
| `apps.manage_all` | Edit or delete any application | admin |
| `users.*` | Manage portal accounts in `ep` | admin, user-manager |
| `roles.view` / `roles.manage` | Portal roles | admin (manage), user-manager (view) |

Deleting a portal user also deletes their sandbox applications and test users.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `ALLOW_REGISTRATION` | `true` | Show the sign-up form |
| `REGISTRATION_VERIFY_EMAIL` | `false` | Keycloak asks new users to verify their email (needs SMTP on `ep`) |
| `DEFAULT_ROLE` | `developer` | Role given at sign-up and on first sign-in |
| `MAX_APPS_PER_DEVELOPER` | `5` | Application limit per developer |
| `MAX_TEST_USERS_PER_DEVELOPER` | `5` | Test user limit per developer |

Sign-up is limited to 5 attempts per IP address per 15 minutes and has a hidden bot-trap field.

## Notes

- **Sessions** live in PostgreSQL, so they survive restarts and are shared by every instance. A migrating user's session holds their new authenticator secret until the account is created.
- **In-memory state:** pending tests and the rate limiters (sign-up, `/migrate`) live in memory, so restarting clears them and they are not shared across instances. For production, use a shared store.
- **HTTPS and proxies:** cookies are `Secure` on requests that arrived over HTTPS. Behind a reverse proxy, set `TRUST_PROXY` and forward `X-Forwarded-Proto` and `X-Forwarded-Host`; otherwise the app sees the internal address, finds no profile for it and answers 421.
- **Several instances:** domain and profile changes apply at once on the instance where they were made; restart the others.
