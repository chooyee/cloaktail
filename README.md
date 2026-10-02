# CloakTail

The self-service developer portal for Keycloak SAML.


A self-service portal where developers register, create SAML clients in Keycloak, and test their Keycloak connection. Built with Express, htmx and [Basecoat](https://basecoatui.com) (shadcn/ui styling without React).

## What it does

- **Public landing page** (`/` when signed out, `/guide` when signed in): features, how it works, how to register, how to test, and common problems.
- **Disclaimer** at `/disclaimer`, summarised in every page footer. Developers must accept it to sign up.
- **Certificate generator** at `/tools/certificate`: creates an RSA key pair (2048/3072/4096 bit) and a self-signed PEM certificate for signed requests or encrypted assertions. Keys are generated on the server, shown once, sent with `Cache-Control: no-store` and never stored. It is limited to 10 per developer per 10 minutes. The page also shows the equivalent OpenSSL command for production keys.

- **Developer sign-up:** the portal's own sign-up form creates the account in the portal realm (`ep`). New accounts get the `developer` role.
- **Sign-in:** through Keycloak with SAML 2.0.
- **Applications:** a developer registers their SAML service provider (SP) by filling a form or importing SP metadata XML. The portal creates a SAML client for it in a separate **sandbox realm** (`ep-dev`). Developers see and change only their own applications.
- **Connection details:** each application page shows:
  - The IdP metadata URL, entity ID, SSO/SLO URLs and signing certificate
  - The IdP-initiated login link
  - A ready-to-copy passport-saml config
- **Test connection:** the portal acts as the developer's SP for one login. It sends an AuthnRequest with their entity ID and the portal's own ACS, the developer signs in as a sandbox test user, and the portal shows:
  - Pass/fail checks for status, issuer, destination, audience, signatures and expected attributes
  - The Name ID and session index
  - Every attribute received
  - The raw XML

  The last 10 runs are kept per application.
- **Test users:** each developer manages a few accounts in the sandbox realm to sign in with during tests.
- **Portal administration:** user management (in `ep`) and portal roles and permissions, as before.
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
3. In **Signing certificate**, generate the portal's SAML signing certificate and import it into the portal SAML client in Keycloak.

Until a profile serves the domain, every page except `/admin` answers 421; until a signing certificate exists, Keycloak sign-in shows "not set up yet".

## Admin console

`/admin` is separate from the Keycloak sign-in and from portal roles. Its accounts live in the `admin_accounts` table.

- **Keycloak profiles** (`/admin/keycloak`). The Keycloak connection is stored only in the database (table `keycloak_profiles`), never in `.env`.
  - A profile holds the Keycloak URL, both realms, the SAML client ID, the pinned IdP certificate, and both service accounts' client IDs and secrets. Keep one per environment, e.g. *Local*, *Staging* and *Production*.
  - **Domains:** each profile serves the domains listed on its page (e.g. `https://portal.example.com`), so several Keycloaks can be served side by side. A request uses the profile mapped to its scheme and host; any other host gets `421 Misdirected Request`, except that `/admin` always answers on `BASE_URL`. Changes apply at once, without a restart: the SAML strategies are rebuilt.
  - **Separate data:** users, roles and role assignments, applications and test users belong to one profile, and are only visible on its domains. A Keycloak sign-in is only valid on the domains of the profile it came from. Each new profile starts with the default roles.
  - **Portal SAML client:** for every domain, add `<domain>/*` to *Valid redirect URIs* and *Valid post logout redirect URIs*, and leave *Master SAML Processing URL* empty (when set, Keycloak posts every response to that one URL).
  - **Run checks** tests any profile, in use or not: both realms, the signing certificate, and both service accounts with their permissions. Test a profile before you give it domains.
  - A profile that serves domains can't be deleted. Deleting one also deletes its users, roles and application and test user records from CloakTail; Keycloak keeps its realms.
  - **Duplicate** copies a profile, including its secrets but not its domains, as a starting point for another environment.
  - Client secrets are encrypted at rest (AES-256-GCM, key from `SETTINGS_KEY` or else `SESSION_SECRET`) and are never sent back to the browser.
  - **Upgrading** from a single active profile: the active profile serves `BASE_URL` and keeps every existing user, role, application and test user.
- **Signing certificate** (`/admin/signing`). CloakTail signs its SAML login and logout requests with its own key pair, so Keycloak can keep *Client signature required* on.
  - **Generate** creates an RSA key pair (2048, 3072 or 4096 bit) and a self-signed certificate (1 to 10 years). You can also **import** an existing PEM pair; it must be RSA, at least 2048 bits, with an unencrypted key that matches the certificate.
  - The key pair is stored in the database (table `sp_keys`), with the private key encrypted like the profile secrets. The private key is never shown or downloadable. The certificate can be copied or downloaded, and is also published in `/saml/metadata`.
  - **Rotation:** while a certificate is active, a new one is *pending*. Import the pending certificate into Keycloak, then **Activate** it; the old key is deleted. Sign-ins fail between those two steps, so do them together.
  - The page and the server log warn when the certificate expires within 30 days.
  - **Upgrading:** an existing `certs/sp-key.pem` + `certs/sp-cert.pem` pair (from the old `npm run gen:sp-cert`) is moved into the database once, on the first start. After that the files are not read.
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
| `ep-dev` | `devportal-admin` | OIDC, service account | Creates developers' SAML clients and test users |

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
  - **Import key:** Archive format **Certificate PEM**, then upload the certificate from the admin console (**Signing certificate → Download**). The portal signs its login and logout requests with the matching private key.
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

- **In-memory state:** sessions, pending tests and the sign-up limiter live in memory, so restarting clears them. They are also not shared across instances. For production, use a shared store.
- **HTTPS and proxies:** cookies are `Secure` on requests that arrived over HTTPS. Behind a reverse proxy, set `TRUST_PROXY` and forward `X-Forwarded-Proto` and `X-Forwarded-Host`; otherwise the app sees the internal address, finds no profile for it and answers 421.
- **Several instances:** domain and profile changes apply at once on the instance where they were made; restart the others.
