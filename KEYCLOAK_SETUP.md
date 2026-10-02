# Keycloak setup checklist

Everything to configure in a fresh (or reset) Keycloak for CloakTail. Values assume the defaults
(`ep`, `ep-dev`, portal on `http://localhost:3000`); replace them with your own realm names and domain.

| Realm | Client | Protocol | Purpose |
|---|---|---|---|
| `ep` | `samlclient` | SAML | Signs users in to the portal |
| `ep` | `samlclient-admin` | OIDC, service account | Developer sign-up and admin user management |
| `ep-dev` | `devportal-admin` | OIDC, service account | Creates developers' SAML clients and test users |

---

## 1. Portal realm `ep`

- [ ] **Create realm** `ep`
- [ ] *(Only if `REGISTRATION_VERIFY_EMAIL=true`)* **Realm settings → Email**: configure SMTP
- [ ] Create a user for yourself whose username is in `ADMIN_USERS` (default `admin`). That user gets the portal `admin` role on first sign-in.

### 1a. SAML client `samlclient`

**Clients → Create client**

- [ ] Client type: **SAML**
- [ ] Client ID: `samlclient` (must equal the profile's *SAML issuer*)

*Login settings*

| Field | Value |
|---|---|
| Root URL | `http://localhost:3000` |
| Home URL | `http://localhost:3000/` |
| Valid redirect URIs | `http://localhost:3000/*` (one entry per portal domain) |
| Valid post logout redirect URIs | `http://localhost:3000/*` (one entry per portal domain) |
| IDP-Initiated SSO URL name | `samlclient` (optional) |
| IDP Initiated SSO Relay State | `/` (optional) |
| Master SAML Processing URL | `http://localhost:3000/saml/acs`, or **empty** if the profile serves more than one domain |

**Settings → SAML capabilities**
- [ ] Name ID format: `username`
- [ ] Force name ID format: **On**

**Settings → Signature and Encryption**
- [ ] Sign documents: **On**
- [ ] Sign assertions: **On**
- [ ] Signature algorithm: `RSA_SHA256`

**Keys**
- [ ] Client signature required: **On**
- [ ] **Import key** → Archive format **Certificate PEM** → upload the certificate from CloakTail **/admin → Keycloak profiles → (your profile) → SAML signing certificate → Download**

**Advanced → Fine Grain SAML Endpoint Configuration**
- [ ] Assertion Consumer Service POST Binding URL: `http://localhost:3000/saml/acs`
- [ ] Logout Service POST Binding URL: `http://localhost:3000/saml/logout/callback`

**Client scopes → `samlclient-dedicated` → Configure a new mapper → User Property** (three mappers)

| Name | Property | SAML Attribute Name |
|---|---|---|
| email | `email` | `email` |
| firstName | `firstName` | `firstName` |
| lastName | `lastName` | `lastName` |

### 1b. Service account client `samlclient-admin`

- [ ] **Clients → Create client**: OpenID Connect, Client ID `samlclient-admin`
- [ ] Capability config: Client authentication **On**; tick only **Service accounts roles** (untick Standard flow / Direct access)
- [ ] **Service accounts roles → Assign role → Filter by clients** → add these `realm-management` roles:
  - [ ] `view-users`
  - [ ] `query-users`
  - [ ] `manage-users`
- [ ] **Credentials**: copy the client secret (goes into the profile, step 3)

---

## 2. Sandbox realm `ep-dev`

- [ ] **Create realm** `ep-dev`
- [ ] **Realm settings → Login**: User registration **Off**

### 2a. Service account client `devportal-admin`

- [ ] **Clients → Create client**: OpenID Connect, Client ID `devportal-admin`
- [ ] Client authentication **On**; tick only **Service accounts roles**
- [ ] **Service accounts roles → Assign role → Filter by clients** → add these `realm-management` roles:
  - [ ] `view-clients`
  - [ ] `query-clients`
  - [ ] `manage-clients`
  - [ ] `view-users`
  - [ ] `query-users`
  - [ ] `manage-users`
- [ ] **Credentials**: copy the client secret (goes into the profile, step 3)

---

## 3. Update CloakTail after the reset (`/admin`)

A reset gives the realms **new signing keys** and the clients **new secrets**, so the existing profile no longer matches.

**Keycloak profiles → (your profile) → Edit**
- [ ] Keycloak URL, e.g. `http://localhost:8080`
- [ ] Portal realm `ep`, SAML issuer `samlclient`, portal service account `samlclient-admin` + **new secret**
- [ ] Sandbox realm `ep-dev`, sandbox service account `devportal-admin` + **new secret**
- [ ] **Pinned IdP certificate**: clear it (the realm certificate is then fetched automatically), or paste the new one from **Realm settings → Keys → RS256 → Certificate**. If you keep the old one, every sign-in fails.
- [ ] Domains: still list your portal domain(s), e.g. `http://localhost:3000`
- [ ] **Check all connections**: all seven should pass (Keycloak server, both realms, realm signing certificate, sandbox OIDC discovery and keys, both service accounts). Each section also has its own **Check connection** button.

**(your profile) → SAML signing certificate**
- [ ] Download the profile's active certificate and import it into `samlclient` → **Keys** (step 1a). The reset removed it from Keycloak.

---

## 4. Stale data to be aware of

CloakTail's database still holds records from the old Keycloak:

- **Applications**: their SAML clients no longer exist in `ep-dev`. Delete and recreate them, or re-register them.
- **Test users**: no longer exist in `ep-dev`. Recreate them from the Test users page.
- **Portal users**: accounts in `ep` are gone. Users must sign up again; if they use the same username, the local record and roles are picked up again on sign-in.

## 5. Smoke test

- [ ] Sign in to the portal through Keycloak with your `ADMIN_USERS` account
- [ ] Register a new developer through the sign-up form (checks `samlclient-admin`)
- [ ] Create an application and a test user, then run **Test connection** (checks `devportal-admin` and the sandbox realm)
