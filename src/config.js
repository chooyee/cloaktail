import 'dotenv/config';
import { AsyncLocalStorage } from 'node:async_hooks';

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable ${name} (see .env.example)`);
  return value;
}

// BASE_URL: the portal's main address. The admin console is always reachable here, even before any
// Keycloak profile serves this domain; the other domains are set per profile in the admin console.
const baseUrl = (() => {
  const raw = (process.env.BASE_URL || 'http://localhost:3000').trim();
  const url = new URL(raw);
  if (url.pathname !== '/' || url.search || url.hash || raw.includes(',')) {
    throw new Error(`BASE_URL must be one origin such as https://example.com, not ${raw}. Other domains are set per Keycloak profile in the admin console.`);
  }
  return url.origin;
})();
const flag = (name, fallback) => (process.env[name] ?? String(fallback)).toLowerCase() === 'true';
const int = (name, fallback) => Number.parseInt(process.env[name] ?? '', 10) || fallback;
const sessionSecret = required('SESSION_SECRET');

// A pasted certificate may carry PEM armour and line breaks; keep only the base64 body.
export const stripPem = (cert) => (cert || '').replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, '');

export const config = {
  port: Number(process.env.PORT || 3000),
  baseUrl,
  sessionSecret,
  // Encrypts client secrets stored in Keycloak profiles. Changing it makes stored secrets unreadable.
  settingsKey: process.env.SETTINGS_KEY || sessionSecret,
  // Domains may be http:// or https://, so cookies are Secure whenever the request came over HTTPS.
  // Behind a TLS-terminating proxy that needs TRUST_PROXY (which domain lookup needs anyway).
  secureCookies: 'auto',
  // TRUST_PROXY: number of proxy hops (e.g. 1), or an Express value such as "loopback". Unset = no proxy.
  trustProxy: /^\d+$/.test(process.env.TRUST_PROXY || '') ? Number(process.env.TRUST_PROXY) : process.env.TRUST_PROXY || null,
  adminUsers: (process.env.ADMIN_USERS || '')
    .split(',')
    .map((u) => u.trim().toLowerCase())
    .filter(Boolean),
  defaultRole: process.env.DEFAULT_ROLE || 'developer',
  // PostgreSQL connection. Unset values fall back to the standard PG* variables / pg defaults.
  db: {
    host: process.env.dbhost || undefined,
    port: int('dbport', 5432),
    database: process.env.database || undefined,
    user: process.env.dbuser || undefined,
    password: process.env.dbpassword || undefined,
    // Optional account used only at startup to create missing tables (see db/schema.sql).
    admin: process.env.dbadminuser
      ? { user: process.env.dbadminuser, password: process.env.dbadminpassword || undefined }
      : null,
  },

  registration: {
    enabled: flag('ALLOW_REGISTRATION', true),
    // Adds Keycloak's VERIFY_EMAIL required action; needs SMTP configured on the realm.
    verifyEmail: flag('REGISTRATION_VERIFY_EMAIL', false),
  },

  // keycloak, sandbox and saml (defined below) depend on the Keycloak profile serving the current
  // request, so always read them at call time rather than copying them at import.
};

// Keycloak's fixed OIDC endpoint paths under a realm URL (the same as its discovery document lists).
function oidcEndpoints(realmUrl) {
  const at = (path) => (realmUrl ? `${realmUrl}${path}` : '');
  return {
    issuer: realmUrl,
    discoveryUrl: at('/.well-known/openid-configuration'),
    authorizationEndpoint: at('/protocol/openid-connect/auth'),
    tokenEndpoint: at('/protocol/openid-connect/token'),
    userinfoEndpoint: at('/protocol/openid-connect/userinfo'),
    jwksUri: at('/protocol/openid-connect/certs'),
    endSessionEndpoint: at('/protocol/openid-connect/logout'),
  };
}

// Everything the app derives from a Keycloak profile's settings. With no profile (fresh install)
// every value is empty and `configured` is false.
export function deriveKeycloakConfig(s) {
  const configured = Boolean(s);
  const url = configured ? s.url.replace(/\/+$/, '') : '';
  const realm = s?.realm || '';
  const sandboxRealm = s?.sandboxRealm || '';
  const realmBase = (name) => (configured ? `${url}/realms/${name}` : '');
  const adminBase = (name) => (configured ? `${url}/admin/realms/${name}` : '');
  return {
    keycloak: {
      configured,
      url,
      realm,
      realmUrl: realmBase(realm),
      adminApiUrl: adminBase(realm),
      adminClientId: s?.adminClientId || '',
      adminClientSecret: s?.adminClientSecret || '',
    },
    sandbox: {
      configured,
      realm: sandboxRealm,
      realmUrl: realmBase(sandboxRealm),
      adminApiUrl: adminBase(sandboxRealm),
      adminClientId: s?.sandboxAdminClientId || '',
      adminClientSecret: s?.sandboxAdminClientSecret || '',
      samlEndpoint: configured ? `${realmBase(sandboxRealm)}/protocol/saml` : '',
      descriptorUrl: configured ? `${realmBase(sandboxRealm)}/protocol/saml/descriptor` : '',
      // OpenID Connect provider endpoints of the sandbox realm (issuer = realmUrl).
      oidc: oidcEndpoints(configured ? realmBase(sandboxRealm) : ''),
    },
    saml: {
      issuer: s?.samlIssuer || '',
      idpCert: stripPem(s?.idpCert),
      entryPoint: configured ? `${realmBase(realm)}/protocol/saml` : '',
      descriptorUrl: configured ? `${realmBase(realm)}/protocol/saml/descriptor` : '',
    },
  };
}

// ---------- the Keycloak profile serving the current request ----------

// Each request runs inside tenantContext.run(tenant) (app.js), where tenant is the Keycloak profile
// mapped to the request's domain (keycloakProfiles.js):
//   { profileId, profileName, siteUrl, domains, keycloak, sandbox, saml }
// siteUrl is the request's own domain; domains are all of the profile's domains.
export const tenantContext = new AsyncLocalStorage();
export const currentTenant = () => tenantContext.getStore() ?? null;

// Data in the database belongs to one profile. Failing loudly outside a profile's context means a
// query can never fall back to reading or writing another profile's rows.
export function currentProfileId() {
  const tenant = currentTenant();
  if (!tenant) throw new Error('No Keycloak profile serves this request.');
  return tenant.profileId;
}

export const testAcsUrlFor = (siteUrl) => `${siteUrl}/saml/test/acs`;
export const testOidcRedirectUriFor = (siteUrl) => `${siteUrl}/oidc/test/callback`;

// The portal's own SAML endpoints on one domain.
export const samlUrlsFor = (siteUrl) => ({
  callbackUrl: `${siteUrl}/saml/acs`,
  logoutCallbackUrl: `${siteUrl}/saml/logout/callback`,
});

const UNCONFIGURED = deriveKeycloakConfig(null);
const sandboxLimits = {
  maxAppsPerDeveloper: int('MAX_APPS_PER_DEVELOPER', 5),
  maxTestUsersPerDeveloper: int('MAX_TEST_USERS_PER_DEVELOPER', 5),
};
const samlKeyFiles = {
  // Key pair files from before signing keys were stored in the database; only read once, to
  // move them into it (spKeys.js). Generate or import keys in the admin console instead.
  spKeyFile: process.env.SAML_SP_KEY_FILE || 'certs/sp-key.pem',
  spCertFile: process.env.SAML_SP_CERT_FILE || 'certs/sp-cert.pem',
};

Object.defineProperties(config, {
  // Portal realm: where developers sign in.
  keycloak: { enumerable: true, get: () => currentTenant()?.keycloak ?? UNCONFIGURED.keycloak },
  // Realm where developers' SAML clients and test users live, isolated from the portal realm.
  sandbox: {
    enumerable: true,
    get() {
      const t = currentTenant();
      return {
        ...sandboxLimits,
        ...(t?.sandbox ?? UNCONFIGURED.sandbox),
        // The portal's own ACS used by "Test connection" on this domain. Every developer client
        // accepts the test ACS of all the profile's domains.
        testAcsUrl: t ? testAcsUrlFor(t.siteUrl) : '',
        testAcsUrls: t ? t.domains.map(testAcsUrlFor) : [],
        // The same for OIDC clients: the portal's redirect URI on every domain of the profile.
        testOidcRedirectUri: t ? testOidcRedirectUriFor(t.siteUrl) : '',
        testOidcRedirectUris: t ? t.domains.map(testOidcRedirectUriFor) : [],
      };
    },
  },
  saml: {
    enumerable: true,
    get() {
      const t = currentTenant();
      return { ...samlKeyFiles, ...(t?.saml ?? UNCONFIGURED.saml), ...(t ? samlUrlsFor(t.siteUrl) : {}) };
    },
  },
});
