import 'dotenv/config';

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable ${name} (see .env.example)`);
  return value;
}

const baseUrl = (process.env.BASE_URL || 'http://localhost:3000').replace(/\/$/, '');
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
  secureCookies: baseUrl.startsWith('https://'),
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
  },

  registration: {
    enabled: flag('ALLOW_REGISTRATION', true),
    // Adds Keycloak's VERIFY_EMAIL required action; needs SMTP configured on the realm.
    verifyEmail: flag('REGISTRATION_VERIFY_EMAIL', false),
  },

  // Keycloak connection: not in .env. It comes from the active Keycloak profile in the database
  // (src/keycloakProfiles.js), which calls applyKeycloakSettings(). These objects are updated in
  // place, so always read them at call time rather than copying them at import.
  keycloak: {},

  // Realm where developers' SAML clients and test users live, isolated from the portal realm.
  sandbox: {
    // The portal's own ACS used by "Test connection"; added to every developer client.
    testAcsUrl: `${baseUrl}/saml/test/acs`,
    maxAppsPerDeveloper: int('MAX_APPS_PER_DEVELOPER', 5),
    maxTestUsersPerDeveloper: int('MAX_TEST_USERS_PER_DEVELOPER', 5),
  },

  saml: {
    // Key pair files from before signing keys were stored in the database; only read once, to
    // move them into it (spKeys.js). Generate or import keys in the admin console instead.
    spKeyFile: process.env.SAML_SP_KEY_FILE || 'certs/sp-key.pem',
    spCertFile: process.env.SAML_SP_CERT_FILE || 'certs/sp-cert.pem',
    callbackUrl: `${baseUrl}/saml/acs`,
    logoutCallbackUrl: `${baseUrl}/saml/logout/callback`,
  },
};

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
    },
    saml: {
      issuer: s?.samlIssuer || '',
      idpCert: stripPem(s?.idpCert),
      entryPoint: configured ? `${realmBase(realm)}/protocol/saml` : '',
      descriptorUrl: configured ? `${realmBase(realm)}/protocol/saml/descriptor` : '',
    },
  };
}

export function applyKeycloakSettings(settings) {
  const derived = deriveKeycloakConfig(settings);
  Object.assign(config.keycloak, derived.keycloak);
  Object.assign(config.sandbox, derived.sandbox);
  Object.assign(config.saml, derived.saml);
}

applyKeycloakSettings(null);
