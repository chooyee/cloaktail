import { deriveKeycloakConfig } from '../config.js';
import { fetchIdpCerts } from './idpCerts.js';
import { createAdminClient } from './keycloakAdmin.js';

// Connection checks in the admin console: test a Keycloak profile's settings end to end, one
// connection (section of the profile form) at a time or all of them. They work on any settings,
// saved or not, so a profile can be verified before it is saved or serves a domain.

const TIMEOUT_MS = 8000;

function withTimeout(promise) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`No answer within ${TIMEOUT_MS / 1000} seconds.`)), TIMEOUT_MS);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function check(name, fn) {
  try {
    return { name, ok: true, detail: await withTimeout(fn()) };
  } catch (err) {
    // fetch() hides the network error (ECONNREFUSED, ENOTFOUND...) in err.cause.
    const cause = err.cause?.code || err.cause?.message;
    return { name, ok: false, detail: cause ? `${err.message} (${cause})` : err.message };
  }
}

const get = (url) => fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });

async function realmExists(realmUrl) {
  const res = await get(realmUrl);
  if (!res.ok) throw new Error(`${realmUrl} answered HTTP ${res.status}. Check the URL and realm name.`);
  return `Found at ${realmUrl}.`;
}

// The checks of each connection; ids match the profile form's sections (PROFILE_SECTIONS).
const SECTIONS = {
  server: ({ keycloak }) => [
    check('Keycloak server', async () => {
      const res = await get(`${keycloak.url}/realms/master`);
      if (res.status >= 500) throw new Error(`${keycloak.url} answered HTTP ${res.status}.`);
      const body = await res.json().catch(() => null);
      if (!body?.realm) throw new Error(`${keycloak.url} answered, but not like Keycloak (no realm at /realms/master). Enter the base URL, without /realms/… or a context path it doesn’t use.`);
      return `Keycloak answers at ${keycloak.url}.`;
    }),
  ],
  portal: ({ keycloak, saml }) => {
    // Throwaway client, so checking never touches the live clients' cached tokens.
    const admin = createAdminClient(() => keycloak, 'portal service account client secret');
    return [
      check(`Portal realm "${keycloak.realm}"`, () => realmExists(keycloak.realmUrl)),
      check('Portal realm signing certificate', async () => {
        const certs = await fetchIdpCerts(saml.descriptorUrl, { signal: AbortSignal.timeout(TIMEOUT_MS) });
        if (saml.idpCert && !certs.includes(saml.idpCert)) {
          throw new Error("The pinned certificate is not one of the realm's signing certificates, so every sign-in would fail.");
        }
        return `${certs.length} signing certificate${certs.length === 1 ? '' : 's'} published${saml.idpCert ? '; the pinned one matches' : ''}.`;
      }),
      check(`Portal service account "${keycloak.adminClientId}"`, async () => {
        const count = await admin.countUsers({});
        return `Signed in; can read users (${count} in the realm).`;
      }),
    ];
  },
  sandbox: ({ sandbox }) => {
    const admin = createAdminClient(() => sandbox, 'sandbox service account client secret');
    return [
      check(`Sandbox realm "${sandbox.realm}"`, () => realmExists(sandbox.realmUrl)),
      check('Sandbox OpenID Connect discovery and keys', async () => {
        const res = await get(sandbox.oidc.discoveryUrl);
        if (!res.ok) throw new Error(`${sandbox.oidc.discoveryUrl} answered HTTP ${res.status}.`);
        const doc = await res.json();
        if (doc.issuer !== sandbox.oidc.issuer) {
          throw new Error(`Keycloak calls itself ${doc.issuer}, not ${sandbox.oidc.issuer}: tokens would fail issuer checks. Use the URL Keycloak advertises (its hostname setting).`);
        }
        const jwks = await (await get(sandbox.oidc.jwksUri)).json();
        const signing = (jwks.keys || []).filter((k) => k.use !== 'enc');
        if (!signing.length) throw new Error(`No signing keys at ${sandbox.oidc.jwksUri}.`);
        return `Issuer matches; ${signing.length} signing key${signing.length === 1 ? '' : 's'} published.`;
      }),
      check(`Sandbox service account "${sandbox.adminClientId}"`, async () => {
        const [count] = await Promise.all([admin.countUsers({}), admin.listClients({ max: 1 })]);
        return `Signed in; can read clients and users (${count} users in the realm).`;
      }),
    ];
  },
};

export const CHECK_SECTIONS = Object.keys(SECTIONS);

// settings: a profile's settings and secrets, flattened. sections: which connections to check.
export function checkKeycloakConnection(settings, sections = CHECK_SECTIONS) {
  const derived = deriveKeycloakConfig(settings);
  return Promise.all(sections.flatMap((s) => SECTIONS[s](derived)));
}
