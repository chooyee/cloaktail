import { deriveKeycloakConfig } from '../config.js';
import { fetchIdpCerts } from './idpCerts.js';
import { createAdminClient } from './keycloakAdmin.js';

// "Test connection" in the admin console: checks a Keycloak profile end to end. Works on any
// profile, active or not, so a profile can be verified before switching to it.

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

async function realmExists(realmUrl) {
  const res = await fetch(realmUrl, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!res.ok) throw new Error(`${realmUrl} answered HTTP ${res.status}. Check the URL and realm name.`);
  return `Found at ${realmUrl}.`;
}

// settings: a profile's settings and secrets, flattened.
export function checkKeycloakConnection(settings) {
  const { keycloak, sandbox, saml } = deriveKeycloakConfig(settings);
  // Throwaway clients, so testing never touches the live clients' cached tokens.
  const portalAdmin = createAdminClient(() => keycloak, 'portal service account client secret');
  const sandboxAdmin = createAdminClient(() => sandbox, 'sandbox service account client secret');
  return Promise.all([
    check(`Portal realm "${keycloak.realm}"`, () => realmExists(keycloak.realmUrl)),
    check('Portal realm signing certificate', async () => {
      const certs = await fetchIdpCerts(saml.descriptorUrl, { signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (saml.idpCert && !certs.includes(saml.idpCert)) {
        throw new Error("The pinned certificate is not one of the realm's signing certificates, so every sign-in would fail.");
      }
      return `${certs.length} signing certificate${certs.length === 1 ? '' : 's'} published${saml.idpCert ? '; the pinned one matches' : ''}.`;
    }),
    check(`Portal service account "${keycloak.adminClientId}"`, async () => {
      const count = await portalAdmin.countUsers({});
      return `Signed in; can read users (${count} in the realm).`;
    }),
    check(`Sandbox realm "${sandbox.realm}"`, () => realmExists(sandbox.realmUrl)),
    check(`Sandbox service account "${sandbox.adminClientId}"`, async () => {
      const [count] = await Promise.all([sandboxAdmin.countUsers({}), sandboxAdmin.listClients({ max: 1 })]);
      return `Signed in; can read clients and users (${count} users in the realm).`;
    }),
  ]);
}
