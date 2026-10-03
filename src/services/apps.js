import { config, testAcsUrlFor, testOidcRedirectUriFor } from '../config.js';
import { KeycloakError } from '../lib/keycloakAdmin.js';
import { loadIdpCerts } from '../lib/idpCerts.js';
import {
  NAME_ID_FORMATS, USER_ATTRIBUTES, ATTRIBUTE_NAME_FORMATS, ENCRYPTION_KEY_ALGORITHMS, certToPem,
  defaultAppValues, parseAppForm, validateApp, valuesFromMetadata,
  createSamlClient, updateSamlClient, loadSamlClient, deleteSandboxClient,
} from '../lib/samlClients.js';
import {
  CLIENT_TYPES, defaultOidcValues, parseOidcForm, validateOidcApp,
  createOidcClient, updateOidcClient, loadOidcClient, getOidcClientSecret, regenerateOidcClientSecret,
} from '../lib/oidcClients.js';
import { startTest } from '../lib/samlTest.js';
import { startOidcTest } from '../lib/oidcTest.js';
import { listApps, countApps, getApp, getAppByClientId, insertApp, renameApp, deleteApp } from '../db.js';
import { ServiceError, invalid } from './errors.js';

// Developer applications: SAML or OpenID Connect clients in the sandbox realm (apps.protocol).
// Used by the HTML pages (routes/apps.js) and the REST API (routes/api.js). `actor` is who acts:
// { username, can(permission) }, the signed-in developer or the owner of an API credential.

export const protocolOf = (value) => (value === 'oidc' ? 'oidc' : 'saml');

export const PROTOCOL = {
  saml: {
    form: 'pages/apps/form',
    formOptions: { NAME_ID_FORMATS, USER_ATTRIBUTES, ATTRIBUTE_NAME_FORMATS, ENCRYPTION_KEY_ALGORITHMS },
    defaults: defaultAppValues,
    parse: parseAppForm,
    validate: validateApp,
    create: createSamlClient,
    update: updateSamlClient,
    load: loadSamlClient,
    // The portal's own endpoint Keycloak sends test logins to, shown on the form.
    testUrl: testAcsUrlFor,
    duplicate: (v) => `Entity ID "${v.clientId}" is already registered. Choose a different one.`,
  },
  oidc: {
    form: 'pages/apps/oidc-form',
    formOptions: { CLIENT_TYPES },
    defaults: defaultOidcValues,
    parse: parseOidcForm,
    validate: validateOidcApp,
    create: createOidcClient,
    update: updateOidcClient,
    load: loadOidcClient,
    testUrl: testOidcRedirectUriFor,
    duplicate: (v) => `Client ID "${v.clientId}" is already registered. Choose a different one.`,
  },
};

export const canEditApp = (actor, app) => (app.owner === actor.username ? actor.can('apps.own') : actor.can('apps.manage_all'));

// Owners manage their own apps; apps.view_all / apps.manage_all extend that to everyone's.
// Returns null when the actor may not see (or, with write, change) the app.
export async function findApp(actor, id, { write = false } = {}) {
  const app = await getApp(Number(id));
  const own = app && app.owner === actor.username && actor.can('apps.own');
  return app && (own || actor.can(write ? 'apps.manage_all' : 'apps.view_all')) ? app : null;
}

export function listAppsFor(actor, { all = false } = {}) {
  const showAll = actor.can('apps.view_all') && (all || !actor.can('apps.own'));
  if (!showAll && !actor.can('apps.own')) throw new ServiceError(403, 'forbidden', 'You do not have permission to do that.');
  return listApps(showAll ? {} : { owner: actor.username });
}

// The app's Keycloak client ({ rep, values }). Keycloak can lose a client (deleted in its admin
// console); that is a 404 the developer can fix by registering the app again.
export async function loadClient(app) {
  try {
    return await PROTOCOL[app.protocol].load(app.kc_id);
  } catch (err) {
    if (err instanceof KeycloakError && err.status === 404) {
      throw new ServiceError(404, 'keycloak_client_missing',
        `The Keycloak client for "${app.name}" no longer exists in realm ${config.sandbox.realm}. Delete this application and register it again.`);
    }
    throw err;
  }
}

// Validates `values` (normalizing them in place), creates the Keycloak client and records the app.
// Returns the new app's id.
export async function createApp(actor, protocol, values) {
  const p = PROTOCOL[protocol];
  if (!actor.can('apps.own')) throw new ServiceError(403, 'forbidden', 'You do not have permission to do that.');
  const max = config.sandbox.maxAppsPerDeveloper;
  if (await countApps(actor.username) >= max) {
    throw new ServiceError(422, 'quota_exceeded', `You have reached the limit of ${max} applications. Delete one first.`);
  }
  const error = p.validate(values, { isNew: true });
  if (error) throw invalid(error);

  let kcId;
  try {
    kcId = await p.create(values, actor.username);
  } catch (err) {
    if (err instanceof KeycloakError && err.status === 409) {
      // Tell the owner which of their apps it is, so a retried create can carry on with it.
      const existing = await getAppByClientId(values.clientId);
      throw new ServiceError(409, 'duplicate_client_id', p.duplicate(values),
        existing?.owner === actor.username ? { existing_app_id: existing.id } : {});
    }
    if (err instanceof KeycloakError && err.status < 500) throw new ServiceError(422, 'keycloak_rejected', err.message);
    throw err;
  }
  return insertApp({ protocol, owner: actor.username, kcId, clientId: values.clientId, name: values.name });
}

// Validates `values` (the client ID can't change) and updates the Keycloak client and the app's name.
export async function updateApp(app, values) {
  const p = PROTOCOL[app.protocol];
  values.clientId = app.client_id;
  const error = p.validate(values, { isNew: false });
  if (error) throw invalid(error);
  try {
    await p.update(app.kc_id, values, app.owner);
  } catch (err) {
    if (err instanceof KeycloakError && err.status < 500) throw new ServiceError(422, 'keycloak_rejected', err.message);
    throw err;
  }
  await renameApp(app.id, values.name);
  return values;
}

export async function removeApp(app) {
  await deleteSandboxClient(app.kc_id);
  await deleteApp(app.id);
}

// SP metadata XML -> SAML form values. Nothing is created.
export async function samlValuesFromMetadata(metadata) {
  const xml = (metadata || '').trim();
  if (!xml.startsWith('<')) throw invalid('Paste your SP metadata XML (it starts with <EntityDescriptor …>).');
  try {
    return await valuesFromMetadata(xml);
  } catch (err) {
    if (err instanceof KeycloakError && err.status < 500) throw invalid(`Keycloak could not read that metadata: ${err.message}`);
    throw err;
  }
}

const requireOidc = (app) => {
  if (app.protocol !== 'oidc') throw new ServiceError(400, 'not_oidc', 'Only OpenID Connect clients have a client secret.');
};

// The client secret of a confidential OIDC client; null for a public client.
export async function appClientSecret(app) {
  requireOidc(app);
  return getOidcClientSecret(app.kc_id);
}

// A new client secret; the old one stops working at once.
export async function rotateAppClientSecret(app) {
  requireOidc(app);
  return regenerateOidcClientSecret(app.kc_id);
}

// Starts "Test connection" and returns the URL to open in a browser: a person signs in there as a
// test user, and the run is recorded when Keycloak sends them back to siteUrl.
export async function startAppTest(actor, app, siteUrl) {
  const client = await loadClient(app);
  if (app.protocol === 'oidc') {
    const redirectUri = testOidcRedirectUriFor(siteUrl);
    // Clients registered before this domain was added to the profile don't accept its redirect URI yet.
    if (!client.rep.redirectUris?.includes(redirectUri)) await updateOidcClient(app.kc_id, client.values, app.owner);
    return startOidcTest({ app, values: client.values, startedBy: actor.username, redirectUri });
  }
  if (client.values.clientSignature) {
    throw new ServiceError(400, 'signed_requests_required', 'This client requires signed requests, which only your app can create. Use the IdP-initiated link instead, or turn off "Require signed requests" while testing.');
  }
  const acsUrl = testAcsUrlFor(siteUrl);
  // Clients registered before this domain was added to the profile don't accept its test ACS yet.
  if (!client.rep.redirectUris?.includes(acsUrl)) await updateSamlClient(app.kc_id, client.values, app.owner);
  return startTest({ app, values: client.values, startedBy: actor.username, acsUrl });
}

// The sandbox realm as a SAML identity provider.
export async function idpInfo() {
  let certs = [];
  try { certs = await loadIdpCerts(config.sandbox.descriptorUrl); } catch { /* shown as unavailable */ }
  return {
    realm: config.sandbox.realm,
    entityId: config.sandbox.realmUrl,
    ssoUrl: config.sandbox.samlEndpoint,
    sloUrl: config.sandbox.samlEndpoint,
    metadataUrl: config.sandbox.descriptorUrl,
    cert: certs[0] || null,
    certPem: certs[0] ? certToPem(certs[0]) : null,
  };
}

