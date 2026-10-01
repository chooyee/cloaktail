import express from 'express';
import { config } from '../config.js';
import { KeycloakError } from '../lib/keycloakAdmin.js';
import { loadIdpCerts } from '../lib/idpCerts.js';
import {
  NAME_ID_FORMATS, USER_ATTRIBUTES, ATTRIBUTE_NAME_FORMATS,
  defaultAppValues, parseAppForm, validateApp, valuesFromMetadata,
  createSamlClient, updateSamlClient, loadSamlClient, deleteSamlClient, idpInitiatedUrl,
} from '../lib/samlClients.js';
import { startTest, finishTest } from '../lib/samlTest.js';
import {
  listApps, countApps, getApp, insertApp, renameApp, deleteApp, listTestRuns, getTestRun, insertTestRun, countTestUsers,
} from '../db.js';
import { requirePermission, redirect, isHtmx, sendError } from '../middleware.js';

export const appsRouter = express.Router();

const formOptions = { NAME_ID_FORMATS, USER_ATTRIBUTES, ATTRIBUTE_NAME_FORMATS, testAcsUrl: config.sandbox.testAcsUrl };
const canCreate = (req) => req.can('apps.own');

// Owners manage their own apps; apps.view_all / apps.manage_all extend that to everyone's.
async function loadApp(req, res, { write = false } = {}) {
  const app = await getApp(Number(req.params.id));
  const own = app && app.owner === req.user.username && req.can('apps.own');
  if (app && (own || req.can(write ? 'apps.manage_all' : 'apps.view_all'))) return app;
  sendError(req, res, 404, 'Application not found.');
  return null;
}

// Keycloak can lose a client (deleted in the admin console); surface that clearly.
async function loadClientOr404(req, res, app) {
  try {
    return await loadSamlClient(app.kc_id);
  } catch (err) {
    if (err instanceof KeycloakError && err.status === 404) {
      sendError(req, res, 404, `The Keycloak client for "${app.name}" no longer exists in realm ${config.sandbox.realm}. Delete this application and register it again.`);
      return null;
    }
    throw err;
  }
}

async function idpInfo() {
  let certs = [];
  try { certs = await loadIdpCerts(config.sandbox.descriptorUrl); } catch { /* shown as unavailable */ }
  return {
    realm: config.sandbox.realm,
    entityId: config.sandbox.realmUrl,
    ssoUrl: config.sandbox.samlEndpoint,
    sloUrl: config.sandbox.samlEndpoint,
    metadataUrl: config.sandbox.descriptorUrl,
    cert: certs[0] || null,
  };
}

// ---------- list ----------

appsRouter.get('/', async (req, res) => {
  const showAll = req.can('apps.view_all') && (req.query.all === '1' || !req.can('apps.own'));
  if (!showAll && !req.can('apps.own')) return sendError(req, res, 403, 'You do not have permission to do that.');
  const [apps, ownCount] = await Promise.all([
    showAll ? listApps() : listApps({ owner: req.user.username }),
    countApps(req.user.username),
  ]);
  res.render('pages/apps/list', {
    title: 'Applications',
    apps,
    showAll,
    ownCount,
    maxApps: config.sandbox.maxAppsPerDeveloper,
  });
});

// ---------- create ----------

async function renderNew(req, res, values, error, status = 200) {
  const quotaReached = await countApps(req.user.username) >= config.sandbox.maxAppsPerDeveloper;
  res.status(isHtmx(req) ? 200 : status).render('pages/apps/form', {
    title: 'Register application', app: null, values, error, isNew: true, ...formOptions,
    quotaReached,
    maxApps: config.sandbox.maxAppsPerDeveloper,
  });
}

appsRouter.get('/new', requirePermission('apps.own'), (req, res) => renderNew(req, res, defaultAppValues(), null));

// Pre-fills the form from pasted SP metadata; nothing is created until the developer submits.
appsRouter.post('/import', requirePermission('apps.own'), async (req, res) => {
  const xml = (req.body.metadata || '').trim();
  if (!xml.startsWith('<')) return renderNew(req, res, defaultAppValues(), 'Paste your SP metadata XML (it starts with <EntityDescriptor …>).', 422);
  try {
    const values = await valuesFromMetadata(xml);
    await renderNew(req, res, values, null);
  } catch (err) {
    if (err instanceof KeycloakError && err.status < 500) {
      return renderNew(req, res, defaultAppValues(), `Keycloak could not read that metadata: ${err.message}`, 422);
    }
    throw err;
  }
});

appsRouter.post('/', requirePermission('apps.own'), async (req, res) => {
  const values = parseAppForm(req.body);
  if (await countApps(req.user.username) >= config.sandbox.maxAppsPerDeveloper) {
    return renderNew(req, res, values, `You have reached the limit of ${config.sandbox.maxAppsPerDeveloper} applications. Delete one first.`, 422);
  }
  const error = validateApp(values, { isNew: true });
  if (error) return renderNew(req, res, values, error, 422);

  let kcId;
  try {
    kcId = await createSamlClient(values, req.user.username);
  } catch (err) {
    if (err instanceof KeycloakError && err.status === 409) {
      return renderNew(req, res, values, `Entity ID "${values.clientId}" is already registered. Choose a different one.`, 422);
    }
    if (err instanceof KeycloakError && err.status < 500) return renderNew(req, res, values, err.message, 422);
    throw err;
  }
  const id = await insertApp({ owner: req.user.username, kcId, clientId: values.clientId, name: values.name });
  redirect(req, res, `/apps/${id}?created=1`);
});

// ---------- detail ----------

appsRouter.get('/:id', async (req, res) => {
  const app = await loadApp(req, res);
  if (!app) return;
  const client = await loadClientOr404(req, res, app);
  if (!client) return;
  const [idp, runs, testUserCount] = await Promise.all([
    idpInfo(), listTestRuns(app.id), countTestUsers(req.user.username),
  ]);
  res.render('pages/apps/detail', {
    title: app.name,
    app,
    values: client.values,
    enabled: client.rep.enabled,
    idpInitiatedUrl: idpInitiatedUrl(client.rep),
    idp,
    runs,
    testUserCount,
    canEdit: app.owner === req.user.username ? req.can('apps.own') : req.can('apps.manage_all'),
    created: 'created' in req.query,
    NAME_ID_FORMATS,
  });
});

// ---------- edit ----------

function renderEdit(req, res, app, values, locals = {}) {
  res.render('pages/apps/form', {
    title: `Edit ${app.name}`, app, values, isNew: false, error: null, message: null, ...formOptions, ...locals,
  });
}

appsRouter.get('/:id/edit', async (req, res) => {
  const app = await loadApp(req, res, { write: true });
  if (!app) return;
  const client = await loadClientOr404(req, res, app);
  if (!client) return;
  renderEdit(req, res, app, client.values);
});

appsRouter.post('/:id', async (req, res) => {
  const app = await loadApp(req, res, { write: true });
  if (!app) return;
  const values = { ...parseAppForm(req.body), clientId: app.client_id };
  const error = validateApp(values, { isNew: false });
  if (error) return renderEdit(req, res, app, values, { error });
  try {
    await updateSamlClient(app.kc_id, values, app.owner);
  } catch (err) {
    if (err instanceof KeycloakError && err.status < 500) return renderEdit(req, res, app, values, { error: err.message });
    throw err;
  }
  await renameApp(app.id, values.name);
  renderEdit(req, res, { ...app, name: values.name }, values, { message: 'Saved. Keycloak uses the new settings on the next login.' });
});

// ---------- delete ----------

appsRouter.post('/:id/delete', async (req, res) => {
  const app = await loadApp(req, res, { write: true });
  if (!app) return;
  await deleteSamlClient(app.kc_id);
  await deleteApp(app.id);
  redirect(req, res, '/apps');
});

// ---------- test connection ----------

appsRouter.post('/:id/test', async (req, res) => {
  const app = await loadApp(req, res);
  if (!app) return;
  const client = await loadClientOr404(req, res, app);
  if (!client) return;
  if (client.values.clientSignature) {
    return sendError(req, res, 400, 'This client requires signed requests, which only your app can create. Use the IdP-initiated link instead, or turn off "Require signed requests" while testing.');
  }
  const url = await startTest({ app, values: client.values, startedBy: req.user.username });
  redirect(req, res, url);
});

appsRouter.get('/:id/tests/:runId', async (req, res) => {
  const app = await loadApp(req, res);
  if (!app) return;
  const run = await getTestRun(Number(req.params.runId));
  if (!run || run.app_id !== app.id) return sendError(req, res, 404, 'Test run not found.');
  res.render('pages/apps/test-result', { title: `Test · ${app.name}`, app, run });
});

// Keycloak posts the test SAML Response here (cross-site, so no session cookie and no CSRF token;
// the response itself is authenticated by its XML signature and the RelayState nonce).
export const testAcsRouter = express.Router();

testAcsRouter.post('/saml/test/acs', async (req, res) => {
  const outcome = await finishTest(req.body);
  if (!outcome) {
    return sendError(req, res, 400, 'This test has expired or was already used. Start the test again from the application page.');
  }
  const runId = await insertTestRun(outcome);
  res.redirect(303, `/apps/${outcome.appId}/tests/${runId}`);
});
