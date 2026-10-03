import express from 'express';
import { config } from '../config.js';
import { NAME_ID_FORMATS, NAME_ID_FORMAT_URNS, ATTRIBUTE_NAME_FORMAT_URNS, ENCRYPTION_KEY_ALGORITHMS, defaultAppValues, idpInitiatedUrl } from '../lib/samlClients.js';
import { getOidcClientSecret } from '../lib/oidcClients.js';
import { finishTest } from '../lib/samlTest.js';
import { samlSamples, oidcSamples, migrationSamples } from '../lib/codeSamples.js';
import {
  MIGRATION_ATTRIBUTES, REQUEST_KEYS, getAppMigration, defaultMigrationValues, migrationValues, parseMigrationForm,
  saveAppMigration, regenerateMigrationSecret, migrationWarnings,
} from '../lib/userMigration.js';
import { finishOidcTest } from '../lib/oidcTest.js';
import {
  countApps, listTestRuns, getTestRun, insertTestRun, countTestUsers, listMigrationEvents, countMigrationEvents,
} from '../db.js';
import {
  PROTOCOL, protocolOf, canEditApp, findApp, listAppsFor, loadClient, createApp, updateApp, removeApp,
  samlValuesFromMetadata, rotateAppClientSecret, startAppTest, idpInfo,
} from '../services/apps.js';
import { ServiceError } from '../services/errors.js';
import { requirePermission, redirect, isHtmx, sendError, actorOf } from '../middleware.js';

export const appsRouter = express.Router();

// An application is a SAML or an OpenID Connect client in the sandbox realm (services/apps.js).

async function loadApp(req, res, { write = false } = {}) {
  const app = await findApp(actorOf(req), req.params.id, { write });
  if (!app) sendError(req, res, 404, 'Application not found.');
  return app;
}

// Keycloak can lose a client (deleted in the admin console); surface that clearly.
async function loadClientOr404(req, res, app) {
  try {
    return await loadClient(app);
  } catch (err) {
    if (!(err instanceof ServiceError)) throw err;
    sendError(req, res, err.status, err.message);
    return null;
  }
}

// ---------- list ----------

appsRouter.get('/', async (req, res) => {
  const showAll = req.can('apps.view_all') && (req.query.all === '1' || !req.can('apps.own'));
  if (!showAll && !req.can('apps.own')) return sendError(req, res, 403, 'You do not have permission to do that.');
  const [apps, ownCount] = await Promise.all([
    listAppsFor(actorOf(req), { all: showAll }),
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

async function renderNew(req, res, protocol, values, error, status = 200) {
  const p = PROTOCOL[protocol];
  const quotaReached = await countApps(req.user.username) >= config.sandbox.maxAppsPerDeveloper;
  res.status(isHtmx(req) ? 200 : status).render(p.form, {
    title: 'Register application', app: null, values, error, isNew: true, protocol, ...p.formOptions,
    testUrl: p.testUrl(req.siteUrl),
    quotaReached,
    maxApps: config.sandbox.maxAppsPerDeveloper,
  });
}

appsRouter.get('/new', requirePermission('apps.own'), (req, res) => {
  const protocol = protocolOf(req.query.protocol);
  renderNew(req, res, protocol, PROTOCOL[protocol].defaults(), null);
});

// Pre-fills the SAML form from pasted SP metadata; nothing is created until the developer submits.
appsRouter.post('/import', requirePermission('apps.own'), async (req, res) => {
  let values;
  try {
    values = await samlValuesFromMetadata(req.body.metadata);
  } catch (err) {
    if (err instanceof ServiceError) return renderNew(req, res, 'saml', defaultAppValues(), err.message, 422);
    throw err;
  }
  await renderNew(req, res, 'saml', values, null);
});

appsRouter.post('/', requirePermission('apps.own'), async (req, res) => {
  const protocol = protocolOf(req.body.protocol);
  const values = PROTOCOL[protocol].parse(req.body);
  let id;
  try {
    id = await createApp(actorOf(req), protocol, values);
  } catch (err) {
    if (err instanceof ServiceError) return renderNew(req, res, protocol, values, err.message, 422);
    throw err;
  }
  redirect(req, res, `/apps/${id}?created=1`);
});

// ---------- detail ----------

appsRouter.get('/:id', async (req, res) => {
  const app = await loadApp(req, res);
  if (!app) return;
  const client = await loadClientOr404(req, res, app);
  if (!client) return;
  const canEdit = canEditApp(actorOf(req), app);
  const [runs, testUserCount, migration, migrationCounts] = await Promise.all([
    listTestRuns(app.id), countTestUsers(req.user.username), getAppMigration(app.id), countMigrationEvents(app.id),
  ]);
  const common = {
    migration,
    migrationCounts,
    title: app.name,
    app,
    values: client.values,
    enabled: client.rep.enabled,
    runs,
    testUserCount,
    canEdit,
    created: 'created' in req.query,
  };
  if (app.protocol === 'oidc') {
    // The secret is only shown to those who may change the client.
    const secret = canEdit && client.values.clientType === 'confidential' ? await getOidcClientSecret(app.kc_id) : null;
    if (secret) res.set('Cache-Control', 'no-store');
    const op = { realm: config.sandbox.realm, ...config.sandbox.oidc };
    return res.render('pages/apps/oidc-detail', {
      ...common,
      op,
      codeSamples: oidcSamples({ clientId: app.client_id, values: client.values, op }),
      secret,
      secretRegenerated: 'secret' in req.query,
    });
  }
  const idp = await idpInfo();
  res.render('pages/apps/detail', {
    ...common,
    idpInitiatedUrl: idpInitiatedUrl(client.rep),
    idp,
    codeSamples: samlSamples({ values: client.values, idp }),
    NAME_ID_FORMATS,
    NAME_ID_FORMAT_URNS,
    ATTRIBUTE_NAME_FORMAT_URNS,
    ENCRYPTION_KEY_ALGORITHMS,
  });
});

// ---------- edit ----------

function renderEdit(req, res, app, values, locals = {}) {
  const p = PROTOCOL[app.protocol];
  res.render(p.form, {
    title: `Edit ${app.name}`, app, values, isNew: false, protocol: app.protocol, error: null, message: null, ...p.formOptions,
    testUrl: p.testUrl(req.siteUrl), ...locals,
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
  const values = PROTOCOL[app.protocol].parse(req.body);
  try {
    await updateApp(app, values);
  } catch (err) {
    if (err instanceof ServiceError) return renderEdit(req, res, app, values, { error: err.message });
    throw err;
  }
  renderEdit(req, res, { ...app, name: values.name }, values, { message: 'Saved. Keycloak uses the new settings on the next login.' });
});

// A new client secret for a confidential OIDC client; the old one stops working at once.
appsRouter.post('/:id/secret', async (req, res) => {
  const app = await loadApp(req, res, { write: true });
  if (!app) return;
  if (app.protocol !== 'oidc') return sendError(req, res, 400, 'Only OpenID Connect clients have a client secret.');
  await rotateAppClientSecret(app);
  redirect(req, res, `/apps/${app.id}?secret`);
});

// ---------- user migration ----------
// The application sends its not-yet-migrated users to /migrate (routes/migrate.js); here its
// developer sets that up and reads how to do the redirect.

async function renderMigration(req, res, app, { status = 200, values = null, errors = {}, message = null } = {}) {
  const migration = await getAppMigration(app.id);
  const canEdit = canEditApp(actorOf(req), app);
  const settings = migration?.settings;
  const migrateUrl = `${req.siteUrl}/migrate`;
  const [events, counts, warnings] = await Promise.all([
    listMigrationEvents(app.id),
    countMigrationEvents(app.id),
    migrationWarnings(migration),
  ]);
  // The migration secret is only shown to those who may change the application.
  if (canEdit && migration) res.set('Cache-Control', 'no-store');
  res.status(status).render('pages/apps/migration', {
    title: `User migration · ${app.name}`,
    app,
    migration,
    canEdit,
    secret: canEdit && migration && !migration.secretUnreadable ? migration.secret : null,
    values: values ?? (migration ? migrationValues(migration) : defaultMigrationValues()),
    errors,
    message,
    REQUEST_KEYS,
    MIGRATION_ATTRIBUTES,
    migrateUrl,
    sandboxRealm: config.sandbox.realm,
    events,
    counts,
    warnings,
    samples: migrationSamples({
      clientId: app.client_id,
      migrateUrl,
      returnUrl: settings?.returnUrls[0] || 'https://myapp.example.com/migrated',
      requestKey: settings?.requestKey || 'secret',
      requireOtp: settings?.requireOtp ?? true,
    }),
  });
}

appsRouter.get('/:id/migration', async (req, res) => {
  const app = await loadApp(req, res);
  if (!app) return;
  const message = 'secret' in req.query ? 'New migration secret created. The old one stopped working: update your application now.' : null;
  await renderMigration(req, res, app, { message });
});

appsRouter.post('/:id/migration', async (req, res) => {
  const app = await loadApp(req, res, { write: true });
  if (!app) return;
  const existing = await getAppMigration(app.id);
  const values = parseMigrationForm(req.body);
  const { errors } = await saveAppMigration(app, values, existing, req.user.username);
  if (Object.keys(errors).length) return renderMigration(req, res, app, { status: 422, values, errors });
  await renderMigration(req, res, app, {
    message: existing ? 'Saved. It applies to new requests at once.' : 'User migration is set up. Copy the migration secret into your application’s configuration.',
  });
});

appsRouter.post('/:id/migration/secret', async (req, res) => {
  const app = await loadApp(req, res, { write: true });
  if (!app) return;
  const migration = await getAppMigration(app.id);
  if (!migration) return sendError(req, res, 400, 'Set up user migration first.');
  await regenerateMigrationSecret(app, migration, req.user.username);
  redirect(req, res, `/apps/${app.id}/migration?secret`);
});

// ---------- delete ----------

appsRouter.post('/:id/delete', async (req, res) => {
  const app = await loadApp(req, res, { write: true });
  if (!app) return;
  await removeApp(app);
  redirect(req, res, '/apps');
});

// ---------- test connection ----------

appsRouter.post('/:id/test', async (req, res) => {
  const app = await loadApp(req, res);
  if (!app) return;
  let url;
  try {
    url = await startAppTest(actorOf(req), app, req.siteUrl);
  } catch (err) {
    if (err instanceof ServiceError) return sendError(req, res, err.status, err.message);
    throw err;
  }
  redirect(req, res, url);
});

appsRouter.get('/:id/tests/:runId', async (req, res) => {
  const app = await loadApp(req, res);
  if (!app) return;
  const run = await getTestRun(Number(req.params.runId));
  if (!run || run.app_id !== app.id) return sendError(req, res, 404, 'Test run not found.');
  const view = run.result.protocol === 'oidc' ? 'pages/apps/oidc-test-result' : 'pages/apps/test-result';
  res.render(view, { title: `Test · ${app.name}`, app, run });
});

// Where Keycloak returns test logins: cross-site, so no session cookie (SAML) and no CSRF token.
// Each response is authenticated by its own means: the XML signature and RelayState nonce (SAML),
// or the state, PKCE verifier and client credentials of the code exchange (OIDC).
export const testAcsRouter = express.Router();

async function recordTest(req, res, outcome) {
  if (!outcome) {
    return sendError(req, res, 400, 'This test has expired or was already used. Start the test again from the application page.');
  }
  const runId = await insertTestRun(outcome);
  res.redirect(303, `/apps/${outcome.appId}/tests/${runId}`);
}

testAcsRouter.post('/saml/test/acs', async (req, res) => recordTest(req, res, await finishTest(req.body)));

testAcsRouter.get('/oidc/test/callback', async (req, res) => {
  // The authorization code is single-use and short-lived; keep it out of the browser history.
  res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  await recordTest(req, res, await finishOidcTest(req.query));
});
