import express from 'express';
import { config } from '../config.js';
import {
  listTestUsersWithDetails, findOwnTestUser, createTestUser, setTestUserPassword, removeTestUser,
} from '../services/testUsers.js';
import { ServiceError } from '../services/errors.js';
import { requirePermission, sendError } from '../middleware.js';
import { listMigratedUsersForOwner, getApp, getMigratedUser, deleteMigratedUser } from '../db.js';
import { sandboxAdmin, KeycloakError } from '../lib/keycloakAdmin.js';

// Developers' own test accounts in the sandbox realm, used to sign in during "Test connection".
export const testUsersRouter = express.Router();
testUsersRouter.use(requirePermission('apps.own'));

const max = config.sandbox.maxTestUsersPerDeveloper;
const MIGRATED_SHOWN = 500;

async function renderPage(req, res, locals = {}) {
  const [users, migrated] = await Promise.all([
    listTestUsersWithDetails(req.user.username),
    // Users of the developer's applications who moved into the sandbox realm through /migrate.
    listMigratedUsersForOwner(req.user.username, MIGRATED_SHOWN + 1),
  ]);
  res.render('pages/test-users', {
    title: 'Test users',
    // Which tab is shown: the developer's own test accounts, or the users their applications migrated.
    view: req.query.view === 'migrated' ? 'migrated' : 'accounts',
    users,
    max,
    realm: config.sandbox.realm,
    migrated: migrated.slice(0, MIGRATED_SHOWN),
    migratedMore: migrated.length > MIGRATED_SHOWN,
    values: {},
    error: null,
    message: null,
    ...locals,
  });
}

async function loadOwn(req, res) {
  const row = await findOwnTestUser(req.user.username, req.params.id);
  if (row) return row;
  sendError(req, res, 404, 'Test user not found.');
  return null;
}

// Runs a service call; a refusal is shown on the page.
async function attempt(req, res, locals, fn) {
  try {
    await fn();
    return true;
  } catch (err) {
    if (!(err instanceof ServiceError)) throw err;
    await renderPage(req, res, { ...locals, error: err.message });
    return false;
  }
}

testUsersRouter.get('/', (req, res) => renderPage(req, res));

testUsersRouter.post('/', async (req, res) => {
  const values = {
    username: (req.body.username || '').trim().toLowerCase(),
    email: (req.body.email || '').trim(),
    firstName: (req.body.firstName || '').trim(),
    lastName: (req.body.lastName || '').trim(),
  };
  if (!await attempt(req, res, { values }, () => createTestUser(req.user.username, values, req.body.password || ''))) return;
  renderPage(req, res, { message: `Test user ${values.username} created.` });
});

testUsersRouter.post('/:id/password', async (req, res) => {
  const row = await loadOwn(req, res);
  if (!row) return;
  if (!await attempt(req, res, {}, () => setTestUserPassword(row, req.body.password || ''))) return;
  renderPage(req, res, { message: `Password for ${row.username} changed.` });
});

// ---------- migrated users of the developer's applications ----------

// The migration record of one of the developer's own applications; sends 404 otherwise.
async function loadOwnMigrated(req, res) {
  const app = await getApp(Number(req.body.appId));
  const record = app && app.owner === req.user.username && typeof req.body.sub === 'string'
    ? await getMigratedUser(app.id, req.body.sub) : null;
  if (record) return { app, record };
  sendError(req, res, 404, 'Migrated user not found.');
  return {};
}

// A user /migrate created: deletes their Keycloak account and the record, so the application can
// migrate them again. A user linked by hand to an account that existed before is only unlinked (see
// /unlink): that account may be someone else's, such as a test user.
testUsersRouter.post('/migrated/delete', async (req, res) => {
  const { app, record } = await loadOwnMigrated(req, res);
  if (!record) return;
  if (record.linked_by) return renderPage(req, res, { view: 'migrated', error: `${record.username} was linked by hand to an existing account. Unlink it instead; the account itself is kept.` });
  try {
    await sandboxAdmin.deleteUser(record.keycloak_id);
  } catch (err) {
    if (!(err instanceof KeycloakError && err.status === 404)) throw err;
  }
  await deleteMigratedUser(app.id, record.legacy_id);
  console.log(`[migrate] ${app.client_id}: ${req.user.username} deleted migrated user ${record.username} (legacy ${record.legacy_id}, ${record.keycloak_id})`);
  renderPage(req, res, { view: 'migrated', message: `Migrated user ${record.username} deleted from Keycloak. ${app.name} can migrate them again; clear its own migrated flag for them first.` });
});

// Forgets the link between the application's user and a Keycloak account, which stays as it is.
testUsersRouter.post('/migrated/unlink', async (req, res) => {
  const { app, record } = await loadOwnMigrated(req, res);
  if (!record) return;
  await deleteMigratedUser(app.id, record.legacy_id);
  console.log(`[migrate] ${app.client_id}: ${req.user.username} unlinked ${record.username} (legacy ${record.legacy_id}, ${record.keycloak_id})`);
  renderPage(req, res, { view: 'migrated', message: `${record.username} unlinked from ${app.name}. The Keycloak account is kept.` });
});

testUsersRouter.post('/:id/delete', async (req, res) => {
  const row = await loadOwn(req, res);
  if (!row) return;
  await removeTestUser(row);
  renderPage(req, res, { message: `Test user ${row.username} deleted.` });
});
