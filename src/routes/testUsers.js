import express from 'express';
import { config } from '../config.js';
import { sandboxAdmin, KeycloakError } from '../lib/keycloakAdmin.js';
import { listTestUsers, countTestUsers, getTestUser, insertTestUser, deleteTestUser } from '../db.js';
import { requirePermission, sendError } from '../middleware.js';

// Developers' own test accounts in the sandbox realm, used to sign in during "Test connection".
export const testUsersRouter = express.Router();
testUsersRouter.use(requirePermission('apps.own'));

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,39}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const max = config.sandbox.maxTestUsersPerDeveloper;

async function withKeycloakDetails(rows) {
  return Promise.all(rows.map(async (row) => {
    try {
      return { ...row, kc: await sandboxAdmin.getUser(row.kc_id) };
    } catch (err) {
      if (err instanceof KeycloakError && err.status === 404) return { ...row, kc: null };
      throw err;
    }
  }));
}

async function renderPage(req, res, locals = {}) {
  const users = await withKeycloakDetails(listTestUsers(req.user.username));
  res.render('pages/test-users', {
    title: 'Test users', users, max, realm: config.sandbox.realm, values: {}, error: null, message: null, ...locals,
  });
}

// Rows are only ever looked up for their owner.
function loadOwn(req, res) {
  const row = getTestUser(Number(req.params.id));
  if (row && row.owner === req.user.username) return row;
  sendError(req, res, 404, 'Test user not found.');
  return null;
}

testUsersRouter.get('/', (req, res) => renderPage(req, res));

testUsersRouter.post('/', async (req, res) => {
  const values = {
    username: (req.body.username || '').trim().toLowerCase(),
    email: (req.body.email || '').trim(),
    firstName: (req.body.firstName || '').trim(),
    lastName: (req.body.lastName || '').trim(),
  };
  const password = req.body.password || '';
  const fail = (error) => renderPage(req, res, { values, error });

  if (countTestUsers(req.user.username) >= max) return fail(`You have reached the limit of ${max} test users. Delete one first.`);
  if (!USERNAME_RE.test(values.username)) return fail('Username must be 3-40 characters: lowercase letters, digits, . _ -');
  if (!EMAIL_RE.test(values.email)) return fail('Enter a valid email address.');
  if (!values.firstName || !values.lastName) return fail('First and last name are required.');
  if (password.length < 8) return fail('Password must be at least 8 characters.');

  let kcId;
  try {
    kcId = await sandboxAdmin.createUser({ ...values, emailVerified: true, password, temporary: false });
  } catch (err) {
    if (err instanceof KeycloakError && err.status === 409) return fail('That username or email is already used in the sandbox. Try another.');
    if (err instanceof KeycloakError && err.status < 500) return fail(err.message);
    throw err;
  }
  insertTestUser({ owner: req.user.username, kcId, username: values.username });
  renderPage(req, res, { message: `Test user ${values.username} created.` });
});

testUsersRouter.post('/:id/password', async (req, res) => {
  const row = loadOwn(req, res);
  if (!row) return;
  const password = req.body.password || '';
  if (password.length < 8) return renderPage(req, res, { error: 'Password must be at least 8 characters.' });
  try {
    await sandboxAdmin.resetPassword(row.kc_id, password, false);
  } catch (err) {
    if (err instanceof KeycloakError && err.status < 500) return renderPage(req, res, { error: err.message });
    throw err;
  }
  renderPage(req, res, { message: `Password for ${row.username} changed.` });
});

testUsersRouter.post('/:id/delete', async (req, res) => {
  const row = loadOwn(req, res);
  if (!row) return;
  await sandboxAdmin.deleteUser(row.kc_id).catch((err) => {
    if (!(err instanceof KeycloakError && err.status === 404)) throw err;
  });
  deleteTestUser(row.id);
  renderPage(req, res, { message: `Test user ${row.username} deleted.` });
});
