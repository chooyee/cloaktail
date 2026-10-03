import crypto from 'node:crypto';
import express from 'express';
import { currentProfileId } from '../config.js';
import { sandboxAdmin, KeycloakError } from '../lib/keycloakAdmin.js';
import { decodeJwt, verifyJwtSignature, verifyJwtWithPublicKey, verifyJwtHs256, signJwtHs256 } from '../lib/jwt.js';
import {
  MIGRATION_ATTRIBUTES, findMigrationClient, getMigrationClient, isSameMigratedUser, newUserRequiredActions,
} from '../migrationClients.js';
import { startMigrationEvent, finishMigrationEvent } from '../db.js';

// User migration (see migrationClients.js and the README). The flow:
//   1. The application sends the user to /migrate/start with a signed request (GET ?request= or a
//      form POST), saying who they are and where to send them back.
//   2. CloakTail checks it, keeps it in the session and shows /migrate: the profile, read-only, and
//      a new password.
//   3. On submit it creates the user in the profile's sandbox realm, then sends the user back to the
//      return URL with a signed result (?result=). A user CloakTail already migrated is sent back at
//      once, without asking for a password again.

export const migrateRouter = express.Router();

const REQUEST_MAX_AGE_S = 10 * 60; // longest lifetime (exp - iat) a request may have
const CLOCK_SKEW_S = 60;
const SESSION_MS = 30 * 60 * 1000; // time the user has to choose a password
const RESULT_TTL_S = 5 * 60;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Keycloak lowercases usernames; reject only what it can't store.
const USERNAME_RE = /^[^\s\x00-\x1f\x7f]{1,255}$/;

// Per-IP limits (in memory; use a shared store behind a load balancer).
const WINDOW_MS = 15 * 60 * 1000;
function limiter(max) {
  const attempts = new Map();
  return (ip) => {
    const now = Date.now();
    const recent = (attempts.get(ip) || []).filter((t) => now - t < WINDOW_MS);
    recent.push(now);
    attempts.set(ip, recent);
    return recent.length > max;
  };
}
const startLimited = limiter(30);
const submitLimited = limiter(10);

migrateRouter.use((req, res, next) => {
  // Pages carry personal data and one-time state; the start URL may carry the request token.
  res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  // Anonymous visitors need a session-bound CSRF token for the form.
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

// These pages are for other applications' users: not the portal's marketing description.
const DESCRIPTION = 'Set up your new sign-in.';

const renderMessage = (res, status, heading, message, { appName = null } = {}) =>
  res.status(status).render('pages/migrate/message', {
    title: heading, description: DESCRIPTION, heading, message, appName, bare: true,
  });

// A request that can't be trusted (bad signature, unknown client...) never leads anywhere: the
// return URL in it is unverified. The details go to the server log, not the page.
function rejectRequest(req, res, reason) {
  console.warn(`[migrate] rejected request from ${req.ip}: ${reason}`);
  renderMessage(res, 400, 'This link can’t be used',
    'The application sent an invalid or expired request. Go back to the application and sign in again. If this keeps happening, contact its support.');
}

// ---------- results ----------

// Sends the user back to the application with a signed result.
function sendBack(req, res, client, migration, { status, keycloakId = null, detail = null }) {
  const now = Math.floor(Date.now() / 1000);
  const result = signJwtHs256({
    iss: `${req.siteUrl}/migrate`,
    aud: client.clientId,
    sub: migration.legacyId,
    iat: now,
    exp: now + RESULT_TTL_S,
    jti: crypto.randomUUID(),
    request_jti: migration.jti,
    status,
    preferred_username: migration.username,
    ...(keycloakId ? { keycloak_id: keycloakId } : {}),
    ...(migration.state ? { state: migration.state } : {}),
    ...(detail ? { error_description: detail } : {}),
  }, client.secrets.clientSecret);
  const url = new URL(migration.returnUrl);
  url.searchParams.set('result', result);
  delete req.session.migration;
  res.redirect(303, url.toString());
}

async function finish(req, res, client, migration, outcome) {
  await finishMigrationEvent({
    clientPk: client.id, jti: migration.jti, status: outcome.status, keycloakId: outcome.keycloakId, detail: outcome.log ?? outcome.detail,
  });
  console.log(`[migrate] ${client.clientId}: ${migration.username} (legacy ${migration.legacyId}) ${outcome.status}`);
  sendBack(req, res, client, migration, outcome);
}

// ---------- 1. the application's request ----------

async function verifySignature(jwt, client) {
  const { requestKey, publicKey, jwksUrl } = client.settings;
  if (requestKey === 'secret') return verifyJwtHs256(jwt, client.secrets.clientSecret);
  if (requestKey === 'publicKey') return verifyJwtWithPublicKey(jwt, crypto.createPublicKey(publicKey));
  return verifyJwtSignature(jwt, jwksUrl);
}

const optionalString = (value, max) => (value === undefined || value === null || value === '' ? ''
  : typeof value === 'string' && value.length <= max ? value : null);

// Returns { migration, client } or { error } (for the log).
async function readRequest(req, token) {
  const jwt = decodeJwt(token);
  if (!jwt) return { error: 'not a signed JWT' };
  const claims = jwt.payload;
  const client = await findMigrationClient(currentProfileId(), claims.iss);
  if (!client) return { error: `unknown client ${JSON.stringify(claims.iss)}` };
  if (!client.enabled) return { error: `client ${client.clientId} is disabled` };
  if (client.secretsUnreadable) return { error: `the secrets of client ${client.clientId} can't be decrypted (SETTINGS_KEY changed?)` };
  try {
    await verifySignature(jwt, client);
  } catch (err) {
    return { error: `${client.clientId}: ${err.message}` };
  }

  // Signed by the client; now check it is meant for us, fresh and complete.
  const audience = `${req.siteUrl}/migrate`;
  const now = Math.floor(Date.now() / 1000);
  const fail = (why) => ({ error: `${client.clientId}: ${why}` });
  if (![].concat(claims.aud).includes(audience)) return fail(`aud must be ${audience}`);
  if (!Number.isInteger(claims.exp) || !Number.isInteger(claims.iat)) return fail('exp and iat are required');
  if (claims.exp < now - CLOCK_SKEW_S) return fail('expired');
  if (claims.iat > now + CLOCK_SKEW_S) return fail('iat is in the future');
  if (claims.exp - claims.iat > REQUEST_MAX_AGE_S) return fail(`lifetime (exp - iat) over ${REQUEST_MAX_AGE_S} seconds`);
  if (typeof claims.jti !== 'string' || !claims.jti || claims.jti.length > 200) return fail('jti is required');
  if (typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 255) return fail('sub (legacy user id) is required');
  if (typeof claims.preferred_username !== 'string' || !USERNAME_RE.test(claims.preferred_username)) return fail('preferred_username is missing or invalid');
  if (!client.settings.returnUrls.includes(claims.return_url)) return fail(`return_url ${JSON.stringify(claims.return_url)} is not registered`);

  const email = optionalString(claims.email, 254);
  const firstName = optionalString(claims.given_name, 100);
  const lastName = optionalString(claims.family_name, 100);
  const state = optionalString(claims.state, 500);
  if ([email, firstName, lastName, state].includes(null)) return fail('email, given_name, family_name or state is not a short string');
  if (email && !EMAIL_RE.test(email)) return fail('email is not an email address');

  return {
    client,
    migration: {
      clientPk: client.id,
      jti: claims.jti,
      legacyId: claims.sub,
      username: claims.preferred_username.toLowerCase(),
      email,
      firstName,
      lastName,
      returnUrl: claims.return_url,
      state,
      expiresAt: Date.now() + SESSION_MS,
    },
  };
}

async function start(req, res) {
  if (startLimited(req.ip)) return renderMessage(res, 429, 'Too many attempts', 'Too many requests from your network. Try again in 15 minutes.');
  const token = req.method === 'POST' ? req.body.request : req.query.request;
  const { error, client, migration } = await readRequest(req, typeof token === 'string' ? token : '');
  if (error) return rejectRequest(req, res, error);

  // Each request id only once, so a request copied from a log or history can't be replayed.
  if (!(await startMigrationEvent({ clientPk: client.id, jti: migration.jti, legacyId: migration.legacyId, username: migration.username, ip: req.ip }))) {
    return rejectRequest(req, res, `${client.clientId}: request ${migration.jti} was already used`);
  }

  // Someone with this username already? If it is this user, migrated before, there is nothing to do.
  let existing;
  try {
    [existing] = await sandboxAdmin.findUsersExact({ username: migration.username });
  } catch (err) {
    console.error(`[migrate] ${client.clientId}: looking up ${migration.username} failed:`, err.message);
    await finishMigrationEvent({ clientPk: client.id, jti: migration.jti, status: 'error', detail: err.message });
    return renderMessage(res, 503, 'Try again later', 'Your account can’t be moved right now. Go back to the application and try again in a few minutes.',
      { appName: client.name });
  }
  if (existing) {
    return isSameMigratedUser(existing, client, migration.legacyId)
      ? finish(req, res, client, migration, { status: 'already_migrated', keycloakId: existing.id })
      : finish(req, res, client, migration, {
        status: 'conflict', detail: 'A different account already uses this username.', log: `username taken by ${existing.id}`,
      });
  }

  req.session.migration = migration;
  // A clean URL: the token leaves the address bar and history.
  req.session.save((err) => (err ? res.status(500).end() : res.redirect(303, '/migrate')));
}

migrateRouter.get('/start', start);
migrateRouter.post('/start', start);

// ---------- 2. the page ----------

// The migration in this session and its client; otherwise renders why not and returns {}.
async function load(req, res) {
  const migration = req.session.migration;
  if (!migration) {
    renderMessage(res, 400, 'Nothing to do here',
      'This page is opened by an application that is moving your account. Go back to the application and sign in again.');
    return {};
  }
  const client = await getMigrationClient(currentProfileId(), migration.clientPk);
  if (!client || !client.enabled || client.secretsUnreadable) {
    delete req.session.migration;
    renderMessage(res, 503, 'Account moves are paused', 'Moving accounts for this application isn’t available right now. Try again later.');
    return {};
  }
  if (Date.now() > migration.expiresAt) {
    await finish(req, res, client, migration, { status: 'expired', detail: 'The user took too long to choose a password.' });
    return {};
  }
  return { client, migration };
}

const render = (res, client, migration, { error = null, field = null } = {}) =>
  res.status(error ? 422 : 200).render('pages/migrate/form', {
    title: `Set up your new sign-in for ${client.name}`,
    description: DESCRIPTION,
    bare: true,
    appName: client.name,
    requireOtp: client.settings.requireOtp,
    migration,
    error,
    field,
  });

migrateRouter.get('/', async (req, res) => {
  const { client, migration } = await load(req, res);
  if (client) render(res, client, migration);
});

// Keycloak's messages don't say which field failed; only the password is on the form.
const fieldForKeycloakError = (message) => (message.toLowerCase().includes('password') ? 'password' : null);

// ---------- 3. creating the user ----------

migrateRouter.post('/', async (req, res) => {
  const { client, migration } = await load(req, res);
  if (!client) return;
  const password = String(req.body.password ?? '');
  const fail = (error, field = null) => render(res, client, migration, { error, field });

  if (submitLimited(req.ip)) return fail('Too many attempts. Try again in 15 minutes.');
  if (password.length < 8) return fail('Use at least 8 characters.', 'password');
  if (password.length > 256) return fail('Use at most 256 characters.', 'password');
  if (password !== req.body.confirmPassword) return fail('The passwords don’t match.', 'confirmPassword');

  let keycloakId;
  try {
    // The profile is exactly what the application sent. Emails are not verified (no email is sent).
    keycloakId = await sandboxAdmin.createUser({
      username: migration.username,
      email: migration.email,
      firstName: migration.firstName,
      lastName: migration.lastName,
      emailVerified: false,
      password,
      temporary: false,
      requiredActions: newUserRequiredActions(client),
      attributes: {
        [MIGRATION_ATTRIBUTES.legacyId]: [migration.legacyId],
        [MIGRATION_ATTRIBUTES.migratedFrom]: [client.clientId],
        [MIGRATION_ATTRIBUTES.migratedAt]: [new Date().toISOString()],
      },
    });
  } catch (err) {
    if (!(err instanceof KeycloakError)) throw err;
    if (err.status === 409) return conflict(req, res, client, migration, err.message);
    // 400: the realm's password policy (or user profile rules, which the user can't fix here).
    if (err.status === 400 && fieldForKeycloakError(err.message)) return fail(err.message, 'password');
    console.error(`[migrate] ${client.clientId}: creating ${migration.username} failed:`, err.message);
    if (err.status === 400) {
      return finish(req, res, client, migration, { status: 'error', detail: 'Keycloak rejected the account details.', log: `Keycloak: ${err.message}` });
    }
    return fail('Your account couldn’t be set up just now. Try again in a moment.');
  }
  await finish(req, res, client, migration, { status: 'created', keycloakId });
});

// Username or email taken. It may be this same user (a double submit, or a lost response), who is
// then already migrated; a different account is a conflict for an administrator to resolve.
async function conflict(req, res, client, migration, message) {
  const [byUsername] = await sandboxAdmin.findUsersExact({ username: migration.username });
  if (byUsername && isSameMigratedUser(byUsername, client, migration.legacyId)) {
    return finish(req, res, client, migration, { status: 'already_migrated', keycloakId: byUsername.id });
  }
  return finish(req, res, client, migration, {
    status: 'conflict',
    detail: 'A different account already uses this username or email address.',
    log: `Keycloak: ${message}`,
  });
}

migrateRouter.post('/cancel', async (req, res) => {
  const { client, migration } = await load(req, res);
  if (client) await finish(req, res, client, migration, { status: 'cancelled' });
});
