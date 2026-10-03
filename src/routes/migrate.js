import crypto from 'node:crypto';
import express from 'express';
import { sandboxAdmin, KeycloakError } from '../lib/keycloakAdmin.js';
import { decodeJwt, verifyJwtSignature, verifyJwtWithPublicKey, verifyJwtHs256, signJwtHs256 } from '../lib/jwt.js';
import {
  MIGRATION_ATTRIBUTES, OTP_SETUP_ACTION, REQUEST_ERRORS, RESULT_STATUSES, getAppMigration, isSameMigratedUser,
} from '../lib/userMigration.js';
import {
  getApp, getAppByClientId, startMigrationEvent, finishMigrationEvent, recordRejectedMigration, migrationJtiUsed,
  getMigratedUser, putMigratedUser, deleteMigratedUser,
} from '../db.js';
import { migrationSpec } from '../lib/migrationSpec.js';
import { newTotpSecret, verifyTotp, manualKey, totpQrSvg, totpCredential } from '../lib/totp.js';

// User migration of developer applications (see lib/userMigration.js and the README). The flow:
//   1. The application sends the user to /migrate/start with a signed request (GET ?request= or a
//      form POST), saying who they are and where to send them back. Its iss is the app's client ID.
//   2. CloakTail checks it, keeps it in the session and shows /migrate: the profile, read-only, a
//      new password and, when the application requires OTP, a QR code for an authenticator app.
//   3. On submit it creates the user in the profile's sandbox realm, with the OTP credential so
//      Keycloak asks for no more setup at their first sign-in, then sends the user back to the
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
const codeLimited = limiter(30);

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
// return URL in it is unverified. The details go to the server log, not the page, and to the
// application's request history when the request names one, so its developer can see why.
async function rejectRequest(req, res, { code, message }, client = null) {
  console.warn(`[migrate] rejected request from ${req.ip}: ${client ? `${client.clientId}: ` : ''}${code}: ${message}`);
  if (client) await recordRejectedMigration({ appId: client.id, detail: `${code}: ${message}`, ip: req.ip });
  renderMessage(res, 400, 'This link can’t be used',
    'The application sent an invalid or expired request. Go back to the application and sign in again. If this keeps happening, contact its support.');
}

// ---------- results ----------

// The signed result for the application, and the URL that hands it over.
function resultFor(req, client, migration, { status, keycloakId = null, detail = null, simulated = false }) {
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
    ...(simulated ? { simulated: true } : {}),
  }, client.secret);
  const url = new URL(migration.returnUrl);
  url.searchParams.set('result', result);
  return { result, url: url.toString() };
}

// Sends the user back to the application with a signed result.
function sendBack(req, res, client, migration, outcome) {
  const { url } = resultFor(req, client, migration, outcome);
  delete req.session.migration;
  res.redirect(303, url);
}

async function finish(req, res, client, migration, outcome) {
  // Record who the user became: always for a new account; for already_migrated only when there is no
  // record yet (recognised by its Keycloak attributes), so a link or the original username is kept.
  const record = outcome.keycloakId && (outcome.status === 'created'
    || (outcome.status === 'already_migrated' && !(await getMigratedUser(client.id, migration.legacyId))));
  if (record) {
    await putMigratedUser({ appId: client.id, legacyId: migration.legacyId, keycloakId: outcome.keycloakId, username: migration.username });
  }
  await finishMigrationEvent({
    appId: client.id, jti: migration.jti, status: outcome.status, keycloakId: outcome.keycloakId, detail: outcome.log ?? outcome.detail,
  });
  console.log(`[migrate] ${client.clientId}: ${migration.username} (legacy ${migration.legacyId}) ${outcome.status}`);
  sendBack(req, res, client, migration, outcome);
}

// ---------- the application ----------

// A developer application with user migration set up, as the flow uses it; null otherwise.
async function clientFor(app) {
  const setup = app && await getAppMigration(app.id);
  if (!setup) return null;
  return {
    id: app.id,
    app,
    clientId: app.client_id,
    name: app.name,
    enabled: setup.enabled,
    settings: setup.settings,
    secret: setup.secret,
    secretUnreadable: setup.secretUnreadable,
  };
}

// The Keycloak user CloakTail recorded for this legacy user of the application, when it still
// exists; null otherwise (a record whose user was deleted in Keycloak is dropped). This record,
// not the user's attributes, decides "already migrated", so it works whatever the realm keeps.
async function recordedUser(client, legacyId) {
  const record = await getMigratedUser(client.id, legacyId);
  if (!record) return null;
  try {
    return { ...record, user: await sandboxAdmin.getUser(record.keycloak_id) };
  } catch (err) {
    if (!(err instanceof KeycloakError && err.status === 404)) throw err;
    await deleteMigratedUser(client.id, legacyId);
    return null;
  }
}

// The application a request names: its iss is the app's client ID, in this domain's profile.
const findClient = async (clientId) => (typeof clientId === 'string' && clientId ? clientFor(await getAppByClientId(clientId)) : null);

// ---------- 1. the application's request ----------

async function verifySignature(jwt, client) {
  const { requestKey, publicKey, jwksUrl } = client.settings;
  if (requestKey === 'secret') return verifyJwtHs256(jwt, client.secret);
  if (requestKey === 'publicKey') return verifyJwtWithPublicKey(jwt, crypto.createPublicKey(publicKey));
  return verifyJwtSignature(jwt, jwksUrl);
}

const optionalString = (value, max) => (value === undefined || value === null || value === '' ? ''
  : typeof value === 'string' && value.length <= max ? value : null);

const requestError = (code, message = REQUEST_ERRORS[code]) => ({ code, message });

// Returns { migration, client }, or { error: { code, message } } with the client when the request
// names one, and `verified` once its signature checked out. Doesn't look at whether migration is
// turned on (start() does) or whether the jti was used.
async function readRequest(req, token) {
  const jwt = decodeJwt(token);
  if (!jwt || typeof jwt.payload !== 'object' || !jwt.payload) return { error: requestError('malformed') };
  const claims = jwt.payload;
  const client = await findClient(claims.iss);
  if (!client) return { error: requestError('unknown_client', `${REQUEST_ERRORS.unknown_client} iss was ${JSON.stringify(claims.iss)}.`) };
  if (client.secretUnreadable) return { error: requestError('secret_unreadable'), client };
  try {
    await verifySignature(jwt, client);
  } catch (err) {
    return { error: requestError('bad_signature', err.message), client };
  }

  // Signed by the application; now check it is meant for us, fresh and complete.
  const fail = (code, message) => ({ error: requestError(code, message), client, verified: true });
  const audience = `${req.siteUrl}/migrate`;
  const now = Math.floor(Date.now() / 1000);
  if (![].concat(claims.aud).includes(audience)) return fail('aud_mismatch', `aud must be ${audience}.`);
  if (!Number.isInteger(claims.exp) || !Number.isInteger(claims.iat)) return fail('times_missing');
  if (claims.exp < now - CLOCK_SKEW_S) return fail('expired');
  if (claims.iat > now + CLOCK_SKEW_S) return fail('iat_in_future');
  if (claims.exp - claims.iat > REQUEST_MAX_AGE_S) return fail('lifetime_too_long');
  if (typeof claims.jti !== 'string' || !claims.jti || claims.jti.length > 200) return fail('jti_missing');
  if (typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 255) return fail('sub_invalid');
  if (typeof claims.preferred_username !== 'string' || !USERNAME_RE.test(claims.preferred_username)) return fail('username_invalid');
  if (!client.settings.returnUrls.includes(claims.return_url)) {
    return fail('return_url_unregistered', `return_url ${JSON.stringify(claims.return_url)} is not one of the registered return URLs.`);
  }

  const email = optionalString(claims.email, 254);
  const firstName = optionalString(claims.given_name, 100);
  const lastName = optionalString(claims.family_name, 100);
  const state = optionalString(claims.state, 500);
  if ([email, firstName, lastName, state].includes(null)) return fail('claim_invalid');
  if (email && !EMAIL_RE.test(email)) return fail('email_invalid');

  return {
    client,
    verified: true,
    migration: {
      appId: client.id,
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
  if (error) return rejectRequest(req, res, error, client);
  if (!client.enabled) return rejectRequest(req, res, requestError('migration_disabled'), client);

  // Each request id only once, so a request copied from a log or history can't be replayed.
  if (!(await startMigrationEvent({ appId: client.id, jti: migration.jti, legacyId: migration.legacyId, username: migration.username, ip: req.ip }))) {
    return rejectRequest(req, res, requestError('jti_reused', `${REQUEST_ERRORS.jti_reused} jti was ${JSON.stringify(migration.jti)}.`), client);
  }

  // Migrated before (CloakTail's record), or someone with this username already? If it is this
  // user, there is nothing to do.
  let recorded;
  let existing;
  try {
    recorded = await recordedUser(client, migration.legacyId);
    if (!recorded) [existing] = await sandboxAdmin.findUsersExact({ username: migration.username });
  } catch (err) {
    console.error(`[migrate] ${client.clientId}: looking up ${migration.username} failed:`, err.message);
    await finishMigrationEvent({ appId: client.id, jti: migration.jti, status: 'error', detail: err.message });
    return renderMessage(res, 503, 'Try again later', 'Your account can’t be moved right now. Go back to the application and try again in a few minutes.',
      { appName: client.name });
  }
  if (recorded) return finish(req, res, client, migration, { status: 'already_migrated', keycloakId: recorded.keycloak_id });
  // The Keycloak attributes are a copy of the record, for users migrated before it existed.
  if (existing) {
    return isSameMigratedUser(existing, client.app, migration.legacyId)
      ? finish(req, res, client, migration, { status: 'already_migrated', keycloakId: existing.id })
      : finish(req, res, client, migration, {
        status: 'conflict', detail: RESULT_STATUSES.conflict.detail, log: `username taken by ${existing.id}`,
      });
  }

  req.session.migration = migration;
  // A clean URL: the token leaves the address bar and history.
  req.session.save((err) => (err ? res.status(500).end() : res.redirect(303, '/migrate')));
}

migrateRouter.get('/start', start);
migrateRouter.post('/start', start);

// ---------- 2. the page ----------

// The migration in this session and its application; otherwise renders why not and returns {}.
async function load(req, res) {
  const migration = req.session.migration;
  if (!migration) {
    renderMessage(res, 400, 'Nothing to do here',
      'This page is opened by an application that is moving your account. Go back to the application and sign in again.');
    return {};
  }
  const client = await clientFor(await getApp(migration.appId));
  if (!client || !client.enabled || client.secretUnreadable) {
    delete req.session.migration;
    renderMessage(res, 503, 'Account moves are paused', 'Moving accounts for this application isn’t available right now. Try again later.');
    return {};
  }
  if (Date.now() > migration.expiresAt) {
    await finish(req, res, client, migration, { status: 'expired', detail: RESULT_STATUSES.expired.detail });
    return {};
  }
  // The authenticator secret stays in the session until the account is created, so the QR code is
  // the same across errors and reloads.
  if (client.settings.requireOtp && !migration.otpSecret) migration.otpSecret = newTotpSecret();
  return { client, migration };
}

const otpRequired = (client, migration) => client.settings.requireOtp && Boolean(migration.otpSecret);

async function render(res, client, migration, { error = null, field = null } = {}) {
  const otp = otpRequired(client, migration) ? {
    qrSvg: await totpQrSvg(migration.otpSecret, { issuer: client.name, account: migration.username }),
    manualKey: manualKey(migration.otpSecret),
    verified: Boolean(migration.otpVerified),
  } : null;
  res.status(error ? 422 : 200).render('pages/migrate/form', {
    title: `Set up your new sign-in for ${client.name}`,
    description: DESCRIPTION,
    bare: true,
    appName: client.name,
    otp,
    migration,
    error,
    field,
  });
}

const otpCode = (body) => String(body.otp ?? '').replace(/\s/g, '');

migrateRouter.get('/', async (req, res) => {
  const { client, migration } = await load(req, res);
  if (client) render(res, client, migration);
});

// Checks the authenticator code before the form is submitted, so a mistyped code doesn't cost the
// user the passwords they typed (they aren't kept after an error). A correct code is remembered.
migrateRouter.post('/otp', async (req, res) => {
  const { client, migration } = await load(req, res);
  if (!client) return;
  if (!otpRequired(client, migration)) return res.status(400).json({ ok: false });
  if (codeLimited(req.ip)) return res.status(429).json({ ok: false, error: 'Too many attempts. Try again in 15 minutes.' });
  if (!verifyTotp(migration.otpSecret, otpCode(req.body))) {
    return res.json({ ok: false, error: 'That code doesn’t match. Check that you scanned this QR code, then enter the code your app shows now.' });
  }
  migration.otpVerified = true;
  res.json({ ok: true });
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
  const otp = otpRequired(client, migration);
  if (otp && !migration.otpVerified) {
    if (!verifyTotp(migration.otpSecret, otpCode(req.body))) return fail('That code doesn’t match. Enter the code your authenticator app shows now.', 'otp');
    migration.otpVerified = true;
  }

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
      requiredActions: [],
      otherCredentials: otp ? [totpCredential(migration.otpSecret)] : [],
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
      return finish(req, res, client, migration, { status: 'error', detail: RESULT_STATUSES.error.detail, log: `Keycloak: ${err.message}` });
    }
    return fail('Your account couldn’t be set up just now. Try again in a moment.');
  }
  if (otp) await skipOtpSetup(client, keycloakId);
  await finish(req, res, client, migration, { status: 'created', keycloakId });
});

// The user already has their OTP credential; a realm that gives every new user Configure OTP (a
// default action) would make them set up a second one. Not fatal: Keycloak then just asks again.
async function skipOtpSetup(client, keycloakId) {
  try {
    const { requiredActions = [] } = await sandboxAdmin.getUser(keycloakId);
    if (requiredActions.includes(OTP_SETUP_ACTION)) {
      await sandboxAdmin.updateUser(keycloakId, { requiredActions: requiredActions.filter((a) => a !== OTP_SETUP_ACTION) });
    }
  } catch (err) {
    console.error(`[migrate] ${client.clientId}: removing ${OTP_SETUP_ACTION} from ${keycloakId} failed:`, err.message);
  }
}

// Username or email taken. It may be this same user (a double submit, or a lost response), who is
// then already migrated; a different account is a conflict for a person to resolve.
async function conflict(req, res, client, migration, message) {
  const recorded = await recordedUser(client, migration.legacyId);
  if (recorded) return finish(req, res, client, migration, { status: 'already_migrated', keycloakId: recorded.keycloak_id });
  const [byUsername] = await sandboxAdmin.findUsersExact({ username: migration.username });
  if (byUsername && isSameMigratedUser(byUsername, client.app, migration.legacyId)) {
    return finish(req, res, client, migration, { status: 'already_migrated', keycloakId: byUsername.id });
  }
  return finish(req, res, client, migration, {
    status: 'conflict',
    detail: RESULT_STATUSES.conflict.detail,
    log: `Keycloak: ${message}`,
  });
}

migrateRouter.post('/cancel', async (req, res) => {
  const { client, migration } = await load(req, res);
  if (client) await finish(req, res, client, migration, { status: 'cancelled' });
});

// ---------- for the application's developers and their coding agents ----------

// Mounted before the session and CSRF middleware (app.js): these are called by servers and agents,
// not browsers. /check, /simulate and /status only answer requests signed for a registered application.
export const migrateApiRouter = express.Router();

migrateApiRouter.get('/spec.md', (req, res) => res.type('text/markdown; charset=utf-8')
  .set('Cache-Control', 'public, max-age=3600').send(migrationSpec({ siteUrl: req.siteUrl })));

const apiLimited = limiter(120);
const api = express.Router();
api.use(express.json({ limit: '64kb' }), express.urlencoded({ extended: false, limit: '64kb' }), (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (apiLimited(req.ip)) return res.status(429).json({ ok: false, error: requestError('rate_limited') });
  next();
});
migrateApiRouter.use(['/check', '/simulate', '/status'], api);

// What a request signed by the application may learn about its own setup.
const appSettings = (client) => ({
  client_id: client.clientId,
  name: client.name,
  enabled: client.enabled,
  return_urls: client.settings.returnUrls,
  request_signing: { secret: 'HS256 with the migration secret', publicKey: 'Your private key (RS256, PS256, ES256 or EdDSA); CloakTail holds the public key', jwks: `Your private key, with the kid of a key at ${client.settings.jwksUrl}` }[client.settings.requestKey],
  result_signing: 'HS256 with the migration secret',
  require_otp: client.settings.requireOtp,
});

// Reads the request for /check and /simulate. Sends the error response and returns null when it
// fails; an unknown client and a bad signature look the same, so client IDs can't be probed.
async function apiRequest(req, res) {
  const token = req.body?.request;
  const { error, client, verified, migration } = await readRequest(req, typeof token === 'string' ? token : '');
  if (error) {
    const shown = verified || ['malformed', 'secret_unreadable'].includes(error.code) ? error : requestError('invalid_request');
    res.status(400).json({ ok: false, error: shown, ...(verified ? { app: appSettings(client) } : {}) });
    return null;
  }
  return { client, migration };
}

const requestSummary = (migration) => ({
  sub: migration.legacyId,
  preferred_username: migration.username,
  email: migration.email || null,
  given_name: migration.firstName || null,
  family_name: migration.lastName || null,
  return_url: migration.returnUrl,
  state: migration.state || null,
  jti: migration.jti,
});

// Checks a request as /migrate/start would, without recording it or using up its jti.
migrateApiRouter.post('/check', async (req, res) => {
  const read = await apiRequest(req, res);
  if (!read) return;
  const { client, migration } = read;
  if (await migrationJtiUsed(client.id, migration.jti)) {
    return res.status(400).json({ ok: false, error: requestError('jti_reused'), app: appSettings(client) });
  }
  res.json({
    ok: true,
    app: appSettings(client),
    request: requestSummary(migration),
    start_url: `${req.siteUrl}/migrate/start`,
    ...(client.enabled ? {} : { warning: requestError('migration_disabled') }),
  });
});

// A result for the request with the status asked for, signed like a real one, to test the
// application's return URL. Nothing is created or recorded. The result says simulated: true.
migrateApiRouter.post('/simulate', async (req, res) => {
  const status = req.body?.status;
  if (!Object.hasOwn(RESULT_STATUSES, status)) {
    return res.status(400).json({ ok: false, error: requestError('status_invalid', `status must be one of ${Object.keys(RESULT_STATUSES).join(', ')}.`) });
  }
  const read = await apiRequest(req, res);
  if (!read) return;
  const { client, migration } = read;
  const keycloakId = ['created', 'already_migrated'].includes(status) ? crypto.randomUUID() : null;
  const { result, url } = resultFor(req, client, migration, { status, keycloakId, detail: RESULT_STATUSES[status].detail, simulated: true });
  res.json({ ok: true, status, result, redirect_url: url });
});

// Whether CloakTail migrated the request's user (sub) for this application: for an application that
// never received a result (the browser didn't come back), so it can record the user and stop sending
// them. Server to server, authenticated by the request's signature; the request isn't recorded and
// its jti isn't used up. A migrated user comes with a signed already_migrated result, checked like
// any result except state (there is no browser session).
migrateApiRouter.post('/status', async (req, res) => {
  const read = await apiRequest(req, res);
  if (!read) return;
  const { client, migration } = read;
  const recorded = await recordedUser(client, migration.legacyId);
  if (!recorded) return res.json({ ok: true, migrated: false, sub: migration.legacyId });
  const { result } = resultFor(req, client, { ...migration, state: '' }, { status: 'already_migrated', keycloakId: recorded.keycloak_id });
  res.json({
    ok: true,
    migrated: true,
    sub: migration.legacyId,
    keycloak_id: recorded.keycloak_id,
    preferred_username: recorded.user.username,
    migrated_at: `${recorded.migrated_at.replace(' ', 'T')}Z`,
    result,
  });
});
