import crypto from 'node:crypto';
import express from 'express';
import {
  ADMIN_USERNAME_RE, getAdminAccount, listAdminAccounts, createAdminAccount, createFirstAdminAccount,
  deleteAdminAccount, setAdminPassword, recordAdminLogin, recordAdminLoginFailure,
} from '../db.js';
import { setupRequired, ensureSetupToken, setupTokenMatches, finishSetup } from '../adminSetup.js';
import { hashPassword, verifyPassword, passwordProblem, DUMMY_HASH } from '../lib/password.js';
import { checkKeycloakConnection } from '../lib/keycloakCheck.js';
import {
  PROFILE_SECTIONS, PROFILE_FIELDS, listProfiles, getProfile, createProfile, updateProfile, duplicateProfile,
  deleteProfile, activateProfile, profileInputFromForm, exportProfiles, importProfiles,
} from '../keycloakProfiles.js';
import {
  KEY_SIZES, VALIDITY_YEARS, getSpKeysView, generateSpKey, importSpKey, activatePendingSpKey, discardPendingSpKey,
} from '../spKeys.js';
import { config } from '../config.js';
import { requireAdmin, redirect, sendError } from '../middleware.js';

// Admin console: local administrator accounts (stored in PostgreSQL, not Keycloak) that configure
// the portal's Keycloak connection. Local on purpose, so a broken Keycloak setup can be fixed.

export const adminRouter = express.Router();

const LOCK_AFTER = 10;
const LOCK_MS = 15 * 60 * 1000;
const LOGIN_FAILED = 'Incorrect username or password, or the account is locked for 15 minutes after too many failed attempts.';

// Per-IP limit on sign-in attempts (in memory; use a shared store behind a load balancer).
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 20;
const attempts = new Map();

function rateLimited(ip) {
  const now = Date.now();
  const recent = (attempts.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  attempts.set(ip, recent);
  return recent.length > MAX_ATTEMPTS;
}

const safeReturnTo = (value) => (typeof value === 'string' && /^\/admin(\/[\w-]+)*$/.test(value) ? value : '/admin');

// Fresh session id on sign-in (prevents session fixation). A Keycloak sign-in in the same
// browser is kept. Also used after a password change, which ends the account's other sessions.
function startAdminSession(req, account, done) {
  const portalLogin = req.session.passport;
  req.session.regenerate((err) => {
    if (err) return done(err);
    if (portalLogin) req.session.passport = portalLogin;
    req.session.admin = { username: account.username, passwordChangedAt: account.password_changed_at, since: Date.now() };
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.save(done);
  });
}

// Admin pages show configuration; never let a browser or proxy cache them.
adminRouter.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// Anonymous visitors need a session-bound CSRF token for the sign-in and setup forms.
function ensureCsrf(req, res) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
}

// ---------- first-run setup ----------

// While no administrator exists, every admin page leads to setup (like Keycloak's welcome page).
adminRouter.use(async (req, res, next) => {
  if (req.path === '/setup' || !(await setupRequired())) return next();
  redirect(req, res, '/admin/setup');
});

const renderSetup = (res, locals, status = 200) =>
  res.status(status).render('pages/admin/setup', {
    title: 'Create the administrator', values: {}, error: null, field: null, ...locals,
  });

adminRouter.get('/setup', async (req, res) => {
  if (!(await setupRequired())) return res.redirect('/admin/login');
  await ensureSetupToken();
  ensureCsrf(req, res);
  renderSetup(res, {});
});

adminRouter.post('/setup', async (req, res, next) => {
  if (!(await setupRequired())) return res.redirect(303, '/admin/login');
  const values = { username: String(req.body.username || '').trim().toLowerCase() };
  const password = String(req.body.password || '');
  const fail = (error, field, status = 422) => renderSetup(res, { values, error, field }, status);

  if (rateLimited(req.ip)) return fail('Too many attempts from your network. Try again in 15 minutes.', null, 429);
  if (!setupTokenMatches(String(req.body.setupToken || '').trim())) {
    console.warn(`[admin] wrong setup token from ${req.ip}`);
    return fail('That setup token is wrong. Copy it from the server log; it changes on every restart.', 'setupToken', 403);
  }
  if (!ADMIN_USERNAME_RE.test(values.username)) {
    return fail('Use 3–40 lowercase letters, digits, dots, dashes or underscores, starting with a letter or digit.', 'username');
  }
  const problem = passwordProblem(password, values.username);
  if (problem) return fail(problem, 'password');
  if (password !== req.body.confirmPassword) return fail('The passwords don’t match.', 'confirmPassword');

  const created = await createFirstAdminAccount({
    username: values.username,
    passwordHash: await hashPassword(password),
    createdBy: 'setup',
    mustChangePassword: false,
  });
  // Lost a race with another setup or the bootstrap variables: someone else is the first admin.
  if (!created) return res.redirect(303, '/admin/login');
  finishSetup();
  console.log(`[admin] first administrator "${values.username}" created from ${req.ip}`);
  startAdminSession(req, await getAdminAccount(values.username), (err) => {
    if (err) return next(err);
    res.redirect(303, '/admin/keycloak');
  });
});

// ---------- sign-in ----------

const renderLogin = (res, locals, status = 200) =>
  res.status(status).render('pages/admin/login', {
    title: 'Administrator sign-in', values: {}, error: null, loggedOut: false, returnTo: '/admin', ...locals,
  });

adminRouter.get('/login', (req, res) => {
  if (req.admin) return res.redirect(safeReturnTo(req.query.returnTo));
  ensureCsrf(req, res);
  renderLogin(res, { returnTo: safeReturnTo(req.query.returnTo), loggedOut: 'loggedOut' in req.query });
});

adminRouter.post('/login', async (req, res, next) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const returnTo = safeReturnTo(req.body.returnTo);
  const fail = (error, status = 401) => renderLogin(res, { values: { username }, error, returnTo }, status);

  if (rateLimited(req.ip)) return fail('Too many sign-in attempts from your network. Try again in 15 minutes.', 429);

  const account = ADMIN_USERNAME_RE.test(username) ? await getAdminAccount(username) : null;
  // Always hash once, so response time doesn't reveal whether the username exists.
  const passwordOk = await verifyPassword(password, account?.password_hash || DUMMY_HASH);
  const locked = account?.locked_until && Date.parse(account.locked_until) > Date.now();

  if (!account || locked || !passwordOk) {
    if (account && !locked) await recordAdminLoginFailure(username, { lockAfter: LOCK_AFTER, lockMs: LOCK_MS });
    console.warn(`[admin] failed sign-in for "${username}" from ${req.ip}${locked ? ' (account locked)' : ''}`);
    return fail(LOGIN_FAILED);
  }

  await recordAdminLogin(username);
  console.log(`[admin] ${username} signed in from ${req.ip}`);
  startAdminSession(req, account, (err) => {
    if (err) return next(err);
    res.redirect(303, account.must_change_password ? '/admin/password' : returnTo);
  });
});

adminRouter.post('/logout', (req, res) => {
  delete req.session.admin;
  redirect(req, res, '/admin/login?loggedOut');
});

// ---------- everything below needs an admin sign-in ----------

adminRouter.use(requireAdmin);

adminRouter.get('/', (req, res) => res.redirect('/admin/keycloak'));

// ---------- Keycloak profiles ----------

const APPLIED_NOTE = 'New sign-ins and Keycloak calls use it now. People already signed in keep their session until they sign out.';

adminRouter.get('/keycloak', async (req, res) => {
  const [profiles, spKeys] = await Promise.all([listProfiles(), getSpKeysView()]);
  const active = profiles.find((p) => p.active);
  let message = null;
  if ('activated' in req.query && active) message = `"${active.name}" is now the active profile. ${APPLIED_NOTE}`;
  if ('deleted' in req.query) message = 'Profile deleted.';
  res.render('pages/admin/profiles', { title: 'Keycloak profiles', profiles, message, hasSigningKey: Boolean(spKeys.active) });
});

// Form values for a profile page. Secrets are never sent back to the browser, only whether they are set.
function renderProfile(res, { status = 200, profile = null, values, errors = {}, error = null, message = null }) {
  res.status(status).render('pages/admin/profile', {
    title: profile ? `Keycloak profile: ${profile.name}` : 'New Keycloak profile',
    sections: PROFILE_SECTIONS,
    fields: PROFILE_FIELDS,
    profile,
    values: values ?? (profile ? { name: profile.name, description: profile.description, ...profile.settings } : {}),
    secretsSet: profile ? Object.fromEntries(Object.entries(profile.secrets).map(([k, v]) => [k, Boolean(v)])) : {},
    errors,
    error,
    message,
  });
}

const formValues = (body) => ({
  name: body.name ?? '',
  description: body.description ?? '',
  ...Object.fromEntries(PROFILE_FIELDS.filter((f) => !f.secret).map((f) => [f.key, body[f.key] ?? ''])),
});

async function loadProfile(req, res) {
  const profile = await getProfile(Number(req.params.id));
  if (!profile) sendError(req, res, 404, 'Keycloak profile not found.');
  return profile;
}

adminRouter.get('/keycloak/new', (req, res) => renderProfile(res, {}));

adminRouter.post('/keycloak/profiles', async (req, res) => {
  const { errors, id } = await createProfile(profileInputFromForm(req.body), req.admin.username);
  if (Object.keys(errors).length) {
    return renderProfile(res, { status: 422, values: formValues(req.body), errors, error: 'Fix the highlighted fields. Nothing was saved.' });
  }
  redirect(req, res, `/admin/keycloak/profiles/${id}?created`);
});

adminRouter.get('/keycloak/profiles/:id', async (req, res) => {
  const profile = await loadProfile(req, res);
  if (!profile) return;
  const message = 'created' in req.query ? 'Profile created. Run the checks, then activate it when you’re ready.'
    : 'duplicated' in req.query ? 'This is a copy, including the client secrets. Rename it and change what differs.'
      : null;
  renderProfile(res, { profile, message });
});

adminRouter.post('/keycloak/profiles/:id', async (req, res) => {
  const profile = await loadProfile(req, res);
  if (!profile) return;
  const { errors } = await updateProfile(profile.id, profileInputFromForm(req.body, profile), req.admin.username);
  if (Object.keys(errors).length) {
    return renderProfile(res, { status: 422, profile, values: formValues(req.body), errors, error: 'Fix the highlighted fields. Nothing was saved.' });
  }
  renderProfile(res, {
    profile: await getProfile(profile.id),
    message: profile.active ? `Saved. This is the active profile: ${APPLIED_NOTE}` : 'Saved.',
  });
});

adminRouter.post('/keycloak/profiles/:id/activate', async (req, res) => {
  const profile = await loadProfile(req, res);
  if (!profile) return;
  await activateProfile(profile.id, req.admin.username);
  redirect(req, res, '/admin/keycloak?activated');
});

adminRouter.post('/keycloak/profiles/:id/test', async (req, res) => {
  const profile = await loadProfile(req, res);
  if (!profile) return;
  res.render('fragments/admin-checks', { checks: await checkKeycloakConnection({ ...profile.settings, ...profile.secrets }) });
});

adminRouter.post('/keycloak/profiles/:id/duplicate', async (req, res) => {
  const profile = await loadProfile(req, res);
  if (!profile) return;
  const id = await duplicateProfile(profile.id, req.admin.username);
  console.log(`[admin] ${req.admin.username} duplicated Keycloak profile "${profile.name}"`);
  redirect(req, res, `/admin/keycloak/profiles/${id}?duplicated`);
});

adminRouter.post('/keycloak/profiles/:id/delete', async (req, res) => {
  const profile = await loadProfile(req, res);
  if (!profile) return;
  const { error } = await deleteProfile(profile.id, req.admin.username);
  if (error) return sendError(req, res, 400, error);
  redirect(req, res, '/admin/keycloak?deleted');
});

// ---------- export / import ----------

async function sendExport(req, res, ids, filePart) {
  const includeSecrets = req.body.includeSecrets === 'on';
  const data = await exportProfiles(ids, { includeSecrets });
  const date = new Date().toISOString().slice(0, 10).replaceAll('-', '');
  const slug = filePart.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'profile';
  console.log(`[admin] ${req.admin.username} exported ${data.profiles.length} Keycloak profile(s)${includeSecrets ? ' WITH client secrets' : ''}`);
  res.set('Content-Disposition', `attachment; filename="cloaktail-keycloak-${slug}-${date}.json"`)
    .type('application/json')
    .send(JSON.stringify(data, null, 2));
}

// POST, not GET: exports can contain client secrets, so they need the CSRF token.
adminRouter.post('/keycloak/export', (req, res) => sendExport(req, res, null, 'profiles'));

adminRouter.post('/keycloak/profiles/:id/export', async (req, res) => {
  const profile = await loadProfile(req, res);
  if (!profile) return;
  await sendExport(req, res, [profile.id], profile.name);
});

const CONFLICT_CHOICES = ['rename', 'overwrite', 'skip'];

const renderImport = (res, { status = 200, ...locals } = {}) =>
  res.status(status).render('pages/admin/import', {
    title: 'Import Keycloak profiles', json: '', onConflict: 'rename', error: null, problems: [], result: null, ...locals,
  });

adminRouter.get('/keycloak/import', (req, res) => renderImport(res));

adminRouter.post('/keycloak/import', async (req, res) => {
  const json = String(req.body.json || '').trim();
  const onConflict = CONFLICT_CHOICES.includes(req.body.onConflict) ? req.body.onConflict : 'rename';
  if (!json) return renderImport(res, { status: 422, onConflict, error: 'Choose a file or paste the exported JSON.' });
  const { error, problems = [], result } = await importProfiles(json, { onConflict, by: req.admin.username });
  // Never echo the JSON back: it may contain client secrets.
  if (error) return renderImport(res, { status: 422, onConflict, error, problems });
  renderImport(res, { onConflict, result });
});

// ---------- SAML signing certificate ----------

const CN_RE = /^[A-Za-z0-9 ._:/@-]{1,64}$/;
const defaultCommonName = () => `CloakTail ${new URL(config.baseUrl).host}`.slice(0, 64);

// Key generation is CPU-heavy; limit it per administrator.
const keyGenerations = new Map();
function keyGenerationLimited(username) {
  const now = Date.now();
  const hits = (keyGenerations.get(username) || []).filter((t) => now - t < 10 * 60 * 1000);
  hits.push(now);
  keyGenerations.set(username, hits);
  return hits.length > 10;
}

const renderSigning = async (res, { status = 200, ...locals } = {}) =>
  res.status(status).render('pages/admin/signing', {
    title: 'SAML signing certificate',
    ...(await getSpKeysView()),
    KEY_SIZES,
    VALIDITY_YEARS,
    values: { commonName: defaultCommonName(), keySize: 2048, years: 5 },
    error: null,
    importError: null,
    importField: null,
    message: null,
    ...locals,
  });

const STATUS_MESSAGES = {
  active: 'The new certificate is active. Import it into the portal SAML client in Keycloak (Keys tab), or sign-in will fail.',
  pending: 'The new certificate is pending. Import it into the portal SAML client in Keycloak (Keys tab), then activate it here.',
};

adminRouter.get('/signing', (req, res) => {
  const message = 'activated' in req.query ? 'The new certificate is active. CloakTail now signs with it.'
    : 'discarded' in req.query ? 'The pending certificate was discarded.'
      : Object.hasOwn(STATUS_MESSAGES, req.query.created ?? '') ? STATUS_MESSAGES[req.query.created] : null;
  return renderSigning(res, { message });
});

adminRouter.post('/signing/generate', async (req, res) => {
  const values = {
    commonName: String(req.body.commonName || '').trim(),
    keySize: Number(req.body.keySize),
    years: Number(req.body.years),
  };
  const fail = (error) => renderSigning(res, { status: 422, values, error });
  if (!CN_RE.test(values.commonName)) return fail('Common name: up to 64 characters (letters, digits, space . - _ : / @).');
  if (!KEY_SIZES.includes(values.keySize)) return fail('Choose a key size.');
  if (!VALIDITY_YEARS.includes(values.years)) return fail('Choose a validity period.');
  if (keyGenerationLimited(req.admin.username)) return fail('You have generated many keys recently. Try again in 10 minutes.');
  const status = await generateSpKey(values, req.admin.username);
  redirect(req, res, `/admin/signing?created=${status}`);
});

adminRouter.post('/signing/import', async (req, res) => {
  const { error, field, status } = await importSpKey(String(req.body.certificate || ''), String(req.body.privateKey || ''), req.admin.username);
  // Never echo the private key back.
  if (error) return renderSigning(res, { status: 422, importError: error, importField: field });
  redirect(req, res, `/admin/signing?created=${status}`);
});

adminRouter.post('/signing/activate', async (req, res) => {
  if (!(await activatePendingSpKey(req.admin.username))) return sendError(req, res, 400, 'There is no pending certificate to activate.');
  redirect(req, res, '/admin/signing?activated');
});

adminRouter.post('/signing/discard', async (req, res) => {
  await discardPendingSpKey(req.admin.username);
  redirect(req, res, '/admin/signing?discarded');
});

// ---------- administrators ----------

const renderAccounts = async (req, res, { status = 200, ...locals } = {}) =>
  res.status(status).render('pages/admin/accounts', {
    title: 'Administrators', accounts: await listAdminAccounts(), values: {}, error: null, message: null, ...locals,
  });

adminRouter.get('/accounts', (req, res) => renderAccounts(req, res));

adminRouter.post('/accounts', async (req, res) => {
  const values = { username: String(req.body.username || '').trim().toLowerCase() };
  const password = String(req.body.password || '');
  const fail = (error) => renderAccounts(req, res, { status: 422, values, error });

  if (!ADMIN_USERNAME_RE.test(values.username)) {
    return fail('Username: 3–40 lowercase letters, digits, dots, dashes or underscores, starting with a letter or digit.');
  }
  if (await getAdminAccount(values.username)) return fail(`Administrator "${values.username}" already exists.`);
  const problem = passwordProblem(password, values.username);
  if (problem) return fail(`Initial password: ${problem}`);
  if (password !== req.body.confirmPassword) return fail('The passwords don’t match.');

  await createAdminAccount({
    username: values.username,
    passwordHash: await hashPassword(password),
    createdBy: req.admin.username,
    mustChangePassword: true,
  });
  console.log(`[admin] ${req.admin.username} created administrator ${values.username}`);
  await renderAccounts(req, res, {
    message: `Administrator "${values.username}" created. Share the initial password securely; they must change it when they first sign in.`,
  });
});

adminRouter.post('/accounts/:username/delete', async (req, res) => {
  const account = await getAdminAccount(req.params.username);
  if (!account) return sendError(req, res, 404, 'Administrator not found.');
  // Never delete yourself, so there is always at least one administrator left.
  if (account.username === req.admin.username) return sendError(req, res, 400, 'You can’t delete your own account.');
  await deleteAdminAccount(account.username);
  console.log(`[admin] ${req.admin.username} deleted administrator ${account.username}`);
  redirect(req, res, '/admin/accounts');
});

// ---------- own password ----------

const renderPassword = (req, res, { status = 200, ...locals } = {}) =>
  res.status(status).render('pages/admin/password', {
    title: 'Change password', error: null, changed: 'changed' in req.query, ...locals,
  });

adminRouter.get('/password', (req, res) => renderPassword(req, res));

adminRouter.post('/password', async (req, res, next) => {
  const current = String(req.body.currentPassword || '');
  const password = String(req.body.password || '');
  const fail = (error) => renderPassword(req, res, { status: 422, error });

  const account = await getAdminAccount(req.admin.username);
  if (!(await verifyPassword(current, account.password_hash))) return fail('Your current password is incorrect.');
  const problem = passwordProblem(password, account.username);
  if (problem) return fail(problem);
  if (password !== req.body.confirmPassword) return fail('The new passwords don’t match.');
  if (password === current) return fail('Choose a password different from the current one.');

  await setAdminPassword(account.username, await hashPassword(password), { mustChangePassword: false });
  console.log(`[admin] ${account.username} changed their password`);
  // Keeps this browser signed in; the account's other sessions end because password_changed_at moved on.
  startAdminSession(req, await getAdminAccount(account.username), (err) => {
    if (err) return next(err);
    res.redirect(303, account.must_change_password ? '/admin/keycloak' : '/admin/password?changed');
  });
});
