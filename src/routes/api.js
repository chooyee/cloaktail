import express from 'express';
import { config } from '../config.js';
import { KeycloakError, sandboxAdmin } from '../lib/keycloakAdmin.js';
import { idpInitiatedUrl, NAME_ID_FORMAT_URNS } from '../lib/samlClients.js';
import {
  REQUEST_ERRORS, getAppMigration, defaultMigrationValues, saveAppMigration, regenerateMigrationSecret, migrationWarnings,
} from '../lib/userMigration.js';
import { TOKEN_TTL_S, authenticateClient, issueAccessToken, authenticateToken, parseScopes } from '../lib/apiCredentials.js';
import {
  getApp, countApps, countTestUsers, getUserPermissions, listTestRuns, getTestRun, listMigrationEvents, countMigrationEvents,
  getMigratedUser, listMigratedUsers, putMigratedUser, deleteMigratedUser,
} from '../db.js';
import {
  findApp, listAppsFor, loadClient, createApp, updateApp, removeApp, samlValuesFromMetadata,
  appClientSecret, rotateAppClientSecret, startAppTest, idpInfo,
} from '../services/apps.js';
import { listTestUsersWithDetails, findOwnTestUser, createTestUser, setTestUserPassword, removeTestUser } from '../services/testUsers.js';
import { generateCertificate, CERTIFICATE_DEFAULTS } from '../services/certificates.js';
import { ServiceError, notFound, invalid } from '../services/errors.js';
import {
  APP_FIELDS, APP_DEFAULTS, MIGRATION_FIELDS, TEST_USER_FIELDS, CERTIFICATE_FIELDS,
  valuesFromJson, jsonFromValues, apiFieldName, migrationValuesFromJson, migrationSettingsJson,
} from '../api/fields.js';
import { openApiSpec } from '../api/openapi.js';
import { agentGuide } from '../api/agentGuide.js';

// The developer REST API, /api/v1: everything a developer does on the portal's application, test
// user and certificate pages, for scripts and coding agents. Mounted before the session and CSRF
// middleware (app.js): it takes no cookies, only bearer tokens from POST /api/v1/oauth/token, so it
// can't be driven cross-site. Described by /api/v1/openapi.json (Swagger UI at /developers/api) and,
// for coding agents, /api/v1/agent.md. Errors are RFC 9457 problem details with a stable `code`.

export const apiRouter = express.Router();
export const API_BASE = '/api/v1';

// ---------- helpers ----------

const TITLES = {
  400: 'Bad request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not found', 409: 'Conflict',
  413: 'Content too large', 422: 'Unprocessable content', 429: 'Too many requests', 500: 'Internal server error', 502: 'Keycloak error',
};

function problem(req, res, status, code, detail, extra = {}) {
  res.status(status).type('application/problem+json').send(JSON.stringify({
    type: `${req.siteUrl}${API_BASE}/agent.md#errors`, title: TITLES[status] ?? 'Error', status, code, detail, ...extra,
  }));
}

// Per-key limits (in memory; use a shared store behind a load balancer).
const WINDOW_MS = 15 * 60 * 1000;
function limiter(max) {
  const hits = new Map();
  return (key) => {
    const now = Date.now();
    const recent = (hits.get(key) || []).filter((t) => now - t < WINDOW_MS);
    recent.push(now);
    hits.set(key, recent);
    return recent.length > max;
  };
}
const tokenLimited = limiter(60);
const callLimited = limiter(1000);

// Database timestamps are UTC 'YYYY-MM-DD HH:MM:SS'.
const iso = (text) => (text ? `${text.replace(' ', 'T')}Z` : null);
const link = (req, path) => `${req.siteUrl}${API_BASE}${path}`;

// ---------- documentation (public) ----------

// Where the API is described (RFC 8631), on every response, so an agent holding any API URL finds
// the spec and the guide. Also used by the API catalog (app.js, /.well-known/api-catalog).
export const API_DESCRIPTIONS = {
  'service-desc': [{ href: `${API_BASE}/openapi.json`, type: 'application/openapi+json' }],
  'service-doc': [{ href: `${API_BASE}/agent.md`, type: 'text/markdown' }, { href: '/developers/api', type: 'text/html' }],
};
const linkHeader = Object.entries(API_DESCRIPTIONS)
  .flatMap(([rel, links]) => links.map((l) => `<${l.href}>; rel="${rel}"; type="${l.type}"`)).join(', ');
apiRouter.use((req, res, next) => {
  res.set('Link', linkHeader);
  next();
});

apiRouter.get('/', (req, res) => res.json({
  name: 'CloakTail developer API',
  version: 'v1',
  openapi: link(req, '/openapi.json'),
  docs: `${req.siteUrl}/developers/api`,
  guide: `${req.siteUrl}/developers`,
  agent_guide: link(req, '/agent.md'),
  token_endpoint: link(req, '/oauth/token'),
  credentials: `${req.siteUrl}/api-credentials`,
}));

apiRouter.get('/openapi.json', (req, res) => res.set('Cache-Control', 'public, max-age=300')
  .json(openApiSpec()));

apiRouter.get('/agent.md', (req, res) => res.type('text/markdown; charset=utf-8').set('Cache-Control', 'public, max-age=300')
  .send(agentGuide()));

// The API reference is a public page (routes/developers.js) that runs Swagger UI with this script.
apiRouter.get('/docs', (req, res) => res.redirect(301, '/developers/api'));

apiRouter.get('/docs.js', (req, res) => res.type('text/javascript').send(`window.ui = SwaggerUIBundle({
  url: '${API_BASE}/openapi.json',
  dom_id: '#swagger-ui',
  deepLinking: true,
  tryItOutEnabled: false,
  persistAuthorization: false,
});`));

// ---------- tokens ----------

apiRouter.use(express.json({ limit: '1mb' }), express.urlencoded({ extended: false, limit: '1mb' }));
apiRouter.use((req, res, next) => {
  // Responses can carry secrets and are per developer.
  res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' });
  next();
});

// RFC 6749 error responses, which OAuth client libraries understand.
const oauthError = (res, status, error, description) => res.status(status).json({ error, error_description: description });

// Client credentials from HTTP Basic (client_secret_basic) or the body (client_secret_post).
function clientCredentials(req) {
  const basic = /^Basic\s+(\S+)$/i.exec(req.get('Authorization') || '');
  if (basic) {
    const text = Buffer.from(basic[1], 'base64').toString('utf8');
    const at = text.indexOf(':');
    try {
      return at < 0 ? {} : { clientId: decodeURIComponent(text.slice(0, at)), secret: decodeURIComponent(text.slice(at + 1)) };
    } catch {
      return {};
    }
  }
  return { clientId: req.body?.client_id, secret: req.body?.client_secret };
}

apiRouter.post('/oauth/token', async (req, res) => {
  if (tokenLimited(req.ip)) return oauthError(res, 429, 'slow_down', 'Too many token requests from this address. Reuse a token until it expires.');
  if (req.body?.grant_type !== 'client_credentials') {
    return oauthError(res, 400, 'unsupported_grant_type', 'Use grant_type=client_credentials.');
  }
  const { clientId, secret } = clientCredentials(req);
  const credential = await authenticateClient(clientId, secret);
  if (!credential) {
    res.set('WWW-Authenticate', 'Basic realm="CloakTail API"');
    return oauthError(res, 401, 'invalid_client', `Unknown client ID or wrong secret, the credential expired or was revoked, or it was created on another CloakTail site. Create one at ${req.siteUrl}/api-credentials.`);
  }
  const granted = parseScopes(credential.scopes);
  const asked = typeof req.body.scope === 'string' && req.body.scope.trim() ? req.body.scope.trim().split(/\s+/) : granted;
  const notGranted = asked.filter((s) => !granted.includes(s));
  if (notGranted.length) return oauthError(res, 400, 'invalid_scope', `This credential doesn't have ${notGranted.join(', ')}. It has: ${granted.join(' ')}.`);
  res.json({
    access_token: issueAccessToken(credential, asked, req.siteUrl),
    token_type: 'Bearer',
    expires_in: TOKEN_TTL_S,
    scope: asked.join(' '),
  });
});

// ---------- authentication ----------

apiRouter.use(async (req, res, next) => {
  const bearer = /^Bearer\s+(\S+)$/i.exec(req.get('Authorization') || '');
  const fail = (detail) => {
    res.set('WWW-Authenticate', `Bearer realm="CloakTail API", error="invalid_token"`);
    problem(req, res, 401, 'invalid_token', detail);
  };
  if (!bearer) return fail(`Send an access token: "Authorization: Bearer <token>". Get one from POST ${link(req, '/oauth/token')}.`);
  const auth = await authenticateToken(bearer[1]);
  if (!auth) return fail('The access token is invalid or expired, or its credential was revoked. Get a new one from POST /api/v1/oauth/token.');
  if (callLimited(auth.credential.id)) return problem(req, res, 429, 'rate_limited', 'Too many calls with this credential. Try again in 15 minutes.');
  // The owner's current permissions, so a role taken away applies at once.
  const permissions = await getUserPermissions(auth.credential.owner);
  if (!permissions.has('apps.own')) {
    return problem(req, res, 403, 'forbidden', 'Your account may not use the developer API: it needs a role with the apps.own permission (e.g. developer).');
  }
  req.actor = { username: auth.credential.owner, can: (p) => permissions.has(p) };
  req.scopes = auth.scopes;
  req.credential = auth.credential;
  next();
});

const need = (scope) => (req, res, next) => (req.scopes.includes(scope)
  ? next()
  : problem(req, res, 403, 'insufficient_scope', `This call needs the ${scope} scope; this token has: ${req.scopes.join(' ') || '(none)'}. Create a credential with it at ${req.siteUrl}/api-credentials.`));

async function appOr404(req, { write = false } = {}) {
  const app = await findApp(req.actor, req.params.id, { write });
  if (!app) throw notFound('Application');
  return app;
}

// ---------- me ----------

function sandboxJson() {
  const s = config.sandbox;
  return {
    realm: s.realm,
    oidc: {
      issuer: s.oidc.issuer,
      discovery_url: s.oidc.discoveryUrl,
      authorization_endpoint: s.oidc.authorizationEndpoint,
      token_endpoint: s.oidc.tokenEndpoint,
      userinfo_endpoint: s.oidc.userinfoEndpoint,
      end_session_endpoint: s.oidc.endSessionEndpoint,
      jwks_uri: s.oidc.jwksUri,
    },
    saml: { entity_id: s.realmUrl, sso_url: s.samlEndpoint, slo_url: s.samlEndpoint, metadata_url: s.descriptorUrl },
  };
}

apiRouter.get('/me', async (req, res) => {
  const [apps, testUsers] = await Promise.all([countApps(req.actor.username), countTestUsers(req.actor.username)]);
  res.json({
    username: req.actor.username,
    credential: { name: req.credential.name, client_id: req.credential.client_id, expires_at: iso(req.credential.expires_at) },
    scopes: req.scopes,
    quotas: {
      apps: { used: apps, max: config.sandbox.maxAppsPerDeveloper },
      test_users: { used: testUsers, max: config.sandbox.maxTestUsersPerDeveloper },
    },
    sandbox: sandboxJson(),
  });
});

// ---------- applications ----------

async function integrationJson(req, app, client) {
  if (app.protocol === 'oidc') {
    const { oidc } = sandboxJson();
    return {
      ...oidc,
      client_id: app.client_id,
      client_secret: client.values.clientType === 'confidential' ? link(req, `/apps/${app.id}/client-secret`) : null,
      scopes: 'openid profile email',
    };
  }
  const idp = await idpInfo();
  return {
    idp_entity_id: idp.entityId,
    idp_sso_url: idp.ssoUrl,
    idp_slo_url: idp.sloUrl,
    idp_metadata_url: idp.metadataUrl,
    idp_certificate_pem: idp.certPem,
    sp_entity_id: app.client_id,
    name_id_format: NAME_ID_FORMAT_URNS[client.values.nameIdFormat],
    idp_initiated_sso_url: idpInitiatedUrl(client.rep),
  };
}

async function appJson(req, app, client = null) {
  client ??= await loadClient(app);
  const migration = await getAppMigration(app.id);
  return {
    id: app.id,
    protocol: app.protocol,
    ...jsonFromValues(APP_FIELDS[app.protocol], client.values),
    owner: app.owner,
    enabled: client.rep.enabled,
    created_at: iso(app.created_at),
    integration: await integrationJson(req, app, client),
    migration: { configured: Boolean(migration), enabled: migration?.enabled ?? false, url: link(req, `/apps/${app.id}/migration`) },
    portal_url: `${req.siteUrl}/apps/${app.id}`,
  };
}

const appSummary = (req, app) => ({
  id: app.id,
  protocol: app.protocol,
  name: app.name,
  client_id: app.client_id,
  owner: app.owner,
  created_at: iso(app.created_at),
  last_test: app.last_test_at ? { ok: Boolean(app.last_test_ok), at: iso(app.last_test_at) } : null,
  url: link(req, `/apps/${app.id}`),
});

apiRouter.get('/apps', need('apps:read'), async (req, res) => {
  const apps = await listAppsFor(req.actor, { all: req.query.all === 'true' });
  res.json({ apps: apps.map((a) => appSummary(req, a)) });
});

apiRouter.post('/apps', need('apps:write'), async (req, res) => {
  const protocol = req.body?.protocol;
  if (!['oidc', 'saml'].includes(protocol)) throw invalid('protocol is required: "oidc" or "saml".', { field: 'protocol' });
  const values = valuesFromJson(APP_FIELDS[protocol], req.body, APP_DEFAULTS[protocol](), { ignore: ['protocol'] });
  const id = await createApp(req.actor, protocol, values);
  res.status(201).location(link(req, `/apps/${id}`)).json(await appJson(req, await getApp(id)));
});

// SP metadata XML -> the fields to register a SAML app with. Nothing is created.
apiRouter.post('/saml-metadata', need('apps:write'), async (req, res) => {
  const metadata = req.body?.metadata;
  if (typeof metadata !== 'string') throw invalid('Send {"metadata": "<EntityDescriptor …>"}.', { field: 'metadata' });
  const values = await samlValuesFromMetadata(metadata);
  res.json({ protocol: 'saml', ...jsonFromValues(APP_FIELDS.saml, values) });
});

apiRouter.get('/apps/:id', need('apps:read'), async (req, res) => {
  res.json(await appJson(req, await appOr404(req)));
});

apiRouter.patch('/apps/:id', need('apps:write'), async (req, res) => {
  const app = await appOr404(req, { write: true });
  if (req.body?.protocol !== undefined && req.body.protocol !== app.protocol) {
    throw invalid(`protocol cannot change (this is a ${app.protocol} application). Register a new application instead.`, { field: 'protocol' });
  }
  const client = await loadClient(app);
  const values = valuesFromJson(APP_FIELDS[app.protocol], req.body, client.values, { isNew: false, ignore: ['protocol'] });
  await updateApp(app, values);
  res.json(await appJson(req, await getApp(app.id)));
});

apiRouter.delete('/apps/:id', need('apps:write'), async (req, res) => {
  await removeApp(await appOr404(req, { write: true }));
  res.status(204).end();
});

// ---------- .env output ----------
// Secrets and settings as NAME=value lines (?format=dotenv), so an agent can write them straight into
// a file (curl -o) without parsing JSON or seeing the values. Values that need it are double-quoted.

const dotenvValue = (v) => (/^[\w./:@+-]*$/.test(v) ? v : `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`);
const sendDotenv = (res, lines) => res.type('text/plain; charset=utf-8').send(`${lines
  .map((l) => (Array.isArray(l) ? `${l[0]}=${dotenvValue(l[1] ?? '')}` : l)).join('\n')}\n`);
const wantsDotenv = (req) => req.query.format === 'dotenv';

// The secret is only given to those who may change the application, as on its page.
apiRouter.get('/apps/:id/client-secret', need('secrets:read'), async (req, res) => {
  const app = await appOr404(req, { write: true });
  const secret = await appClientSecret(app);
  if (!secret) throw new ServiceError(400, 'public_client', 'This is a public client: it has no client secret. It uses PKCE instead.');
  if (wantsDotenv(req)) return sendDotenv(res, [['OIDC_CLIENT_SECRET', secret]]);
  res.json({ client_id: app.client_id, client_secret: secret });
});

// Every variable the application needs, with the default names the agent guide uses: the IdP
// settings, its own client settings and secrets, and user migration's when it is set up.
apiRouter.get('/apps/:id/env', need('secrets:read'), async (req, res) => {
  const app = await appOr404(req, { write: true });
  const client = await loadClient(app);
  const { values } = client;
  const lines = [`# CloakTail: ${app.name.replace(/[\r\n]/g, ' ')} (${app.protocol.toUpperCase()} app ${app.id}). Secrets: keep this file out of git.`];
  if (app.protocol === 'oidc') {
    lines.push(
      ['OIDC_ISSUER', config.sandbox.oidc.issuer],
      ['OIDC_CLIENT_ID', app.client_id],
      ...(values.clientType === 'confidential' ? [['OIDC_CLIENT_SECRET', await appClientSecret(app)]] : []),
      ['OIDC_REDIRECT_URI', values.redirectUris[0] ?? ''],
      ...(values.postLogoutRedirectUris[0] ? [['OIDC_POST_LOGOUT_REDIRECT_URI', values.postLogoutRedirectUris[0]]] : []),
    );
  } else {
    const idp = await idpInfo();
    lines.push(
      ['SAML_IDP_METADATA_URL', idp.metadataUrl],
      ['SAML_IDP_SSO_URL', idp.ssoUrl],
      ['SAML_IDP_CERT', idp.cert ?? ''],
      ['SAML_SP_ENTITY_ID', app.client_id],
      ['SAML_ACS_URL', values.acsUrl],
    );
  }
  const migration = await getAppMigration(app.id);
  if (migration && !migration.secretUnreadable) {
    lines.push(['CLOAKTAIL_URL', req.siteUrl], ['CLOAKTAIL_MIGRATION_SECRET', migration.secret]);
  }
  if (req.query.format === 'json') {
    return res.json({ variables: Object.fromEntries(lines.filter(Array.isArray)) });
  }
  sendDotenv(res, lines);
});

apiRouter.post('/apps/:id/client-secret/rotate', need('apps:write'), async (req, res) => {
  const app = await appOr404(req, { write: true });
  const secret = await rotateAppClientSecret(app);
  if (!secret) throw new ServiceError(400, 'public_client', 'This is a public client: it has no client secret.');
  res.json({ client_id: app.client_id, ...(req.scopes.includes('secrets:read') ? { client_secret: secret } : { rotated: true }) });
});

// ---------- test connection ----------

apiRouter.post('/apps/:id/tests', need('apps:write'), async (req, res) => {
  const app = await appOr404(req);
  const testUrl = await startAppTest(req.actor, app, req.siteUrl);
  res.status(201).json({
    test_url: testUrl,
    expires_in: 600,
    instructions: `A person must open test_url in a browser within 10 minutes and sign in as one of your test users. The result then appears in GET ${link(req, `/apps/${app.id}/tests`)}.`,
  });
});

apiRouter.get('/apps/:id/tests', need('apps:read'), async (req, res) => {
  const app = await appOr404(req);
  const runs = await listTestRuns(app.id);
  res.json({ runs: runs.map((r) => ({ id: r.id, ok: Boolean(r.ok), summary: r.summary, created_at: iso(r.created_at), url: link(req, `/apps/${app.id}/tests/${r.id}`) })) });
});

apiRouter.get('/apps/:id/tests/:runId', need('apps:read'), async (req, res) => {
  const app = await appOr404(req);
  const run = await getTestRun(Number(req.params.runId));
  if (!run || run.app_id !== app.id) throw notFound('Test run');
  res.json({ id: run.id, ok: Boolean(run.ok), summary: run.summary, created_at: iso(run.created_at), result: run.result });
});

// ---------- user migration ----------

async function migrationJson(req, app, migration) {
  const migrateUrl = `${req.siteUrl}/migrate`;
  const [counts, warnings] = await Promise.all([
    migration ? countMigrationEvents(app.id) : {},
    migrationWarnings(migration),
  ]);
  return {
    configured: Boolean(migration),
    ...(migration ? migrationSettingsJson(migration.settings, migration.enabled) : {}),
    secret_readable: migration ? !migration.secretUnreadable : null,
    counts,
    warnings,
    endpoints: {
      start: `${migrateUrl}/start`,
      request_aud_and_result_iss: migrateUrl,
      check: `${migrateUrl}/check`,
      simulate: `${migrateUrl}/simulate`,
      status: `${migrateUrl}/status`,
      spec: `${migrateUrl}/spec.md`,
      secret: link(req, `/apps/${app.id}/migration/secret`),
      users: link(req, `/apps/${app.id}/migration/users`),
      env: link(req, `/apps/${app.id}/env`),
    },
  };
}

apiRouter.get('/apps/:id/migration', need('apps:read'), async (req, res) => {
  const app = await appOr404(req);
  res.json(await migrationJson(req, app, await getAppMigration(app.id)));
});

// Fields left out keep their current value (their default on first setup). The first setup creates
// the migration secret.
apiRouter.put('/apps/:id/migration', need('apps:write'), async (req, res) => {
  const app = await appOr404(req, { write: true });
  const existing = await getAppMigration(app.id);
  const base = existing ? { enabled: existing.enabled, ...existing.settings } : { ...defaultMigrationValues(), returnUrls: [] };
  const values = migrationValuesFromJson(req.body, base);
  const { errors } = await saveAppMigration(app, values, existing, req.actor.username);
  const list = Object.entries(errors).map(([key, message]) => ({ field: apiFieldName(MIGRATION_FIELDS, key), message }));
  if (list.length) throw invalid(list[0].message, { field: list[0].field, errors: list });
  res.status(existing ? 200 : 201).json(await migrationJson(req, app, await getAppMigration(app.id)));
});

async function migrationOr404(app) {
  const migration = await getAppMigration(app.id);
  if (!migration) throw new ServiceError(404, 'migration_not_configured', 'User migration is not set up for this application. PUT its settings first.');
  return migration;
}

apiRouter.get('/apps/:id/migration/secret', need('secrets:read'), async (req, res) => {
  const app = await appOr404(req, { write: true });
  const migration = await migrationOr404(app);
  if (migration.secretUnreadable) throw new ServiceError(409, 'secret_unreadable', REQUEST_ERRORS.secret_unreadable);
  if (wantsDotenv(req)) return sendDotenv(res, [['CLOAKTAIL_MIGRATION_SECRET', migration.secret]]);
  res.json({ client_id: app.client_id, migration_secret: migration.secret });
});

apiRouter.post('/apps/:id/migration/secret/rotate', need('apps:write'), async (req, res) => {
  const app = await appOr404(req, { write: true });
  await regenerateMigrationSecret(app, await migrationOr404(app), req.actor.username);
  const { secret } = await getAppMigration(app.id);
  res.json({ client_id: app.client_id, ...(req.scopes.includes('secrets:read') ? { migration_secret: secret } : { rotated: true }) });
});

apiRouter.get('/apps/:id/migration/events', need('apps:read'), async (req, res) => {
  const app = await appOr404(req);
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 200);
  const events = await listMigrationEvents(app.id, limit);
  res.json({
    events: events.map((e) => ({
      id: e.id, status: e.status, legacy_id: e.legacy_id, username: e.username, keycloak_id: e.keycloak_id,
      detail: e.detail, created_at: iso(e.created_at), updated_at: iso(e.updated_at),
    })),
  });
});

// ---------- migrated users ----------
// CloakTail's record of which Keycloak user each legacy user (sub) became. It decides
// already_migrated. Linking an existing Keycloak account resolves a "conflict": the next request for
// that sub answers already_migrated with that account.

const migratedUserJson = (r) => ({
  sub: r.legacy_id, keycloak_id: r.keycloak_id, username: r.username, migrated_at: iso(r.migrated_at), linked_by: r.linked_by,
});

apiRouter.get('/apps/:id/migration/users', need('apps:read'), async (req, res) => {
  const app = await appOr404(req);
  await migrationOr404(app);
  res.json({ users: (await listMigratedUsers(app.id)).map(migratedUserJson) });
});

apiRouter.put('/apps/:id/migration/users/:sub', need('apps:write'), async (req, res) => {
  const app = await appOr404(req, { write: true });
  await migrationOr404(app);
  const { sub } = req.params;
  const username = req.body?.username;
  if (sub.length > 255) throw invalid('sub is at most 255 characters.', { field: 'sub' });
  if (typeof username !== 'string' || !username.trim()) throw invalid('Send {"username": "<the existing Keycloak username or email>"}.', { field: 'username' });
  // By username, then by email: a realm with "email as username" stores the email as the username.
  const wanted = username.trim().toLowerCase();
  let [user] = await sandboxAdmin.findUsersExact({ username: wanted });
  if (!user && wanted.includes('@')) [user] = await sandboxAdmin.findUsersExact({ email: wanted });
  if (!user) throw new ServiceError(404, 'keycloak_user_not_found', `No user with username or email "${username.trim()}" in the sandbox realm ${config.sandbox.realm}.`);
  const existed = await getMigratedUser(app.id, sub);
  await putMigratedUser({ appId: app.id, legacyId: sub, keycloakId: user.id, username: user.username, linkedBy: req.actor.username });
  res.status(existed ? 200 : 201).json(migratedUserJson(await getMigratedUser(app.id, sub)));
});

apiRouter.delete('/apps/:id/migration/users/:sub', need('apps:write'), async (req, res) => {
  const app = await appOr404(req, { write: true });
  if (!(await getMigratedUser(app.id, req.params.sub))) throw notFound('Migrated user');
  await deleteMigratedUser(app.id, req.params.sub);
  res.status(204).end();
});

// ---------- test users ----------

const testUserJson = (row) => ({
  id: row.id,
  username: row.username,
  email: row.kc?.email ?? null,
  first_name: row.kc?.firstName ?? null,
  last_name: row.kc?.lastName ?? null,
  enabled: row.kc?.enabled ?? null,
  missing_in_keycloak: !row.kc,
  created_at: iso(row.created_at),
});

apiRouter.use('/test-users', need('test_users'), (req, res, next) => {
  res.locals.fields = TEST_USER_FIELDS;
  next();
});

apiRouter.get('/test-users', async (req, res) => {
  const users = await listTestUsersWithDetails(req.actor.username);
  res.json({ test_users: users.map(testUserJson), max: config.sandbox.maxTestUsersPerDeveloper });
});

apiRouter.post('/test-users', async (req, res) => {
  const values = valuesFromJson(TEST_USER_FIELDS, req.body, { username: '', email: '', firstName: '', lastName: '', password: '' });
  const { password, ...profile } = values;
  profile.username = profile.username.toLowerCase();
  const id = await createTestUser(req.actor.username, profile, password);
  const row = (await listTestUsersWithDetails(req.actor.username)).find((u) => u.id === id);
  res.status(201).location(link(req, `/test-users/${id}`)).json(testUserJson(row));
});

async function testUserOr404(req) {
  const row = await findOwnTestUser(req.actor.username, req.params.id);
  if (!row) throw notFound('Test user');
  return row;
}

apiRouter.post('/test-users/:id/password', async (req, res) => {
  const row = await testUserOr404(req);
  if (typeof req.body?.password !== 'string') throw invalid('Send {"password": "…"} (at least 8 characters).', { field: 'password' });
  await setTestUserPassword(row, req.body.password);
  res.status(204).end();
});

apiRouter.delete('/test-users/:id', async (req, res) => {
  await removeTestUser(await testUserOr404(req));
  res.status(204).end();
});

// ---------- tools ----------

apiRouter.post('/tools/certificate', need('tools'), async (req, res) => {
  res.locals.fields = CERTIFICATE_FIELDS;
  const values = valuesFromJson(CERTIFICATE_FIELDS, req.body, CERTIFICATE_DEFAULTS);
  const cert = await generateCertificate(req.actor.username, values);
  res.json({
    private_key_pem: cert.privateKey,
    certificate_pem: cert.certificate,
    subject: cert.subject,
    valid_to: new Date(cert.validTo).toISOString(),
    fingerprint_sha256: cert.fingerprint,
  });
});

// ---------- errors ----------

apiRouter.use((req, res) => problem(req, res, 404, 'not_found', `No API endpoint ${req.method} ${req.baseUrl}${req.path}. See ${link(req, '/openapi.json')}.`));

// eslint-disable-next-line no-unused-vars
apiRouter.use((err, req, res, next) => {
  if (err instanceof ServiceError) {
    const extra = { ...err.extra };
    if (extra.field) extra.field = apiFieldName(res.locals.fields ?? {}, extra.field);
    return problem(req, res, err.status, err.code, err.message, extra);
  }
  if (err.type === 'entity.parse.failed') return problem(req, res, 400, 'invalid_json', 'The request body is not valid JSON.');
  if (err.type === 'entity.too.large') return problem(req, res, 413, 'too_large', 'The request body is larger than 1 MB.');
  if (err instanceof KeycloakError) {
    console.error(err);
    return problem(req, res, 502, 'keycloak_error', `Keycloak: ${err.message}`);
  }
  console.error(err);
  problem(req, res, 500, 'internal_error', 'Unexpected error. The server log has the details.');
});
