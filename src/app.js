import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import passport from 'passport';
import { sessionMiddleware } from './session.js';
import { authRouter } from './auth.js';
import { usersRouter } from './routes/users.js';
import { rolesRouter } from './routes/roles.js';
import { registerRouter } from './routes/register.js';
import { migrateRouter } from './routes/migrate.js';
import { appsRouter, testAcsRouter } from './routes/apps.js';
import { testUsersRouter } from './routes/testUsers.js';
import { toolsRouter, publicToolsRouter } from './routes/tools.js';
import { adminRouter } from './routes/admin.js';
import { config, tenantContext } from './config.js';
import { tenantForOrigin } from './keycloakProfiles.js';
import { countApps, countTestUsers } from './db.js';
import { userContext, adminContext, requireAuth, requirePermission, csrf, sendError } from './middleware.js';
import { KeycloakError } from './lib/keycloakAdmin.js';
import * as content from './content.js';
import * as seo from './seo.js';
import { highlight } from './lib/highlight.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(root, 'views'));
app.disable('x-powered-by');
// Behind a TLS-terminating reverse proxy, trust its X-Forwarded-* headers so secure session cookies
// are sent and req.ip is the client's address.
if (config.trustProxy !== null) app.set('trust proxy', config.trustProxy);
app.locals.registrationEnabled = config.registration.enabled;
app.locals.maxApps = config.sandbox.maxAppsPerDeveloper;
app.locals.maxTestUsers = config.sandbox.maxTestUsersPerDeveloper;
app.locals.indexable = false;
app.locals.canonicalUrl = config.baseUrl;
app.locals.content = content;
app.locals.highlight = highlight;

// Every request is served by the Keycloak profile mapped to its domain (admin console), and runs in
// its context: config.keycloak/sandbox/saml and the database are that profile's. The Host header is
// only trusted to pick among configured domains. Other hosts get 421, except that the admin console
// (and its static files) always answers on BASE_URL, so a fresh install can be set up.
// req.protocol and req.host honour X-Forwarded-Proto/-Host only when TRUST_PROXY is set.
const baseHost = new URL(config.baseUrl).host;
const adminOnBaseUrl = (req) => req.host === baseHost && /^\/(admin|static)(\/|$)/.test(req.path);

app.use((req, res, next) => {
  const origin = `${req.protocol}://${req.host || ''}`.toLowerCase();
  const tenant = tenantForOrigin(origin);
  if (!tenant && !adminOnBaseUrl(req)) {
    const hint = req.protocol === 'http' && tenantForOrigin(origin.replace(/^http:/, 'https:'))
      ? ' It is configured for HTTPS: behind a reverse proxy that terminates HTTPS, set TRUST_PROXY.' : '';
    return res.status(421).type('text/plain').send(`No Keycloak profile serves ${origin}.${hint}`
      + (req.host === baseHost ? ` An administrator can assign it one at ${config.baseUrl}/admin/keycloak.` : ''));
  }
  req.siteUrl = tenant?.siteUrl ?? config.baseUrl;
  tenantContext.run(tenant, next);
});

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
  });
  next();
});

app.use('/static', express.static(path.join(root, 'public'), { maxAge: '1h' }));
// Version the stylesheet URL by its modification time so a rebuilt app.css is never served stale.
const cssFile = path.join(root, 'public/css/app.css');
app.use((req, res, next) => {
  try { res.locals.cssVersion = Math.floor(fs.statSync(cssFile).mtimeMs).toString(36); } catch { res.locals.cssVersion = '0'; }
  next();
});
// The Keycloak profile depends on the domain and can change at runtime (admin console), so expose it per request.
app.use((req, res, next) => {
  res.locals.keycloakConfigured = config.keycloak.configured;
  res.locals.sandboxRealm = config.sandbox.realm || 'sandbox';
  res.locals.sandbox = {
    realmUrl: config.sandbox.realmUrl,
    samlEndpoint: config.sandbox.samlEndpoint,
    descriptorUrl: config.sandbox.descriptorUrl,
    jwksUri: config.sandbox.oidc.jwksUri,
    discoveryUrl: config.sandbox.oidc.discoveryUrl,
  };
  next();
});

// Crawler files (src/seo.js). Before the session middleware so crawlers don't create sessions.
// Each domain is its own site, so links in them use the request's domain.
app.get('/robots.txt', (req, res) => res.type('text/plain').send(seo.robotsText({ baseUrl: req.siteUrl })));
app.get('/sitemap.xml', (req, res) => res.type('application/xml').send(seo.sitemapXml({ baseUrl: req.siteUrl })));
const markdown = (full) => (req, res) => res.type('text/markdown; charset=utf-8')
  .set('Cache-Control', 'public, max-age=3600').send(seo.llmsText({ full, baseUrl: req.siteUrl }));
app.get('/llms.txt', markdown(false));
app.get('/llms-full.txt', markdown(true));

app.use('/static/vendor/htmx.min.js', (req, res) =>
  res.sendFile(path.join(root, 'node_modules/htmx.org/dist/htmx.min.js')));
app.use('/static/vendor/basecoat.min.js', (req, res) =>
  res.sendFile(path.join(root, 'node_modules/basecoat-css/dist/js/all.min.js')));

app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(sessionMiddleware);
app.use(passport.session());
app.use(userContext);
app.use(adminContext);
app.use(csrf);
// Search engines index only the public pages, as signed-out visitors see them. /guide is the
// landing page for signed-in users, so its canonical URL is /.
app.use((req, res, next) => {
  res.locals.indexable = !req.user && seo.indexedPaths().includes(req.path);
  res.locals.canonicalUrl = req.siteUrl + (req.path === '/guide' ? '/' : req.path);
  next();
});

app.use(authRouter);
app.use(testAcsRouter);
app.use('/register', registerRouter);
// User migration: legacy applications send their users here to move them into Keycloak.
app.use('/migrate', migrateRouter);

// Public pages. Signed-out visitors land on the product page; signed-in users get the dashboard.
const landing = (req, res) => res.render('pages/landing', {
  title: 'Test Keycloak SAML and OIDC SSO before you ship',
  description: 'Self-service Keycloak sandbox for SAML and OpenID Connect. Register a SAML or OIDC client, sign in as a test user, and inspect signatures, attributes, ID tokens and claims.',
  keywords: content.keywords,
  fullBleed: true,
});
app.get('/guide', landing);
app.get('/troubleshooting', (req, res) => res.render('pages/troubleshooting/index', {
  title: 'Keycloak SAML and OIDC errors and how to fix them',
  description: 'Fixes for common Keycloak SAML and OpenID Connect errors: invalid requester, invalid redirect_uri, invalid_client, missing code_challenge_method, invalid_grant, audience and signature failures.',
}));
app.get('/troubleshooting/:slug', (req, res) => {
  const problem = content.findProblem(req.params.slug);
  if (!problem) return sendError(req, res, 404, 'Page not found.');
  res.render('pages/troubleshooting/problem', {
    title: `${problem.q.replace(/[“”]/g, '')}: Keycloak ${problem.protocol} fix`,
    description: problem.a,
    problem,
    baseUrl: req.siteUrl,
  });
});
app.get('/disclaimer', (req, res) => res.render('pages/disclaimer', {
  title: 'Disclaimer',
  description: 'CloakTail and its sandbox realm are for development and testing only. Do not use real personal data or production credentials.',
}));
app.get('/', (req, res, next) => (req.user ? next() : landing(req, res)), requirePermission('dashboard.view'), async (req, res) => {
  const [appCount, testUserCount] = await Promise.all([countApps(req.user.username), countTestUsers(req.user.username)]);
  res.render('pages/dashboard', {
    title: 'Dashboard',
    appCount,
    testUserCount,
    maxApps: config.sandbox.maxAppsPerDeveloper,
    maxTestUsers: config.sandbox.maxTestUsersPerDeveloper,
  });
});
app.use('/users', requireAuth, usersRouter);
app.use('/roles', requireAuth, rolesRouter);
app.use('/apps', requireAuth, appsRouter);
app.use('/test-users', requireAuth, testUsersRouter);
app.use('/tools', publicToolsRouter);
app.use('/tools', requireAuth, toolsRouter);
app.use('/admin', adminRouter);

app.use((req, res) => sendError(req, res, 404, 'Page not found.'));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  const message = err instanceof KeycloakError
    ? `Keycloak: ${err.message}`
    : 'Unexpected error. Check the server log.';
  sendError(req, res, 500, message);
});

export default app;
