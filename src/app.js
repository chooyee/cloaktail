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
import { appsRouter, testAcsRouter } from './routes/apps.js';
import { testUsersRouter } from './routes/testUsers.js';
import { toolsRouter } from './routes/tools.js';
import { adminRouter } from './routes/admin.js';
import { config } from './config.js';
import { countApps, countTestUsers } from './db.js';
import { userContext, adminContext, requireAuth, requirePermission, csrf, sendError } from './middleware.js';
import { KeycloakError } from './lib/keycloakAdmin.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(root, 'views'));
app.disable('x-powered-by');
app.locals.registrationEnabled = config.registration.enabled;
app.locals.maxApps = config.sandbox.maxAppsPerDeveloper;
app.locals.maxTestUsers = config.sandbox.maxTestUsersPerDeveloper;

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
// The active Keycloak profile can change at runtime (admin console), so expose it per request.
app.use((req, res, next) => {
  res.locals.keycloakConfigured = config.keycloak.configured;
  res.locals.sandboxRealm = config.sandbox.realm || 'sandbox';
  res.locals.sandbox = {
    realmUrl: config.sandbox.realmUrl,
    samlEndpoint: config.sandbox.samlEndpoint,
    descriptorUrl: config.sandbox.descriptorUrl,
  };
  next();
});

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

app.use(authRouter);
app.use(testAcsRouter);
app.use('/register', registerRouter);

// Public pages. Signed-out visitors land on the product page; signed-in users get the dashboard.
const landing = (req, res) => res.render('pages/landing', { title: 'SAML SSO, tested before you ship', fullBleed: true });
app.get('/guide', landing);
app.get('/disclaimer', (req, res) => res.render('pages/disclaimer', { title: 'Disclaimer' }));
app.get('/', (req, res, next) => (req.user ? next() : landing(req, res)), requirePermission('dashboard.view'), (req, res) => {
  res.render('pages/dashboard', {
    title: 'Dashboard',
    appCount: countApps(req.user.username),
    testUserCount: countTestUsers(req.user.username),
    maxApps: config.sandbox.maxAppsPerDeveloper,
    maxTestUsers: config.sandbox.maxTestUsersPerDeveloper,
  });
});
app.use('/users', requireAuth, usersRouter);
app.use('/roles', requireAuth, rolesRouter);
app.use('/apps', requireAuth, appsRouter);
app.use('/test-users', requireAuth, testUsersRouter);
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
