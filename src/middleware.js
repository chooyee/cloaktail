import crypto from 'node:crypto';
import { currentTenant } from './config.js';
import { getUserPermissions, getUserRoles, getAdminAccount } from './db.js';

export const isHtmx = (req) => req.get('HX-Request') === 'true';

// Redirects that work for both full page loads and htmx requests.
export function redirect(req, res, url) {
  if (isHtmx(req)) return res.set('HX-Redirect', url).status(204).end();
  res.redirect(303, url);
}

// Error for the current request: a flash message for htmx, a full error page otherwise.
export function sendError(req, res, status, message) {
  res.status(status);
  res.locals.indexable = false;
  if (isHtmx(req)) {
    return res.set({ 'HX-Retarget': '#flash', 'HX-Reswap': 'innerHTML' })
      .render('fragments/flash', { type: 'error', message });
  }
  const title = { 403: 'Forbidden', 404: 'Not found' }[status] || 'Something went wrong';
  res.render('pages/error', { title, status, message });
}

// Loads the current user's app roles/permissions on every request, so role changes apply immediately.
// A sign-in only counts on the domains of the Keycloak profile it came from (domains on one host but
// different ports share cookies; sessions from before profiles had domains have no profileId).
export async function userContext(req, res, next) {
  if (req.user && req.user.profileId !== currentTenant()?.profileId) req.user = null;
  res.locals.currentPath = req.path;
  res.locals.user = req.user || null;
  const [permissions, roles] = req.user
    ? await Promise.all([getUserPermissions(req.user.username), getUserRoles(req.user.username)])
    : [new Set(), []];
  req.can = (perm) => permissions.has(perm);
  res.locals.can = req.can;
  res.locals.userRoles = roles;
  next();
}

// Admin console sign-in (local account, independent of the Keycloak sign-in above).
// Expires after ADMIN_SESSION_MS, and ends as soon as the account is deleted or its password changes.
const ADMIN_SESSION_MS = 2 * 60 * 60 * 1000;

export async function adminContext(req, res, next) {
  const signedIn = req.session?.admin;
  let admin = null;
  if (signedIn) {
    const account = await getAdminAccount(signedIn.username);
    if (account && account.password_changed_at === signedIn.passwordChangedAt && Date.now() - signedIn.since < ADMIN_SESSION_MS) {
      admin = { username: account.username, mustChangePassword: Boolean(account.must_change_password) };
    } else {
      delete req.session.admin;
    }
  }
  req.admin = admin;
  res.locals.admin = admin;
  next();
}

// Mounted under /admin. Until a temporary password is changed, only the password page is allowed.
export function requireAdmin(req, res, next) {
  if (!req.admin) {
    const target = `/admin/login?returnTo=${encodeURIComponent(req.originalUrl)}`;
    if (isHtmx(req)) return res.set('HX-Redirect', target).status(401).end();
    return res.redirect(target);
  }
  if (req.admin.mustChangePassword && req.path !== '/password') return redirect(req, res, '/admin/password');
  next();
}

export function requireAuth(req, res, next) {
  if (req.user) return next();
  const target = `/login?returnTo=${encodeURIComponent(req.originalUrl)}`;
  if (isHtmx(req)) return res.set('HX-Redirect', target).status(401).end();
  res.redirect(target);
}

export function requirePermission(...perms) {
  return (req, res, next) => {
    if (perms.every((p) => req.can(p))) return next();
    sendError(req, res, 403, 'You do not have permission to do that.');
  };
}

// For the server log: why a form token was rejected. Almost always the session cookie never came back.
function csrfFailureReason(req, expected) {
  if (!/(?:^|;\s*)sid=/.test(req.get('Cookie') || '')) {
    return 'the browser sent no session cookie (blocked cookies, or the form was opened on another domain?).';
  }
  if (!expected) return 'the session cookie matches no stored session (expired, or signed with a different SESSION_SECRET).';
  return 'the form token does not match the session (the page was opened in another session; reload it).';
}

// Synchronizer-token CSRF protection for every state-changing request from our own pages.
// SAML endpoints are excluded: they are cross-site POSTs from Keycloak protected by XML signatures.
export function csrf(req, res, next) {
  if (req.session && (req.user || req.session.admin) && !req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session?.csrfToken || '';

  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || req.path.startsWith('/saml/')) return next();

  const sent = req.get('X-CSRF-Token') || req.body?._csrf || '';
  const expected = req.session?.csrfToken || '';
  const ok = expected && sent.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected));
  if (ok) return next();
  console.warn(`[csrf] rejected ${req.method} ${req.originalUrl}: ${csrfFailureReason(req, expected)}`);
  sendError(req, res, 403, 'Invalid or expired form token. Reload the page and try again.');
}
