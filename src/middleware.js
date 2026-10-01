import crypto from 'node:crypto';
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
  if (isHtmx(req)) {
    return res.set({ 'HX-Retarget': '#flash', 'HX-Reswap': 'innerHTML' })
      .render('fragments/flash', { type: 'error', message });
  }
  const title = { 403: 'Forbidden', 404: 'Not found' }[status] || 'Something went wrong';
  res.render('pages/error', { title, status, message });
}

// Loads the current user's app roles/permissions on every request, so role changes apply immediately.
export function userContext(req, res, next) {
  res.locals.currentPath = req.path;
  res.locals.user = req.user || null;
  const permissions = req.user ? getUserPermissions(req.user.username) : new Set();
  req.can = (perm) => permissions.has(perm);
  res.locals.can = req.can;
  res.locals.userRoles = req.user ? getUserRoles(req.user.username) : [];
  next();
}

// Admin console sign-in (local account, independent of the Keycloak sign-in above).
// Expires after ADMIN_SESSION_MS, and ends as soon as the account is deleted or its password changes.
const ADMIN_SESSION_MS = 2 * 60 * 60 * 1000;

export function adminContext(req, res, next) {
  const signedIn = req.session?.admin;
  let admin = null;
  if (signedIn) {
    const account = getAdminAccount(signedIn.username);
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
  sendError(req, res, 403, 'Invalid or expired form token. Reload the page and try again.');
}
