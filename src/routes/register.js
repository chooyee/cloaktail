import crypto from 'node:crypto';
import express from 'express';
import { config } from '../config.js';
import { keycloakAdmin, KeycloakError } from '../lib/keycloakAdmin.js';
import { upsertUser, addUserRoleByName } from '../db.js';
import { sendError } from '../middleware.js';

export const registerRouter = express.Router();

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,39}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Per-IP limit on sign-up attempts (in memory; use a shared store behind a load balancer).
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const attempts = new Map();

function rateLimited(ip) {
  const now = Date.now();
  const recent = (attempts.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  attempts.set(ip, recent);
  return recent.length > MAX_ATTEMPTS;
}

registerRouter.use((req, res, next) => {
  if (!config.registration.enabled) return sendError(req, res, 404, 'Registration is closed.');
  if (req.user) return res.redirect('/');
  // Anonymous visitors need a session-bound CSRF token for this form.
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

// `field` names the input the error belongs to, so the page can mark it invalid.
const render = (res, values, error = null, field = null) =>
  res.status(error ? 422 : 200).render('pages/register', {
    title: 'Create your account',
    description: 'Create a free CloakTail developer account to get your own Keycloak sandbox: SAML and OpenID Connect clients, test users and verified test logins.',
    values, error, field,
  });

// Keycloak's messages don't say which field failed; infer it for inline display.
function fieldForKeycloakError(message) {
  const m = message.toLowerCase();
  if (m.includes('email')) return 'email';
  if (m.includes('username')) return 'username';
  if (m.includes('password')) return 'password';
  return null;
}

registerRouter.get('/', (req, res) => render(res, {}));

registerRouter.post('/', async (req, res) => {
  const values = {
    username: (req.body.username || '').trim().toLowerCase(),
    email: (req.body.email || '').trim(),
    firstName: (req.body.firstName || '').trim(),
    lastName: (req.body.lastName || '').trim(),
  };
  const password = req.body.password || '';

  // Honeypot: real users never see or fill this field.
  if (req.body.website) return res.redirect(303, '/login?registered');
  if (rateLimited(req.ip)) return render(res, values, 'Too many sign-up attempts. Try again in 15 minutes.');

  if (!USERNAME_RE.test(values.username)) {
    return render(res, values, 'Use 3–40 lowercase letters, digits, dots, dashes or underscores, starting with a letter or digit.', 'username');
  }
  if (!EMAIL_RE.test(values.email)) return render(res, values, 'Enter a valid email address, like name@company.com.', 'email');
  if (!values.firstName) return render(res, values, 'Enter your first name.', 'firstName');
  if (!values.lastName) return render(res, values, 'Enter your last name.', 'lastName');
  if (password.length < 8) return render(res, values, 'Use at least 8 characters.', 'password');
  if (password !== req.body.confirmPassword) return render(res, values, 'Passwords don’t match.', 'confirmPassword');
  if (req.body.acceptDisclaimer !== 'on') return render(res, values, 'Accept the disclaimer to continue.', 'acceptDisclaimer');

  try {
    await keycloakAdmin.createUser({
      ...values,
      password,
      temporary: false,
      requiredActions: config.registration.verifyEmail ? ['VERIFY_EMAIL'] : undefined,
    });
  } catch (err) {
    // 409 = username/email taken; 400 = realm password policy or user profile rules.
    if (err instanceof KeycloakError && err.status < 500) return render(res, values, err.message, fieldForKeycloakError(err.message));
    throw err;
  }

  await upsertUser(values);
  await addUserRoleByName(values.username, config.defaultRole);
  res.redirect(303, '/login?registered');
});
