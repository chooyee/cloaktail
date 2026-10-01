import express from 'express';
import { keycloakAdmin, KeycloakError } from '../lib/keycloakAdmin.js';
import {
  listRoles, getUserRoles, getRolesForUsernames, setUserRoles, upsertUser, deleteLocalUser, getLocalUser,
} from '../db.js';
import { requirePermission, redirect, isHtmx, sendError } from '../middleware.js';
import { destroySessions } from '../session.js';
import { deleteOwnerResources } from '../lib/samlClients.js';

export const usersRouter = express.Router();

const PAGE_SIZE = 20;
const USERNAME_RE = /^[a-zA-Z0-9._@-]{3,64}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const toArray = (v) => (v === undefined ? [] : [].concat(v));
const trim = (v) => (typeof v === 'string' ? v.trim() : '');
const isSelf = (req, username) => req.user.username === username.toLowerCase();

function validatePassword(password, confirm) {
  if (password.length < 8) return 'Password must be at least 8 characters.';
  if (password !== confirm) return 'Passwords do not match.';
  return null;
}

// Load the Keycloak user for :id, or answer 404.
async function loadUser(req, res) {
  try {
    return await keycloakAdmin.getUser(req.params.id);
  } catch (err) {
    if (err instanceof KeycloakError && err.status === 404) {
      sendError(req, res, 404, 'User not found in Keycloak.');
      return null;
    }
    throw err;
  }
}

// ---------- list ----------

usersRouter.get('/', requirePermission('users.view'), async (req, res) => {
  const search = trim(req.query.q);
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const [users, total] = await Promise.all([
    keycloakAdmin.listUsers({ search, first: (page - 1) * PAGE_SIZE, max: PAGE_SIZE }),
    keycloakAdmin.countUsers({ search }),
  ]);
  const rolesByUser = getRolesForUsernames(users.map((u) => u.username));
  const data = {
    title: 'Users',
    users: users.map((u) => ({ ...u, appRoles: rolesByUser.get(u.username.toLowerCase()) || [] })),
    search,
    page,
    pageCount: Math.max(1, Math.ceil(total / PAGE_SIZE)),
    total,
  };
  // Search box and pager swap only the table.
  if (isHtmx(req) && req.get('HX-Target') === 'users-table') return res.render('fragments/users-table', data);
  res.render('pages/users/list', data);
});

// ---------- create ----------

usersRouter.get('/new', requirePermission('users.create'), (req, res) => {
  res.render('pages/users/new', { title: 'New user', roles: listRoles(), values: { enabled: true, temporary: true }, error: null });
});

usersRouter.post('/', requirePermission('users.create'), async (req, res) => {
  const values = {
    username: trim(req.body.username).toLowerCase(),
    email: trim(req.body.email),
    firstName: trim(req.body.firstName),
    lastName: trim(req.body.lastName),
    enabled: req.body.enabled === 'on',
    password: req.body.password || '',
    temporary: req.body.temporary === 'on',
    roleIds: toArray(req.body.roleIds).map(Number),
  };
  const renderForm = (error) =>
    res.status(isHtmx(req) ? 200 : 422).render('pages/users/new', { title: 'New user', roles: listRoles(), values, error });

  if (!USERNAME_RE.test(values.username)) return renderForm('Username must be 3-64 characters: letters, digits, . _ @ -');
  if (values.email && !EMAIL_RE.test(values.email)) return renderForm('Enter a valid email address.');
  if (values.password) {
    const pwError = validatePassword(values.password, req.body.confirmPassword || '');
    if (pwError) return renderForm(pwError);
  }

  let id;
  try {
    id = await keycloakAdmin.createUser(values);
  } catch (err) {
    if (err instanceof KeycloakError && err.status < 500) return renderForm(err.message);
    throw err;
  }

  upsertUser({ username: values.username, keycloakId: id, email: values.email, firstName: values.firstName, lastName: values.lastName });
  if (req.can('users.assign_roles') && values.roleIds.length) setUserRoles(values.username, values.roleIds);
  redirect(req, res, `/users/${id}?created=1`);
});

// ---------- detail ----------

usersRouter.get('/:id', requirePermission('users.view'), async (req, res) => {
  const kcUser = await loadUser(req, res);
  if (!kcUser) return;
  res.render('pages/users/edit', {
    title: kcUser.username,
    kcUser,
    localUser: getLocalUser(kcUser.username),
    appRoles: getUserRoles(kcUser.username),
    roles: listRoles(),
    created: 'created' in req.query,
  });
});

// ---------- profile + enable/disable ----------

usersRouter.post('/:id/profile', requirePermission('users.edit'), async (req, res) => {
  const kcUser = await loadUser(req, res);
  if (!kcUser) return;
  const changes = {
    email: trim(req.body.email),
    firstName: trim(req.body.firstName),
    lastName: trim(req.body.lastName),
    enabled: req.body.enabled === 'on',
  };
  const render = (locals) => res.render('fragments/user-profile', { kcUser: { ...kcUser, ...changes }, ...locals });

  if (changes.email && !EMAIL_RE.test(changes.email)) return render({ error: 'Enter a valid email address.' });
  if (!changes.enabled && isSelf(req, kcUser.username)) return render({ error: 'You cannot disable your own account.' });

  try {
    await keycloakAdmin.updateUser(kcUser.id, changes);
  } catch (err) {
    if (err instanceof KeycloakError && err.status < 500) return render({ error: err.message });
    throw err;
  }
  upsertUser({ username: kcUser.username, keycloakId: kcUser.id, ...changes });

  if (kcUser.enabled && !changes.enabled) {
    // Disabled: end their Keycloak SSO sessions and their sessions in this app.
    await keycloakAdmin.logoutUser(kcUser.id);
    await destroySessions((u) => u.username === kcUser.username.toLowerCase());
  }
  render({ message: 'Profile saved.' });
});

// ---------- app roles ----------

usersRouter.post('/:id/roles', requirePermission('users.assign_roles'), async (req, res) => {
  const kcUser = await loadUser(req, res);
  if (!kcUser) return;
  const roles = listRoles();
  const roleIds = toArray(req.body.roleIds).map(Number).filter((id) => roles.some((r) => r.id === id));
  const render = (locals) =>
    res.render('fragments/user-roles', { kcUser, roles, appRoles: getUserRoles(kcUser.username), ...locals });

  const adminRole = roles.find((r) => r.name === 'admin');
  if (isSelf(req, kcUser.username) && getUserRoles(kcUser.username).some((r) => r.name === 'admin') && !roleIds.includes(adminRole.id)) {
    return render({ error: 'You cannot remove the admin role from yourself.' });
  }
  setUserRoles(kcUser.username, roleIds);
  render({ message: 'Roles updated. Changes apply on the user\'s next request.' });
});

// ---------- password ----------

usersRouter.post('/:id/password', requirePermission('users.reset_password'), async (req, res) => {
  const kcUser = await loadUser(req, res);
  if (!kcUser) return;
  const render = (locals) => res.render('fragments/user-password', { kcUser, ...locals });

  const password = req.body.password || '';
  const pwError = validatePassword(password, req.body.confirmPassword || '');
  if (pwError) return render({ error: pwError });
  try {
    await keycloakAdmin.resetPassword(kcUser.id, password, req.body.temporary === 'on');
  } catch (err) {
    // Keycloak rejects passwords that break the realm password policy with 400.
    if (err instanceof KeycloakError && err.status < 500) return render({ error: err.message });
    throw err;
  }
  render({ message: req.body.temporary === 'on' ? 'Password reset. The user must change it at next login.' : 'Password reset.' });
});

// ---------- delete ----------

usersRouter.post('/:id/delete', requirePermission('users.delete'), async (req, res) => {
  const kcUser = await loadUser(req, res);
  if (!kcUser) return;
  if (isSelf(req, kcUser.username)) return sendError(req, res, 400, 'You cannot delete your own account.');
  await keycloakAdmin.deleteUser(kcUser.id);
  // Their sandbox applications and test users go too.
  await deleteOwnerResources(kcUser.username.toLowerCase());
  deleteLocalUser(kcUser.username);
  await destroySessions((u) => u.username === kcUser.username.toLowerCase());
  redirect(req, res, '/users');
});
