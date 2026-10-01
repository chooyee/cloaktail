import express from 'express';
import { listRoles, getRole, listPermissions, createRole, updateRole, deleteRole } from '../db.js';
import { requirePermission, redirect, isHtmx, sendError } from '../middleware.js';

export const rolesRouter = express.Router();

const ROLE_NAME_RE = /^[a-z0-9][a-z0-9_-]{1,39}$/;
const toArray = (v) => (v === undefined ? [] : [].concat(v));

function loadRole(req, res) {
  const role = getRole(Number(req.params.id));
  if (!role) sendError(req, res, 404, 'Role not found.');
  return role;
}

rolesRouter.get('/', requirePermission('roles.view'), (req, res) => {
  res.render('pages/roles/list', { title: 'Roles', roles: listRoles(), values: {}, error: null });
});

rolesRouter.post('/', requirePermission('roles.manage'), (req, res) => {
  const values = { name: (req.body.name || '').trim().toLowerCase(), description: (req.body.description || '').trim() };
  const renderForm = (error) =>
    res.status(isHtmx(req) ? 200 : 422).render('pages/roles/list', { title: 'Roles', roles: listRoles(), values, error });

  if (!ROLE_NAME_RE.test(values.name)) {
    return renderForm('Name must be 2-40 characters: lowercase letters, digits, - or _, starting with a letter or digit.');
  }
  if (listRoles().some((r) => r.name === values.name)) return renderForm(`Role "${values.name}" already exists.`);
  const id = createRole(values.name, values.description);
  redirect(req, res, `/roles/${id}`);
});

rolesRouter.get('/:id', requirePermission('roles.view'), (req, res) => {
  const role = loadRole(req, res);
  if (!role) return;
  res.render('pages/roles/edit', { title: `Role: ${role.name}`, role, permissions: listPermissions(), message: null, error: null });
});

rolesRouter.post('/:id', requirePermission('roles.manage'), (req, res) => {
  const role = loadRole(req, res);
  if (!role) return;
  const render = (locals) =>
    res.render('fragments/role-form', { role: getRole(role.id), permissions: listPermissions(), ...locals });

  // admin always keeps every permission so there is always a way back in.
  if (role.name === 'admin') return render({ error: 'The admin role always has every permission.' });
  updateRole(role.id, (req.body.description || '').trim(), toArray(req.body.permissions));
  render({ message: 'Role saved. Changes apply to its users on their next request.' });
});

rolesRouter.post('/:id/delete', requirePermission('roles.manage'), (req, res) => {
  const role = loadRole(req, res);
  if (!role) return;
  if (role.is_system) return sendError(req, res, 400, 'System roles cannot be deleted.');
  deleteRole(role.id);
  redirect(req, res, '/roles');
});
