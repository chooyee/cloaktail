import express from 'express';
import { listRoles, getRole, listPermissions, createRole, updateRole, deleteRole } from '../db.js';
import { requirePermission, redirect, isHtmx, sendError } from '../middleware.js';

export const rolesRouter = express.Router();

const ROLE_NAME_RE = /^[a-z0-9][a-z0-9_-]{1,39}$/;
const toArray = (v) => (v === undefined ? [] : [].concat(v));

async function loadRole(req, res) {
  const role = await getRole(Number(req.params.id));
  if (!role) sendError(req, res, 404, 'Role not found.');
  return role;
}

rolesRouter.get('/', requirePermission('roles.view'), async (req, res) => {
  res.render('pages/roles/list', { title: 'Roles', roles: await listRoles(), values: {}, error: null });
});

rolesRouter.post('/', requirePermission('roles.manage'), async (req, res) => {
  const values = { name: (req.body.name || '').trim().toLowerCase(), description: (req.body.description || '').trim() };
  const roles = await listRoles();
  const renderForm = (error) =>
    res.status(isHtmx(req) ? 200 : 422).render('pages/roles/list', { title: 'Roles', roles, values, error });

  if (!ROLE_NAME_RE.test(values.name)) {
    return renderForm('Name must be 2-40 characters: lowercase letters, digits, - or _, starting with a letter or digit.');
  }
  if (roles.some((r) => r.name === values.name)) return renderForm(`Role "${values.name}" already exists.`);
  const id = await createRole(values.name, values.description);
  redirect(req, res, `/roles/${id}`);
});

rolesRouter.get('/:id', requirePermission('roles.view'), async (req, res) => {
  const role = await loadRole(req, res);
  if (!role) return;
  res.render('pages/roles/edit', { title: `Role: ${role.name}`, role, permissions: await listPermissions(), message: null, error: null });
});

rolesRouter.post('/:id', requirePermission('roles.manage'), async (req, res) => {
  const role = await loadRole(req, res);
  if (!role) return;
  const render = async (locals) =>
    res.render('fragments/role-form', { role: await getRole(role.id), permissions: await listPermissions(), ...locals });

  // admin always keeps every permission so there is always a way back in.
  if (role.name === 'admin') return render({ error: 'The admin role always has every permission.' });
  await updateRole(role.id, (req.body.description || '').trim(), toArray(req.body.permissions));
  await render({ message: 'Role saved. Changes apply to its users on their next request.' });
});

rolesRouter.post('/:id/delete', requirePermission('roles.manage'), async (req, res) => {
  const role = await loadRole(req, res);
  if (!role) return;
  if (role.is_system) return sendError(req, res, 400, 'System roles cannot be deleted.');
  await deleteRole(role.id);
  redirect(req, res, '/roles');
});
