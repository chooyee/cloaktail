import { AsyncLocalStorage } from 'node:async_hooks';
import fs from 'node:fs';
import pg from 'pg';
import { config } from './config.js';

// Permissions are defined in code because route guards check them by key.
// Roles (and which permissions they grant) are data, managed from the UI.
export const PERMISSIONS = {
  'dashboard.view': 'View the dashboard',
  'users.view': 'View users',
  'users.create': 'Create users in Keycloak',
  'users.edit': 'Edit user profile and enable/disable users',
  'users.reset_password': 'Reset user passwords',
  'users.delete': 'Delete users from Keycloak',
  'users.assign_roles': 'Assign app roles to users',
  'roles.view': 'View roles',
  'roles.manage': 'Create, edit and delete roles',
  'apps.own': 'Register own SAML applications and test users in the sandbox',
  'apps.view_all': "View every developer's applications",
  'apps.manage_all': "Edit and delete any developer's applications",
};

const SEED_ROLES = [
  { name: 'admin', description: 'Full access', system: 1, permissions: Object.keys(PERMISSIONS) },
  {
    name: 'user-manager',
    description: 'Manage users and their roles',
    system: 0,
    permissions: [
      'dashboard.view', 'users.view', 'users.create', 'users.edit',
      'users.reset_password', 'users.assign_roles', 'roles.view',
    ],
  },
  { name: 'viewer', description: 'Read-only access', system: 0, permissions: ['dashboard.view'] },
  { name: 'developer', description: 'Self-service SAML applications in the sandbox', system: 0, permissions: ['dashboard.view', 'apps.own'] },
];

const pool = new pg.Pool({ ...config.db, admin: undefined });
pool.on('error', (err) => console.error('PostgreSQL pool error:', err));

// Queries inside transaction() run on its client; everything else uses the pool.
const txClient = new AsyncLocalStorage();
const exec = (sql, params = []) => (txClient.getStore() ?? pool).query(sql, params);
const all = async (sql, params) => (await exec(sql, params)).rows;
const one = async (sql, params) => (await exec(sql, params)).rows[0] ?? null;

// Runs fn in a transaction (joining the current one when nested) and returns its result.
export async function transaction(fn) {
  if (txClient.getStore()) return fn();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await txClient.run(client, fn);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export const closeDb = () => pool.end();

// Timestamps are stored as UTC text 'YYYY-MM-DD HH:MM:SS', as views and comparisons expect strings.
const NOW = "to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')";

// Ids come from URLs; anything that isn't a valid INTEGER key simply matches nothing.
const validId = (id) => Number.isInteger(id) && id > 0 && id <= 2147483647;

// Creates whatever in db/schema.sql is missing. It runs nothing when the schema is complete, so the
// app user needs no CREATE privilege afterwards (CREATE ... IF NOT EXISTS still checks privileges).
// With dbadminuser/dbadminpassword set, the schema is created with that account and the app user
// is granted access to the tables; otherwise the app user creates them itself.
async function ensureSchema() {
  const schemaSql = fs.readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8');
  const names = [...schemaSql.matchAll(/CREATE (?:UNIQUE )?(?:TABLE|INDEX) IF NOT EXISTS (\w+)/g)].map((m) => m[1]);
  const { missing } = await one('SELECT array_agg(n) FILTER (WHERE to_regclass(n) IS NULL) AS missing FROM unnest($1::text[]) n', [names]);
  if (!missing) return;

  const { admin, ...appDb } = config.db;
  const appUser = (await one('SELECT current_user AS u')).u;
  const client = admin ? new pg.Client({ ...appDb, ...admin }) : await pool.connect();
  try {
    if (admin) await client.connect();
    await client.query('BEGIN');
    await client.query(schemaSql);
    if (admin && admin.user !== appUser) {
      const tables = [...schemaSql.matchAll(/CREATE TABLE IF NOT EXISTS (\w+)/g)].map((m) => client.escapeIdentifier(m[1]));
      await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ${tables.join(', ')} TO ${client.escapeIdentifier(appUser)}`);
    }
    await client.query('COMMIT');
    console.log(`Created the database schema (${missing.join(', ')})${admin ? ` as "${admin.user}"` : ''}.`);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (err.code !== '42501') throw err;
    const user = admin?.user ?? appUser;
    const database = appDb.database ?? '<database>';
    console.error(`PostgreSQL user "${user}" may not create tables in database "${database}" (missing: ${missing.join(', ')}).\n`
      + 'Set dbadminuser/dbadminpassword to an account that may (e.g. the database owner), or grant it once as a superuser:\n'
      + `  \\c ${database}\n  GRANT CREATE ON SCHEMA public TO ${user};`);
    process.exit(1);
  } finally {
    if (admin) await client.end().catch(() => {});
    else client.release();
  }
}

await ensureSchema();

await transaction(async () => {
  for (const [key, description] of Object.entries(PERMISSIONS)) {
    await exec(
      'INSERT INTO permissions (key, description) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET description = excluded.description',
      [key, description],
    );
  }
  await exec('DELETE FROM permissions WHERE key <> ALL($1)', [Object.keys(PERMISSIONS)]);

  for (const role of SEED_ROLES) {
    if (await one('SELECT id FROM roles WHERE name = $1', [role.name])) continue;
    const { id } = await one(
      'INSERT INTO roles (name, description, is_system) VALUES ($1, $2, $3) RETURNING id',
      [role.name, role.description, role.system],
    );
    for (const perm of role.permissions) {
      await exec('INSERT INTO role_permissions (role_id, permission_key) VALUES ($1, $2)', [id, perm]);
    }
  }

  // The admin role always holds every permission, including ones added later.
  const admin = await one("SELECT id FROM roles WHERE name = 'admin'");
  for (const perm of Object.keys(PERMISSIONS)) {
    await exec('INSERT INTO role_permissions (role_id, permission_key) VALUES ($1, $2) ON CONFLICT DO NOTHING', [admin.id, perm]);
  }
});

// ---------- users ----------

export async function upsertUser({ username, keycloakId, email, firstName, lastName }, { login = false } = {}) {
  username = username.toLowerCase();
  await exec(`
    INSERT INTO users (username, keycloak_id, email, first_name, last_name, last_login_at)
    VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 THEN ${NOW} END)
    ON CONFLICT (username) DO UPDATE SET
      keycloak_id   = COALESCE(excluded.keycloak_id, users.keycloak_id),
      email         = COALESCE(excluded.email, users.email),
      first_name    = COALESCE(excluded.first_name, users.first_name),
      last_name     = COALESCE(excluded.last_name, users.last_name),
      last_login_at = COALESCE(excluded.last_login_at, users.last_login_at)
  `, [username, keycloakId ?? null, email ?? null, firstName ?? null, lastName ?? null, Boolean(login)]);
  return username;
}

export const getLocalUser = (username) =>
  one('SELECT * FROM users WHERE username = $1', [username.toLowerCase()]);

export async function deleteLocalUser(username) {
  await exec('DELETE FROM users WHERE username = $1', [username.toLowerCase()]);
}

export const getUserRoles = (username) => all(`
  SELECT r.id, r.name FROM roles r
  JOIN user_roles ur ON ur.role_id = r.id
  WHERE ur.username = $1 ORDER BY r.name
`, [username.toLowerCase()]);

export async function getRolesForUsernames(usernames) {
  const map = new Map(usernames.map((u) => [u.toLowerCase(), []]));
  if (!usernames.length) return map;
  const rows = await all(`
    SELECT ur.username, r.id, r.name FROM user_roles ur
    JOIN roles r ON r.id = ur.role_id
    WHERE ur.username = ANY($1)
    ORDER BY r.name
  `, [usernames.map((u) => u.toLowerCase())]);
  for (const row of rows) map.get(row.username)?.push({ id: row.id, name: row.name });
  return map;
}

export async function getUserPermissions(username) {
  const rows = await all(`
    SELECT DISTINCT rp.permission_key AS key FROM role_permissions rp
    JOIN user_roles ur ON ur.role_id = rp.role_id
    WHERE ur.username = $1
  `, [username.toLowerCase()]);
  return new Set(rows.map((r) => r.key));
}

export const setUserRoles = (username, roleIds) => transaction(async () => {
  username = await upsertUser({ username });
  await exec('DELETE FROM user_roles WHERE username = $1', [username]);
  for (const id of roleIds.filter(validId)) {
    await exec('INSERT INTO user_roles (username, role_id) SELECT $1, id FROM roles WHERE id = $2', [username, id]);
  }
});

export async function addUserRoleByName(username, roleName) {
  await exec(
    'INSERT INTO user_roles (username, role_id) SELECT $1, id FROM roles WHERE name = $2 ON CONFLICT DO NOTHING',
    [username.toLowerCase(), roleName],
  );
}

// ---------- roles ----------

export const listRoles = () => all(`
  SELECT r.*,
    (SELECT COUNT(*)::int FROM role_permissions rp WHERE rp.role_id = r.id) AS permission_count,
    (SELECT COUNT(*)::int FROM user_roles ur WHERE ur.role_id = r.id) AS user_count
  FROM roles r ORDER BY r.is_system DESC, r.name
`);

export async function getRole(id) {
  if (!validId(id)) return null;
  const role = await one('SELECT * FROM roles WHERE id = $1', [id]);
  if (!role) return null;
  const [perms, users] = await Promise.all([
    all('SELECT permission_key FROM role_permissions WHERE role_id = $1', [id]),
    all('SELECT username FROM user_roles WHERE role_id = $1 ORDER BY username', [id]),
  ]);
  role.permissions = new Set(perms.map((r) => r.permission_key));
  role.users = users.map((r) => r.username);
  return role;
}

export const listPermissions = () => all('SELECT * FROM permissions ORDER BY key');

export async function createRole(name, description) {
  return (await one('INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING id', [name, description])).id;
}

export const updateRole = (id, description, permissionKeys) => transaction(async () => {
  await exec('UPDATE roles SET description = $1 WHERE id = $2', [description, id]);
  await exec('DELETE FROM role_permissions WHERE role_id = $1', [id]);
  for (const key of permissionKeys) {
    await exec('INSERT INTO role_permissions (role_id, permission_key) SELECT $1::int, key FROM permissions WHERE key = $2', [id, key]);
  }
});

export async function deleteRole(id) {
  await exec('DELETE FROM roles WHERE id = $1 AND is_system = 0', [id]);
}

// ---------- developer apps ----------

export function listApps({ owner } = {}) {
  const base = `
    SELECT a.*,
      (SELECT ok FROM test_runs t WHERE t.app_id = a.id ORDER BY t.id DESC LIMIT 1) AS last_test_ok,
      (SELECT created_at FROM test_runs t WHERE t.app_id = a.id ORDER BY t.id DESC LIMIT 1) AS last_test_at
    FROM apps a`;
  return owner
    ? all(`${base} WHERE a.owner = $1 ORDER BY a.created_at DESC`, [owner])
    : all(`${base} ORDER BY a.owner, a.created_at DESC`);
}

export const countApps = async (owner) => (await one('SELECT COUNT(*)::int AS n FROM apps WHERE owner = $1', [owner])).n;
export const getApp = async (id) => (validId(id) ? one('SELECT * FROM apps WHERE id = $1', [id]) : null);

export async function insertApp({ owner, kcId, clientId, name }) {
  return (await one(
    'INSERT INTO apps (owner, kc_id, client_id, name) VALUES ($1, $2, $3, $4) RETURNING id',
    [owner, kcId, clientId, name],
  )).id;
}

export const renameApp = (id, name) => exec('UPDATE apps SET name = $1 WHERE id = $2', [name, id]);
export const deleteApp = (id) => exec('DELETE FROM apps WHERE id = $1', [id]);

// ---------- sandbox test users ----------

export const listTestUsers = (owner) =>
  all('SELECT * FROM test_users WHERE owner = $1 ORDER BY username', [owner]);
export const countTestUsers = async (owner) =>
  (await one('SELECT COUNT(*)::int AS n FROM test_users WHERE owner = $1', [owner])).n;
export const getTestUser = async (id) => (validId(id) ? one('SELECT * FROM test_users WHERE id = $1', [id]) : null);

export async function insertTestUser({ owner, kcId, username }) {
  return (await one(
    'INSERT INTO test_users (owner, kc_id, username) VALUES ($1, $2, $3) RETURNING id',
    [owner, kcId, username],
  )).id;
}

export const deleteTestUser = (id) => exec('DELETE FROM test_users WHERE id = $1', [id]);

// ---------- test runs ----------

const KEEP_TEST_RUNS = 10;

export const insertTestRun = ({ appId, ok, summary, result }) => transaction(async () => {
  const { id } = await one(
    'INSERT INTO test_runs (app_id, ok, summary, result) VALUES ($1, $2, $3, $4) RETURNING id',
    [appId, ok ? 1 : 0, summary, JSON.stringify(result)],
  );
  await exec(`DELETE FROM test_runs WHERE app_id = $1 AND id NOT IN
    (SELECT id FROM test_runs WHERE app_id = $1 ORDER BY id DESC LIMIT ${KEEP_TEST_RUNS})`, [appId]);
  return id;
});

export const listTestRuns = (appId) =>
  all('SELECT id, ok, summary, created_at FROM test_runs WHERE app_id = $1 ORDER BY id DESC', [appId]);

export async function getTestRun(id) {
  if (!validId(id)) return null;
  const run = await one('SELECT * FROM test_runs WHERE id = $1', [id]);
  if (run) run.result = JSON.parse(run.result);
  return run;
}

// ---------- settings ----------

export const listSettingRows = () => all('SELECT * FROM settings');
export const getSetting = (key) => one('SELECT * FROM settings WHERE key = $1', [key]);

export async function setSetting(key, value, updatedBy) {
  await exec(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES ($1, $2, $3, ${NOW})
    ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = excluded.updated_at
  `, [key, value, updatedBy]);
}

export const deleteSetting = (key) => exec('DELETE FROM settings WHERE key = $1', [key]);

// ---------- Keycloak profiles (rows as stored; keycloakProfiles.js decrypts and validates) ----------

export const listProfileRows = () => all('SELECT * FROM keycloak_profiles ORDER BY lower(name)');
export const getProfileRow = async (id) => (validId(id) ? one('SELECT * FROM keycloak_profiles WHERE id = $1', [id]) : null);
export const getProfileRowByName = (name) => one('SELECT * FROM keycloak_profiles WHERE lower(name) = lower($1)', [name]);

export async function insertProfileRow({ name, description, settings, secrets, by }) {
  return (await one(`
    INSERT INTO keycloak_profiles (name, description, settings, secrets, created_by, updated_by)
    VALUES ($1, $2, $3, $4, $5, $5) RETURNING id
  `, [name, description, settings, secrets, by])).id;
}

export async function updateProfileRow(id, { name, description, settings, secrets, by }) {
  await exec(`
    UPDATE keycloak_profiles SET name = $1, description = $2, settings = $3, secrets = $4, updated_by = $5, updated_at = ${NOW}
    WHERE id = $6
  `, [name, description, settings, secrets, by, id]);
}

export const deleteProfileRow = (id) => exec('DELETE FROM keycloak_profiles WHERE id = $1', [id]);

// ---------- SAML signing keys (rows as stored; spKeys.js decrypts) ----------

export const getSpKeyRow = (status) => one('SELECT * FROM sp_keys WHERE status = $1', [status]);

// Stores a key pair under `status`, replacing any existing key with that status.
export const putSpKeyRow = (status, { certificate, privateKey, by }) => transaction(async () => {
  await exec('DELETE FROM sp_keys WHERE status = $1', [status]);
  await exec(`
    INSERT INTO sp_keys (status, certificate, private_key, created_by, activated_at)
    VALUES ($1, $2, $3, $4, CASE WHEN $5 THEN ${NOW} END)
  `, [status, certificate, privateKey, by, status === 'active']);
});

// The pending key replaces the active one, which is deleted.
export const promotePendingSpKey = () => transaction(async () => {
  if (!(await getSpKeyRow('pending'))) return false;
  await exec("DELETE FROM sp_keys WHERE status = 'active'");
  await exec(`UPDATE sp_keys SET status = 'active', activated_at = ${NOW} WHERE status = 'pending'`);
  return true;
});

export const deleteSpKeyRow = (status) => exec('DELETE FROM sp_keys WHERE status = $1', [status]);

// ---------- admin console accounts ----------

export const ADMIN_USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,39}$/;

export const getAdminAccount = (username) =>
  one('SELECT * FROM admin_accounts WHERE username = $1', [username.toLowerCase()]);

export const listAdminAccounts = () => all(`
  SELECT username, must_change_password, password_changed_at, failed_attempts, locked_until,
         created_by, created_at, last_login_at
  FROM admin_accounts ORDER BY username
`);

export const countAdminAccounts = async () => (await one('SELECT COUNT(*)::int AS n FROM admin_accounts')).n;

export async function createAdminAccount({ username, passwordHash, createdBy = null, mustChangePassword = true }) {
  await exec(`
    INSERT INTO admin_accounts (username, password_hash, must_change_password, password_changed_at, created_by)
    VALUES ($1, $2, $3, $4, $5)
  `, [username.toLowerCase(), passwordHash, mustChangePassword ? 1 : 0, new Date().toISOString(), createdBy]);
}

// Creates the account only while there are no administrators at all, under an advisory lock, so
// two concurrent first-run setups can't both succeed. Returns whether it was created.
export const createFirstAdminAccount = ({ username, passwordHash, createdBy, mustChangePassword }) => transaction(async () => {
  await exec("SELECT pg_advisory_xact_lock(hashtext('cloaktail.first_admin'))");
  const { rowCount } = await exec(`
    INSERT INTO admin_accounts (username, password_hash, must_change_password, password_changed_at, created_by)
    SELECT $1, $2, $3::int, $4, $5 WHERE NOT EXISTS (SELECT 1 FROM admin_accounts)
  `, [username.toLowerCase(), passwordHash, mustChangePassword ? 1 : 0, new Date().toISOString(), createdBy]);
  return rowCount === 1;
});

// A new password_changed_at ends the account's other sessions (adminContext compares it) and unlocks it.
export async function setAdminPassword(username, passwordHash, { mustChangePassword }) {
  await exec(`
    UPDATE admin_accounts SET password_hash = $1, must_change_password = $2, password_changed_at = $3,
      failed_attempts = 0, locked_until = NULL
    WHERE username = $4
  `, [passwordHash, mustChangePassword ? 1 : 0, new Date().toISOString(), username.toLowerCase()]);
}

export async function recordAdminLogin(username) {
  await exec(`UPDATE admin_accounts SET last_login_at = ${NOW}, failed_attempts = 0, locked_until = NULL WHERE username = $1`,
    [username.toLowerCase()]);
}

// Locks the account for lockMs once failures reach lockAfter; each later failure renews the lock.
export async function recordAdminLoginFailure(username, { lockAfter, lockMs }) {
  await exec(`
    UPDATE admin_accounts SET failed_attempts = failed_attempts + 1,
      locked_until = CASE WHEN failed_attempts + 1 >= $1::int THEN $2::text ELSE locked_until END
    WHERE username = $3
  `, [lockAfter, new Date(Date.now() + lockMs).toISOString(), username.toLowerCase()]);
}

export const deleteAdminAccount = (username) =>
  exec('DELETE FROM admin_accounts WHERE username = $1', [username.toLowerCase()]);

// ---------- browser sessions (session.js) ----------

export async function getSession(sid) {
  const row = await one('SELECT sess FROM sessions WHERE sid = $1 AND expires_at > now()', [sid]);
  return row ? JSON.parse(row.sess) : null;
}

export async function saveSession(sid, sess, expiresAt) {
  await exec(`
    INSERT INTO sessions (sid, sess, expires_at) VALUES ($1, $2, $3)
    ON CONFLICT (sid) DO UPDATE SET sess = excluded.sess, expires_at = excluded.expires_at
  `, [sid, JSON.stringify(sess), expiresAt]);
}

export const deleteSession = (sid) => exec('DELETE FROM sessions WHERE sid = $1', [sid]);

export const listSessions = async () =>
  (await all('SELECT sid, sess FROM sessions WHERE expires_at > now()')).map((r) => ({ sid: r.sid, sess: JSON.parse(r.sess) }));

export const deleteExpiredSessions = () => exec('DELETE FROM sessions WHERE expires_at <= now()');
