import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
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

fs.mkdirSync(path.dirname(config.dbFile), { recursive: true });
export const db = new Database(config.dbFile);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    keycloak_id   TEXT,
    email         TEXT,
    first_name    TEXT,
    last_name     TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT
  );
  CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    is_system   INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS permissions (
    key         TEXT PRIMARY KEY,
    description TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS role_permissions (
    role_id        INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_key)
  );
  CREATE TABLE IF NOT EXISTS user_roles (
    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    role_id  INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (username, role_id)
  );

  -- Developer-owned SAML clients in the sandbox realm (Keycloak holds their configuration).
  CREATE TABLE IF NOT EXISTS apps (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    owner      TEXT NOT NULL,
    kc_id      TEXT NOT NULL UNIQUE,
    client_id  TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS test_users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    owner      TEXT NOT NULL,
    kc_id      TEXT NOT NULL UNIQUE,
    username   TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS test_runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    ok         INTEGER NOT NULL,
    summary    TEXT NOT NULL,
    result     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Small app-wide values set from the admin console, e.g. which Keycloak profile is active.
  CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_by TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  -- The portal's SAML signing key pair. At most one active and one pending (a replacement waiting
  -- to be imported into Keycloak). See spKeys.js.
  CREATE TABLE IF NOT EXISTS sp_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    status      TEXT NOT NULL CHECK (status IN ('active', 'pending')),
    certificate TEXT NOT NULL,            -- PEM, public
    private_key TEXT NOT NULL,            -- PEM, encrypted
    created_by  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    activated_at TEXT
  );
  CREATE UNIQUE INDEX IF NOT EXISTS sp_keys_one_per_status ON sp_keys (status);
  -- Named Keycloak connections; one is active (settings.active_keycloak_profile). See keycloakProfiles.js.
  CREATE TABLE IF NOT EXISTS keycloak_profiles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    settings    TEXT NOT NULL,            -- JSON, everything except client secrets
    secrets     TEXT NOT NULL DEFAULT '', -- encrypted JSON of the client secrets
    created_by  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by  TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
  -- Admin console accounts. Local on purpose: they must work even when Keycloak is misconfigured.
  CREATE TABLE IF NOT EXISTS admin_accounts (
    username             TEXT PRIMARY KEY,
    password_hash        TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    password_changed_at  TEXT NOT NULL,
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         TEXT,
    created_by           TEXT,
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at        TEXT
  );
`);

db.transaction(() => {
  const upsertPerm = db.prepare(
    'INSERT INTO permissions (key, description) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET description = excluded.description',
  );
  for (const [key, description] of Object.entries(PERMISSIONS)) upsertPerm.run(key, description);
  db.prepare(`DELETE FROM permissions WHERE key NOT IN (${Object.keys(PERMISSIONS).map(() => '?').join(',')})`)
    .run(...Object.keys(PERMISSIONS));

  for (const role of SEED_ROLES) {
    const existing = db.prepare('SELECT id FROM roles WHERE name = ?').get(role.name);
    if (existing) continue;
    const { lastInsertRowid } = db
      .prepare('INSERT INTO roles (name, description, is_system) VALUES (?, ?, ?)')
      .run(role.name, role.description, role.system);
    const grant = db.prepare('INSERT INTO role_permissions (role_id, permission_key) VALUES (?, ?)');
    for (const perm of role.permissions) grant.run(lastInsertRowid, perm);
  }

  // The admin role always holds every permission, including ones added later.
  const admin = db.prepare("SELECT id FROM roles WHERE name = 'admin'").get();
  const grant = db.prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_key) VALUES (?, ?)');
  for (const perm of Object.keys(PERMISSIONS)) grant.run(admin.id, perm);
})();

// ---------- users ----------

export function upsertUser({ username, keycloakId, email, firstName, lastName }, { login = false } = {}) {
  username = username.toLowerCase();
  db.prepare(`
    INSERT INTO users (username, keycloak_id, email, first_name, last_name, last_login_at)
    VALUES (@username, @keycloakId, @email, @firstName, @lastName, CASE WHEN @login THEN datetime('now') END)
    ON CONFLICT(username) DO UPDATE SET
      keycloak_id   = COALESCE(excluded.keycloak_id, users.keycloak_id),
      email         = COALESCE(excluded.email, users.email),
      first_name    = COALESCE(excluded.first_name, users.first_name),
      last_name     = COALESCE(excluded.last_name, users.last_name),
      last_login_at = COALESCE(excluded.last_login_at, users.last_login_at)
  `).run({
    username,
    keycloakId: keycloakId ?? null,
    email: email ?? null,
    firstName: firstName ?? null,
    lastName: lastName ?? null,
    login: login ? 1 : 0,
  });
  return username;
}

export function getLocalUser(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());
}

export function deleteLocalUser(username) {
  db.prepare('DELETE FROM users WHERE username = ?').run(username.toLowerCase());
}

export function getUserRoles(username) {
  return db.prepare(`
    SELECT r.id, r.name FROM roles r
    JOIN user_roles ur ON ur.role_id = r.id
    WHERE ur.username = ? ORDER BY r.name
  `).all(username.toLowerCase());
}

export function getRolesForUsernames(usernames) {
  const map = new Map(usernames.map((u) => [u.toLowerCase(), []]));
  if (!usernames.length) return map;
  const rows = db.prepare(`
    SELECT ur.username, r.id, r.name FROM user_roles ur
    JOIN roles r ON r.id = ur.role_id
    WHERE ur.username IN (${usernames.map(() => '?').join(',')})
    ORDER BY r.name
  `).all(...usernames.map((u) => u.toLowerCase()));
  for (const row of rows) map.get(row.username)?.push({ id: row.id, name: row.name });
  return map;
}

export function getUserPermissions(username) {
  const rows = db.prepare(`
    SELECT DISTINCT rp.permission_key AS key FROM role_permissions rp
    JOIN user_roles ur ON ur.role_id = rp.role_id
    WHERE ur.username = ?
  `).all(username.toLowerCase());
  return new Set(rows.map((r) => r.key));
}

export const setUserRoles = db.transaction((username, roleIds) => {
  username = upsertUser({ username });
  db.prepare('DELETE FROM user_roles WHERE username = ?').run(username);
  const insert = db.prepare('INSERT INTO user_roles (username, role_id) SELECT ?, id FROM roles WHERE id = ?');
  for (const id of roleIds) insert.run(username, id);
});

export function addUserRoleByName(username, roleName) {
  db.prepare('INSERT OR IGNORE INTO user_roles (username, role_id) SELECT ?, id FROM roles WHERE name = ?')
    .run(username.toLowerCase(), roleName);
}

// ---------- roles ----------

export function listRoles() {
  return db.prepare(`
    SELECT r.*,
      (SELECT COUNT(*) FROM role_permissions rp WHERE rp.role_id = r.id) AS permission_count,
      (SELECT COUNT(*) FROM user_roles ur WHERE ur.role_id = r.id) AS user_count
    FROM roles r ORDER BY r.is_system DESC, r.name
  `).all();
}

export function getRole(id) {
  const role = db.prepare('SELECT * FROM roles WHERE id = ?').get(id);
  if (!role) return null;
  role.permissions = new Set(
    db.prepare('SELECT permission_key FROM role_permissions WHERE role_id = ?').all(id).map((r) => r.permission_key),
  );
  role.users = db.prepare('SELECT username FROM user_roles WHERE role_id = ? ORDER BY username').all(id).map((r) => r.username);
  return role;
}

export function listPermissions() {
  return db.prepare('SELECT * FROM permissions ORDER BY key').all();
}

export function createRole(name, description) {
  return db.prepare('INSERT INTO roles (name, description) VALUES (?, ?)').run(name, description).lastInsertRowid;
}

export const updateRole = db.transaction((id, description, permissionKeys) => {
  db.prepare('UPDATE roles SET description = ? WHERE id = ?').run(description, id);
  db.prepare('DELETE FROM role_permissions WHERE role_id = ?').run(id);
  const insert = db.prepare('INSERT INTO role_permissions (role_id, permission_key) SELECT ?, key FROM permissions WHERE key = ?');
  for (const key of permissionKeys) insert.run(id, key);
});

export function deleteRole(id) {
  db.prepare('DELETE FROM roles WHERE id = ? AND is_system = 0').run(id);
}

// ---------- developer apps ----------

export function listApps({ owner } = {}) {
  const base = `
    SELECT a.*,
      (SELECT ok FROM test_runs t WHERE t.app_id = a.id ORDER BY t.id DESC LIMIT 1) AS last_test_ok,
      (SELECT created_at FROM test_runs t WHERE t.app_id = a.id ORDER BY t.id DESC LIMIT 1) AS last_test_at
    FROM apps a`;
  return owner
    ? db.prepare(`${base} WHERE a.owner = ? ORDER BY a.created_at DESC`).all(owner)
    : db.prepare(`${base} ORDER BY a.owner, a.created_at DESC`).all();
}

export const countApps = (owner) => db.prepare('SELECT COUNT(*) AS n FROM apps WHERE owner = ?').get(owner).n;
export const getApp = (id) => db.prepare('SELECT * FROM apps WHERE id = ?').get(id);

export function insertApp({ owner, kcId, clientId, name }) {
  return db.prepare('INSERT INTO apps (owner, kc_id, client_id, name) VALUES (?, ?, ?, ?)')
    .run(owner, kcId, clientId, name).lastInsertRowid;
}

export const renameApp = (id, name) => db.prepare('UPDATE apps SET name = ? WHERE id = ?').run(name, id);
export const deleteApp = (id) => db.prepare('DELETE FROM apps WHERE id = ?').run(id);

// ---------- sandbox test users ----------

export const listTestUsers = (owner) =>
  db.prepare('SELECT * FROM test_users WHERE owner = ? ORDER BY username').all(owner);
export const countTestUsers = (owner) => db.prepare('SELECT COUNT(*) AS n FROM test_users WHERE owner = ?').get(owner).n;
export const getTestUser = (id) => db.prepare('SELECT * FROM test_users WHERE id = ?').get(id);

export function insertTestUser({ owner, kcId, username }) {
  return db.prepare('INSERT INTO test_users (owner, kc_id, username) VALUES (?, ?, ?)').run(owner, kcId, username).lastInsertRowid;
}

export const deleteTestUser = (id) => db.prepare('DELETE FROM test_users WHERE id = ?').run(id);

// ---------- test runs ----------

const KEEP_TEST_RUNS = 10;

export const insertTestRun = db.transaction(({ appId, ok, summary, result }) => {
  const id = db.prepare('INSERT INTO test_runs (app_id, ok, summary, result) VALUES (?, ?, ?, ?)')
    .run(appId, ok ? 1 : 0, summary, JSON.stringify(result)).lastInsertRowid;
  db.prepare(`DELETE FROM test_runs WHERE app_id = ? AND id NOT IN
    (SELECT id FROM test_runs WHERE app_id = ? ORDER BY id DESC LIMIT ${KEEP_TEST_RUNS})`).run(appId, appId);
  return id;
});

export const listTestRuns = (appId) =>
  db.prepare('SELECT id, ok, summary, created_at FROM test_runs WHERE app_id = ? ORDER BY id DESC').all(appId);

export function getTestRun(id) {
  const run = db.prepare('SELECT * FROM test_runs WHERE id = ?').get(id);
  if (run) run.result = JSON.parse(run.result);
  return run;
}

// ---------- settings ----------

export const listSettingRows = () => db.prepare('SELECT * FROM settings').all();
export const getSetting = (key) => db.prepare('SELECT * FROM settings WHERE key = ?').get(key) || null;

export function setSetting(key, value, updatedBy) {
  db.prepare(`
    INSERT INTO settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = excluded.updated_at
  `).run(key, value, updatedBy);
}

export const deleteSetting = (key) => db.prepare('DELETE FROM settings WHERE key = ?').run(key);

// ---------- Keycloak profiles (rows as stored; keycloakProfiles.js decrypts and validates) ----------

export const listProfileRows = () => db.prepare('SELECT * FROM keycloak_profiles ORDER BY name COLLATE NOCASE').all();
export const getProfileRow = (id) => db.prepare('SELECT * FROM keycloak_profiles WHERE id = ?').get(id) || null;
export const getProfileRowByName = (name) => db.prepare('SELECT * FROM keycloak_profiles WHERE name = ?').get(name) || null;

export function insertProfileRow({ name, description, settings, secrets, by }) {
  return Number(db.prepare(`
    INSERT INTO keycloak_profiles (name, description, settings, secrets, created_by, updated_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(name, description, settings, secrets, by, by).lastInsertRowid);
}

export function updateProfileRow(id, { name, description, settings, secrets, by }) {
  db.prepare(`
    UPDATE keycloak_profiles SET name = ?, description = ?, settings = ?, secrets = ?, updated_by = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(name, description, settings, secrets, by, id);
}

export const deleteProfileRow = (id) => db.prepare('DELETE FROM keycloak_profiles WHERE id = ?').run(id);

export const transaction = (fn) => db.transaction(fn);

// ---------- SAML signing keys (rows as stored; spKeys.js decrypts) ----------

export const getSpKeyRow = (status) => db.prepare('SELECT * FROM sp_keys WHERE status = ?').get(status) || null;

// Stores a key pair under `status`, replacing any existing key with that status.
export const putSpKeyRow = db.transaction((status, { certificate, privateKey, by }) => {
  db.prepare('DELETE FROM sp_keys WHERE status = ?').run(status);
  db.prepare(`
    INSERT INTO sp_keys (status, certificate, private_key, created_by, activated_at)
    VALUES (?, ?, ?, ?, CASE WHEN ? = 'active' THEN datetime('now') END)
  `).run(status, certificate, privateKey, by, status);
});

// The pending key replaces the active one, which is deleted.
export const promotePendingSpKey = db.transaction(() => {
  if (!getSpKeyRow('pending')) return false;
  db.prepare("DELETE FROM sp_keys WHERE status = 'active'").run();
  db.prepare("UPDATE sp_keys SET status = 'active', activated_at = datetime('now') WHERE status = 'pending'").run();
  return true;
});

export const deleteSpKeyRow = (status) => db.prepare('DELETE FROM sp_keys WHERE status = ?').run(status);

// ---------- admin console accounts ----------

export const ADMIN_USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,39}$/;

export const getAdminAccount = (username) =>
  db.prepare('SELECT * FROM admin_accounts WHERE username = ?').get(username.toLowerCase());

export const listAdminAccounts = () => db.prepare(`
  SELECT username, must_change_password, password_changed_at, failed_attempts, locked_until,
         created_by, created_at, last_login_at
  FROM admin_accounts ORDER BY username
`).all();

export const countAdminAccounts = () => db.prepare('SELECT COUNT(*) AS n FROM admin_accounts').get().n;

export function createAdminAccount({ username, passwordHash, createdBy = null, mustChangePassword = true }) {
  db.prepare(`
    INSERT INTO admin_accounts (username, password_hash, must_change_password, password_changed_at, created_by)
    VALUES (?, ?, ?, ?, ?)
  `).run(username.toLowerCase(), passwordHash, mustChangePassword ? 1 : 0, new Date().toISOString(), createdBy);
}

// Creates the account only while there are no administrators at all, in one statement, so two
// concurrent first-run setups can't both succeed. Returns whether it was created.
export function createFirstAdminAccount({ username, passwordHash, createdBy, mustChangePassword }) {
  return db.prepare(`
    INSERT INTO admin_accounts (username, password_hash, must_change_password, password_changed_at, created_by)
    SELECT ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM admin_accounts)
  `).run(username.toLowerCase(), passwordHash, mustChangePassword ? 1 : 0, new Date().toISOString(), createdBy).changes === 1;
}

// A new password_changed_at ends the account's other sessions (adminContext compares it) and unlocks it.
export function setAdminPassword(username, passwordHash, { mustChangePassword }) {
  db.prepare(`
    UPDATE admin_accounts SET password_hash = ?, must_change_password = ?, password_changed_at = ?,
      failed_attempts = 0, locked_until = NULL
    WHERE username = ?
  `).run(passwordHash, mustChangePassword ? 1 : 0, new Date().toISOString(), username.toLowerCase());
}

export function recordAdminLogin(username) {
  db.prepare(`UPDATE admin_accounts SET last_login_at = datetime('now'), failed_attempts = 0, locked_until = NULL WHERE username = ?`)
    .run(username.toLowerCase());
}

// Locks the account for lockMs once failures reach lockAfter; each later failure renews the lock.
export function recordAdminLoginFailure(username, { lockAfter, lockMs }) {
  db.prepare(`
    UPDATE admin_accounts SET failed_attempts = failed_attempts + 1,
      locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END
    WHERE username = ?
  `).run(lockAfter, new Date(Date.now() + lockMs).toISOString(), username.toLowerCase());
}

export const deleteAdminAccount = (username) =>
  db.prepare('DELETE FROM admin_accounts WHERE username = ?').run(username.toLowerCase());
