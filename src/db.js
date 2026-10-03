import { AsyncLocalStorage } from 'node:async_hooks';
import fs from 'node:fs';
import pg from 'pg';
import { config, currentProfileId } from './config.js';

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
  'apps.own': 'Register own SAML and OIDC applications and test users in the sandbox',
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
  { name: 'developer', description: 'Self-service SAML and OIDC applications in the sandbox', system: 0, permissions: ['dashboard.view', 'apps.own'] },
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

// Runs fn(client) in a transaction on a connection allowed to change the schema: dbadminuser when set
// (then tables it creates are granted to the app user), otherwise the app user.
async function withSchemaClient(what, fn) {
  const { admin, ...appDb } = config.db;
  const appUser = (await one('SELECT current_user AS u')).u;
  const client = admin ? new pg.Client({ ...appDb, ...admin }) : await pool.connect();
  try {
    if (admin) await client.connect();
    await client.query('BEGIN');
    await client.query("SELECT pg_advisory_xact_lock(hashtext('cloaktail.schema'))");
    const result = await fn(client, { grantTo: admin && admin.user !== appUser ? appUser : null });
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (err.code !== '42501') throw err;
    const user = admin?.user ?? appUser;
    const database = appDb.database ?? '<database>';
    console.error(`PostgreSQL user "${user}" may not change the schema of database "${database}" (${what}).\n`
      + 'Set dbadminuser/dbadminpassword to an account that may (e.g. the database owner), or grant it once as a superuser:\n'
      + `  \\c ${database}\n  GRANT CREATE ON SCHEMA public TO ${user};`);
    process.exit(1);
  } finally {
    if (admin) await client.end().catch(() => {});
    else client.release();
  }
}

// Creates whatever in db/schema.sql is missing. It runs nothing when the schema is complete, so the
// app user needs no CREATE privilege afterwards (CREATE ... IF NOT EXISTS still checks privileges).
async function ensureSchema() {
  const schemaSql = fs.readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8');
  const names = [...schemaSql.matchAll(/CREATE (?:UNIQUE )?(?:TABLE|INDEX) IF NOT EXISTS (\w+)/g)].map((m) => m[1]);
  const { missing } = await one('SELECT array_agg(n) FILTER (WHERE to_regclass(n) IS NULL) AS missing FROM unnest($1::text[]) n', [names]);
  if (!missing) return;
  await withSchemaClient(`missing: ${missing.join(', ')}`, async (client, { grantTo }) => {
    await client.query(schemaSql);
    if (grantTo) {
      const tables = [...schemaSql.matchAll(/CREATE TABLE IF NOT EXISTS (\w+)/g)].map((m) => client.escapeIdentifier(m[1]));
      await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ${tables.join(', ')} TO ${client.escapeIdentifier(grantTo)}`);
    }
  });
  console.log(`Created the database schema (${missing.join(', ')}).`);
}

// Before each Keycloak profile had its own data, users, roles and sandbox records were shared and
// the app ran on one active profile. This gives every existing row to that profile, once.
async function migrateToPerProfileData() {
  const done = await one("SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'profile_id'");
  if (done) return;
  await withSchemaClient('adding profile_id columns', async (client) => {
    const q = async (sql) => (await client.query(sql)).rows;
    const [active] = await q(`SELECT p.id FROM settings s JOIN keycloak_profiles p ON p.id::text = s.value
      WHERE s.key = 'active_keycloak_profile'`);
    const profileId = active ? Number(active.id) : null;
    if (profileId === null) {
      const [{ n }] = await q('SELECT (SELECT COUNT(*) FROM users) + (SELECT COUNT(*) FROM apps) + (SELECT COUNT(*) FROM test_users) AS n');
      if (Number(n) > 0) {
        throw new Error('Upgrading to per-profile data needs an active Keycloak profile to give the existing users and '
          + 'applications to. Start the previous CloakTail version, activate a profile, then upgrade again.');
      }
    }
    // Without an active profile there is nothing to keep (roles are seeded again for every profile).
    const assign = (table) => (profileId === null ? `DELETE FROM ${table}` : `UPDATE ${table} SET profile_id = ${profileId}`);
    for (const sql of [
      'ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_username_fkey',
      'ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_pkey',
      'ALTER TABLE users DROP CONSTRAINT IF EXISTS users_pkey',
      'ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key',
      'ALTER TABLE apps DROP CONSTRAINT IF EXISTS apps_kc_id_key',
      'ALTER TABLE apps DROP CONSTRAINT IF EXISTS apps_client_id_key',
      'ALTER TABLE test_users DROP CONSTRAINT IF EXISTS test_users_kc_id_key',
      'ALTER TABLE test_users DROP CONSTRAINT IF EXISTS test_users_username_key',
      ...['user_roles', 'users', 'roles', 'apps', 'test_users'].flatMap((t) => [
        `ALTER TABLE ${t} ADD COLUMN profile_id INTEGER`,
        assign(t),
        `ALTER TABLE ${t} ALTER COLUMN profile_id SET NOT NULL`,
      ]),
      ...['users', 'roles', 'apps', 'test_users'].map((t) =>
        `ALTER TABLE ${t} ADD FOREIGN KEY (profile_id) REFERENCES keycloak_profiles(id) ON DELETE CASCADE`),
      'ALTER TABLE users ADD PRIMARY KEY (profile_id, username)',
      'ALTER TABLE roles ADD UNIQUE (profile_id, name)',
      'ALTER TABLE user_roles ADD PRIMARY KEY (profile_id, username, role_id)',
      'ALTER TABLE user_roles ADD FOREIGN KEY (profile_id, username) REFERENCES users(profile_id, username) ON DELETE CASCADE',
      'ALTER TABLE apps ADD UNIQUE (profile_id, kc_id)',
      'ALTER TABLE apps ADD UNIQUE (profile_id, client_id)',
      'ALTER TABLE test_users ADD UNIQUE (profile_id, kc_id)',
      'ALTER TABLE test_users ADD UNIQUE (profile_id, username)',
    ]) await q(sql);
  });
  console.log('Users, roles and sandbox records now belong to a Keycloak profile; the existing ones went to the active profile.');
}

// Before each Keycloak profile had its own SAML signing key, one key pair served them all. Every
// existing profile gets a copy of it, so sign-in keeps working (each Keycloak already trusts it).
// Runs before ensureSchema, whose new index needs the profile_id column.
async function migrateSpKeysToProfiles() {
  const { legacy } = await one(`SELECT to_regclass('sp_keys') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'sp_keys' AND column_name = 'profile_id') AS legacy`);
  if (!legacy) return;
  const copied = await withSchemaClient('adding sp_keys.profile_id', async (client) => {
    const q = async (sql) => (await client.query(sql)).rows;
    await q('ALTER TABLE sp_keys ADD COLUMN profile_id INTEGER REFERENCES keycloak_profiles(id) ON DELETE CASCADE');
    await q('DROP INDEX IF EXISTS sp_keys_one_per_status');
    const [{ keys, profiles }] = await q('SELECT (SELECT COUNT(*)::int FROM sp_keys) AS keys, (SELECT COUNT(*)::int FROM keycloak_profiles) AS profiles');
    await q(`INSERT INTO sp_keys (profile_id, status, certificate, private_key, created_by, created_at, activated_at)
      SELECT p.id, k.status, k.certificate, k.private_key, k.created_by, k.created_at, k.activated_at
      FROM sp_keys k CROSS JOIN keycloak_profiles p WHERE k.profile_id IS NULL`);
    await q('DELETE FROM sp_keys WHERE profile_id IS NULL');
    await q('ALTER TABLE sp_keys ALTER COLUMN profile_id SET NOT NULL');
    await q('CREATE UNIQUE INDEX sp_keys_one_per_profile_status ON sp_keys (profile_id, status)');
    return { keys, profiles };
  });
  if (copied.keys && copied.profiles) {
    console.log(`Each Keycloak profile now has its own SAML signing key; all ${copied.profiles} profiles start with a copy of the shared one.`);
  } else if (copied.keys) {
    console.warn('Each Keycloak profile now has its own SAML signing key. The shared key was dropped, as there was no profile to give it to.');
  }
}

// User migration was first configured per Keycloak profile in the admin console (migration_clients);
// it now belongs to developer applications (app_migrations). The old tables are dropped when empty.
async function dropProfileMigrationTables() {
  const { exists } = await one("SELECT to_regclass('migration_clients') IS NOT NULL AS exists");
  if (!exists) return;
  const { n } = await one('SELECT COUNT(*)::int AS n FROM migration_clients');
  if (n) {
    console.warn(`Table migration_clients holds ${n} admin-console migration client(s), which are no longer used: user migration is `
      + 'now set up on each developer application. Recreate them there, then drop migration_events and migration_clients.');
    return;
  }
  await withSchemaClient('dropping migration_clients', (client) => client.query('DROP TABLE IF EXISTS migration_events, migration_clients'));
}

// Applications were all SAML before OIDC clients could be registered.
async function migrateAppProtocol() {
  const done = await one("SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'apps' AND column_name = 'protocol'");
  if (done) return;
  await withSchemaClient('adding apps.protocol', (client) => client.query(
    "ALTER TABLE apps ADD COLUMN protocol TEXT NOT NULL DEFAULT 'saml' CHECK (protocol IN ('saml', 'oidc'))",
  ));
}

await migrateSpKeysToProfiles();
await ensureSchema();
await migrateToPerProfileData();
await migrateAppProtocol();
await dropProfileMigrationTables();

// Permissions are global (defined in code); roles are per profile (seedRoles).
await transaction(async () => {
  for (const [key, description] of Object.entries(PERMISSIONS)) {
    await exec(
      'INSERT INTO permissions (key, description) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET description = excluded.description',
      [key, description],
    );
  }
  await exec('DELETE FROM permissions WHERE key <> ALL($1)', [Object.keys(PERMISSIONS)]);
});

// Creates the default roles a profile lacks, and keeps its admin role holding every permission,
// including ones added later. Run at startup for every profile and when a profile is created.
export const seedRoles = (profileId) => transaction(async () => {
  for (const role of SEED_ROLES) {
    if (await one('SELECT id FROM roles WHERE profile_id = $1 AND name = $2', [profileId, role.name])) continue;
    const { id } = await one(
      'INSERT INTO roles (profile_id, name, description, is_system) VALUES ($1, $2, $3, $4) RETURNING id',
      [profileId, role.name, role.description, role.system],
    );
    for (const perm of role.permissions) {
      await exec('INSERT INTO role_permissions (role_id, permission_key) VALUES ($1, $2)', [id, perm]);
    }
  }
  const admin = await one("SELECT id FROM roles WHERE profile_id = $1 AND name = 'admin'", [profileId]);
  for (const perm of Object.keys(PERMISSIONS)) {
    await exec('INSERT INTO role_permissions (role_id, permission_key) VALUES ($1, $2) ON CONFLICT DO NOTHING', [admin.id, perm]);
  }
});

// Every query below is scoped to the Keycloak profile serving the current request (currentProfileId
// throws outside one), so one profile's users and data are never visible on another's domains.

// ---------- users ----------

export async function upsertUser({ username, keycloakId, email, firstName, lastName }, { login = false } = {}) {
  username = username.toLowerCase();
  await exec(`
    INSERT INTO users (profile_id, username, keycloak_id, email, first_name, last_name, last_login_at)
    VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $7 THEN ${NOW} END)
    ON CONFLICT (profile_id, username) DO UPDATE SET
      keycloak_id   = COALESCE(excluded.keycloak_id, users.keycloak_id),
      email         = COALESCE(excluded.email, users.email),
      first_name    = COALESCE(excluded.first_name, users.first_name),
      last_name     = COALESCE(excluded.last_name, users.last_name),
      last_login_at = COALESCE(excluded.last_login_at, users.last_login_at)
  `, [currentProfileId(), username, keycloakId ?? null, email ?? null, firstName ?? null, lastName ?? null, Boolean(login)]);
  return username;
}

export const getLocalUser = (username) =>
  one('SELECT * FROM users WHERE profile_id = $1 AND username = $2', [currentProfileId(), username.toLowerCase()]);

export async function deleteLocalUser(username) {
  await exec('DELETE FROM users WHERE profile_id = $1 AND username = $2', [currentProfileId(), username.toLowerCase()]);
}

export const getUserRoles = (username) => all(`
  SELECT r.id, r.name FROM roles r
  JOIN user_roles ur ON ur.role_id = r.id
  WHERE ur.profile_id = $1 AND ur.username = $2 ORDER BY r.name
`, [currentProfileId(), username.toLowerCase()]);

export async function getRolesForUsernames(usernames) {
  const map = new Map(usernames.map((u) => [u.toLowerCase(), []]));
  if (!usernames.length) return map;
  const rows = await all(`
    SELECT ur.username, r.id, r.name FROM user_roles ur
    JOIN roles r ON r.id = ur.role_id
    WHERE ur.profile_id = $1 AND ur.username = ANY($2)
    ORDER BY r.name
  `, [currentProfileId(), usernames.map((u) => u.toLowerCase())]);
  for (const row of rows) map.get(row.username)?.push({ id: row.id, name: row.name });
  return map;
}

export async function getUserPermissions(username) {
  const rows = await all(`
    SELECT DISTINCT rp.permission_key AS key FROM role_permissions rp
    JOIN user_roles ur ON ur.role_id = rp.role_id
    WHERE ur.profile_id = $1 AND ur.username = $2
  `, [currentProfileId(), username.toLowerCase()]);
  return new Set(rows.map((r) => r.key));
}

// Role ids are global, so assignments only accept roles of the same profile.
export const setUserRoles = (username, roleIds) => transaction(async () => {
  const profileId = currentProfileId();
  username = await upsertUser({ username });
  await exec('DELETE FROM user_roles WHERE profile_id = $1 AND username = $2', [profileId, username]);
  for (const id of roleIds.filter(validId)) {
    await exec(
      'INSERT INTO user_roles (profile_id, username, role_id) SELECT $1, $2, id FROM roles WHERE id = $3 AND profile_id = $1',
      [profileId, username, id],
    );
  }
});

export async function addUserRoleByName(username, roleName) {
  await exec(`
    INSERT INTO user_roles (profile_id, username, role_id)
    SELECT $1, $2, id FROM roles WHERE profile_id = $1 AND name = $3 ON CONFLICT DO NOTHING
  `, [currentProfileId(), username.toLowerCase(), roleName]);
}

// ---------- roles ----------

export const listRoles = () => all(`
  SELECT r.*,
    (SELECT COUNT(*)::int FROM role_permissions rp WHERE rp.role_id = r.id) AS permission_count,
    (SELECT COUNT(*)::int FROM user_roles ur WHERE ur.role_id = r.id) AS user_count
  FROM roles r WHERE r.profile_id = $1 ORDER BY r.is_system DESC, r.name
`, [currentProfileId()]);

export async function getRole(id) {
  if (!validId(id)) return null;
  const role = await one('SELECT * FROM roles WHERE id = $1 AND profile_id = $2', [id, currentProfileId()]);
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
  return (await one(
    'INSERT INTO roles (profile_id, name, description) VALUES ($1, $2, $3) RETURNING id',
    [currentProfileId(), name, description],
  )).id;
}

export const updateRole = (id, description, permissionKeys) => transaction(async () => {
  const { rowCount } = await exec('UPDATE roles SET description = $1 WHERE id = $2 AND profile_id = $3', [description, id, currentProfileId()]);
  if (!rowCount) return;
  await exec('DELETE FROM role_permissions WHERE role_id = $1', [id]);
  for (const key of permissionKeys) {
    await exec('INSERT INTO role_permissions (role_id, permission_key) SELECT $1::int, key FROM permissions WHERE key = $2', [id, key]);
  }
});

export async function deleteRole(id) {
  await exec('DELETE FROM roles WHERE id = $1 AND profile_id = $2 AND is_system = 0', [id, currentProfileId()]);
}

// ---------- developer apps ----------

export function listApps({ owner } = {}) {
  const base = `
    SELECT a.*,
      (SELECT ok FROM test_runs t WHERE t.app_id = a.id ORDER BY t.id DESC LIMIT 1) AS last_test_ok,
      (SELECT created_at FROM test_runs t WHERE t.app_id = a.id ORDER BY t.id DESC LIMIT 1) AS last_test_at
    FROM apps a WHERE a.profile_id = $1`;
  return owner
    ? all(`${base} AND a.owner = $2 ORDER BY a.created_at DESC`, [currentProfileId(), owner])
    : all(`${base} ORDER BY a.owner, a.created_at DESC`, [currentProfileId()]);
}

export const countApps = async (owner) =>
  (await one('SELECT COUNT(*)::int AS n FROM apps WHERE profile_id = $1 AND owner = $2', [currentProfileId(), owner])).n;
export const getApp = async (id) =>
  (validId(id) ? one('SELECT * FROM apps WHERE id = $1 AND profile_id = $2', [id, currentProfileId()]) : null);

export async function insertApp({ protocol, owner, kcId, clientId, name }) {
  return (await one(
    'INSERT INTO apps (profile_id, protocol, owner, kc_id, client_id, name) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
    [currentProfileId(), protocol, owner, kcId, clientId, name],
  )).id;
}

export const renameApp = (id, name) => exec('UPDATE apps SET name = $1 WHERE id = $2 AND profile_id = $3', [name, id, currentProfileId()]);
export const deleteApp = (id) => exec('DELETE FROM apps WHERE id = $1 AND profile_id = $2', [id, currentProfileId()]);

// ---------- sandbox test users ----------

export const listTestUsers = (owner) =>
  all('SELECT * FROM test_users WHERE profile_id = $1 AND owner = $2 ORDER BY username', [currentProfileId(), owner]);
export const countTestUsers = async (owner) =>
  (await one('SELECT COUNT(*)::int AS n FROM test_users WHERE profile_id = $1 AND owner = $2', [currentProfileId(), owner])).n;
export const getTestUser = async (id) =>
  (validId(id) ? one('SELECT * FROM test_users WHERE id = $1 AND profile_id = $2', [id, currentProfileId()]) : null);

export async function insertTestUser({ owner, kcId, username }) {
  return (await one(
    'INSERT INTO test_users (profile_id, owner, kc_id, username) VALUES ($1, $2, $3, $4) RETURNING id',
    [currentProfileId(), owner, kcId, username],
  )).id;
}

export const deleteTestUser = (id) => exec('DELETE FROM test_users WHERE id = $1 AND profile_id = $2', [id, currentProfileId()]);

// ---------- test runs (reached through an app, which is already scoped to the profile) ----------

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

// Domains served by each profile.
export const listDomainRows = () => all('SELECT origin, profile_id FROM profile_domains ORDER BY origin');
export const setProfileDomains = (profileId, origins) => transaction(async () => {
  await exec('DELETE FROM profile_domains WHERE profile_id = $1', [profileId]);
  for (const origin of origins) await exec('INSERT INTO profile_domains (origin, profile_id) VALUES ($1, $2)', [origin, profileId]);
});

// What deleting a profile would remove from the database (Keycloak keeps its own copies).
export const countProfileData = async (profileId) => one(`
  SELECT (SELECT COUNT(*)::int FROM users WHERE profile_id = $1) AS users,
    (SELECT COUNT(*)::int FROM apps WHERE profile_id = $1) AS apps,
    (SELECT COUNT(*)::int FROM test_users WHERE profile_id = $1) AS test_users
`, [profileId]);

// ---------- SAML signing keys, per Keycloak profile (rows as stored; spKeys.js decrypts) ----------
// Managed from the admin console, outside any request's profile, so these take the profile id.

export const getSpKeyRow = (profileId, status) =>
  one('SELECT * FROM sp_keys WHERE profile_id = $1 AND status = $2', [profileId, status]);
export const listSpKeyRows = () => all('SELECT * FROM sp_keys ORDER BY profile_id, status');

// Stores a key pair under `status`, replacing any key the profile has with that status.
export const putSpKeyRow = (profileId, status, { certificate, privateKey, by }) => transaction(async () => {
  await exec('DELETE FROM sp_keys WHERE profile_id = $1 AND status = $2', [profileId, status]);
  await exec(`
    INSERT INTO sp_keys (profile_id, status, certificate, private_key, created_by, activated_at)
    VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 THEN ${NOW} END)
  `, [profileId, status, certificate, privateKey, by, status === 'active']);
});

// The profile's pending key replaces its active one, which is deleted.
export const promotePendingSpKey = (profileId) => transaction(async () => {
  if (!(await getSpKeyRow(profileId, 'pending'))) return false;
  await exec("DELETE FROM sp_keys WHERE profile_id = $1 AND status = 'active'", [profileId]);
  await exec(`UPDATE sp_keys SET status = 'active', activated_at = ${NOW} WHERE profile_id = $1 AND status = 'pending'`, [profileId]);
  return true;
});

export const deleteSpKeyRow = (profileId, status) =>
  exec('DELETE FROM sp_keys WHERE profile_id = $1 AND status = $2', [profileId, status]);

// ---------- user migration of developer apps (rows as stored; lib/userMigration.js decrypts) ----------
// Reached through an app, which is already scoped to the profile.

export const getAppMigrationRow = (appId) => one('SELECT * FROM app_migrations WHERE app_id = $1', [appId]);

export async function putAppMigrationRow(appId, { enabled, settings, secret, by }) {
  await exec(`
    INSERT INTO app_migrations (app_id, enabled, settings, secret, created_by, updated_by) VALUES ($1, $2, $3, $4, $5, $5)
    ON CONFLICT (app_id) DO UPDATE SET enabled = excluded.enabled, settings = excluded.settings, secret = excluded.secret,
      updated_by = excluded.updated_by, updated_at = ${NOW}
  `, [appId, enabled ? 1 : 0, settings, secret, by]);
}

export const deleteAppMigrationRow = (appId) => exec('DELETE FROM app_migrations WHERE app_id = $1', [appId]);

// The app a migration request names (its iss is the app's client ID), in the request's profile.
export const getAppByClientId = (clientId) =>
  one('SELECT * FROM apps WHERE profile_id = $1 AND client_id = $2', [currentProfileId(), clientId]);

// Records a new request. Returns false when the app already sent that request id (a replay).
export async function startMigrationEvent({ appId, jti, legacyId, username, ip }) {
  const { rowCount } = await exec(`
    INSERT INTO app_migration_events (app_id, jti, legacy_id, username, status, ip) VALUES ($1, $2, $3, $4, 'started', $5)
    ON CONFLICT (app_id, jti) DO NOTHING
  `, [appId, jti, legacyId, username, ip]);
  return rowCount === 1;
}

export async function finishMigrationEvent({ appId, jti, status, keycloakId = null, detail = null }) {
  await exec(`
    UPDATE app_migration_events SET status = $1, keycloak_id = COALESCE($2, keycloak_id), detail = $3, updated_at = ${NOW}
    WHERE app_id = $4 AND jti = $5
  `, [status, keycloakId, detail, appId, jti]);
}

// A request that failed its checks, so the developer can see why. Only the latest are kept.
const KEEP_REJECTED = 50;
export const recordRejectedMigration = ({ appId, detail, ip }) => transaction(async () => {
  await exec("INSERT INTO app_migration_events (app_id, status, detail, ip) VALUES ($1, 'rejected', $2, $3)", [appId, detail, ip]);
  await exec(`DELETE FROM app_migration_events WHERE app_id = $1 AND status = 'rejected' AND id NOT IN
    (SELECT id FROM app_migration_events WHERE app_id = $1 AND status = 'rejected' ORDER BY id DESC LIMIT ${KEEP_REJECTED})`, [appId]);
});

export const listMigrationEvents = (appId, limit = 50) =>
  all('SELECT * FROM app_migration_events WHERE app_id = $1 ORDER BY id DESC LIMIT $2', [appId, limit]);

// Requests by status, plus `migratedUsers`: distinct legacy users who now have a Keycloak account.
export async function countMigrationEvents(appId) {
  const rows = await all('SELECT status, COUNT(*)::int AS n FROM app_migration_events WHERE app_id = $1 GROUP BY status', [appId]);
  const { users } = await one(`SELECT COUNT(DISTINCT legacy_id)::int AS users FROM app_migration_events
    WHERE app_id = $1 AND status IN ('created', 'already_migrated')`, [appId]);
  return { ...Object.fromEntries(rows.map((r) => [r.status, r.n])), migratedUsers: users };
}

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
