import crypto from 'node:crypto';
import { applyKeycloakSettings, stripPem } from './config.js';
import { encrypt, decrypt } from './lib/secretBox.js';
import {
  listProfileRows, getProfileRow, getProfileRowByName, insertProfileRow, updateProfileRow, deleteProfileRow,
  listSettingRows, getSetting, setSetting, deleteSetting, transaction,
} from './db.js';

// Keycloak connection profiles. Each profile is a complete set of Keycloak parameters stored in
// the database (never .env); exactly one may be active, and the app runs on it. Activating or
// editing the active profile applies at once: config is updated in place and listeners (the
// SAML strategy) rebuild themselves. Profiles can be exported to and imported from JSON.

const ACTIVE_KEY = 'active_keycloak_profile';
export const EXPORT_FORMAT = 'cloaktail-keycloak-profiles';
const EXPORT_VERSION = 1;
const MAX_IMPORT = 100;

// ---------- fields ----------

const REALM_RE = /^[A-Za-z0-9._-]{1,100}$/;
const CLIENT_ID_RE = /^[\x21-\x7e]{1,255}$/; // printable ASCII, no spaces (entity IDs may be URLs)

function validUrl(value) {
  let url;
  try { url = new URL(value); } catch { return 'Enter a full URL, like https://sso.example.com.'; }
  if (!['http:', 'https:'].includes(url.protocol)) return 'Use an http:// or https:// URL.';
  if (url.search || url.hash || url.username || url.password) return 'Remove the query string, fragment or credentials.';
  return null;
}
const validRealm = (v) => (REALM_RE.test(v) ? null : 'Use letters, digits, dots, dashes or underscores.');
const validClientId = (v) => (CLIENT_ID_RE.test(v) ? null : 'Use up to 255 printable characters, without spaces.');
function validCert(v) {
  try {
    new crypto.X509Certificate(Buffer.from(v, 'base64'));
    return null;
  } catch {
    return 'This is not a valid X.509 certificate.';
  }
}

export const PROFILE_SECTIONS = [
  { id: 'server', title: 'Keycloak server', text: 'Base URL used for sign-in redirects and Admin API calls.' },
  { id: 'portal', title: 'Portal realm', text: 'Where developers sign in to CloakTail.' },
  { id: 'sandbox', title: 'Sandbox realm', text: "Holds developers' SAML clients and test users. Must differ from the portal realm." },
];

export const PROFILE_FIELDS = [
  { key: 'url', section: 'server', label: 'Keycloak URL', required: true, placeholder: 'https://sso.example.com',
    hint: 'Without /realms/….', normalize: (v) => v.replace(/\/+$/, ''), validate: validUrl },
  { key: 'realm', section: 'portal', label: 'Realm', required: true, placeholder: 'ep', validate: validRealm },
  { key: 'samlIssuer', section: 'portal', label: 'SAML client ID', required: true, placeholder: 'samlclient',
    hint: "Client ID of the portal's SAML client in this realm.", validate: validClientId },
  { key: 'idpCert', section: 'portal', label: 'Pinned signing certificate', multiline: true,
    hint: 'Optional. Leave empty to read the certificate from the realm descriptor, which follows key rotation.',
    normalize: stripPem, validate: validCert },
  { key: 'adminClientId', section: 'portal', label: 'Service account client ID', required: true, placeholder: 'samlclient-admin',
    hint: 'Needs view-users, query-users and manage-users.', validate: validClientId },
  { key: 'adminClientSecret', section: 'portal', label: 'Service account client secret', secret: true },
  { key: 'sandboxRealm', section: 'sandbox', label: 'Realm', required: true, placeholder: 'ep-dev', validate: validRealm },
  { key: 'sandboxAdminClientId', section: 'sandbox', label: 'Service account client ID', required: true, placeholder: 'devportal-admin',
    hint: 'Needs the view, query and manage roles for clients and users.', validate: validClientId },
  { key: 'sandboxAdminClientSecret', section: 'sandbox', label: 'Service account client secret', secret: true },
];
const SETTING_FIELDS = PROFILE_FIELDS.filter((f) => !f.secret);
const SECRET_FIELDS = PROFILE_FIELDS.filter((f) => f.secret);
const LABELS = { name: 'Name', description: 'Description', ...Object.fromEntries(PROFILE_FIELDS.map((f) => [f.key, f.key])) };

// ---------- rows <-> profiles ----------

const pick = (obj, fields) => Object.fromEntries(fields.map((f) => [f.key, typeof obj?.[f.key] === 'string' ? obj[f.key] : '']));

function fromRow(row) {
  let secrets = pick({}, SECRET_FIELDS);
  let secretsUnreadable = false;
  if (row.secrets) {
    try {
      secrets = pick(JSON.parse(decrypt(row.secrets)), SECRET_FIELDS);
    } catch {
      secretsUnreadable = true;
    }
  }
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    settings: pick(JSON.parse(row.settings), SETTING_FIELDS),
    secrets,
    secretsUnreadable,
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedBy: row.updated_by,
    updatedAt: row.updated_at,
  };
}

function toRow(profile, by) {
  const secrets = Object.fromEntries(Object.entries(profile.secrets).filter(([, v]) => v));
  return {
    name: profile.name,
    description: profile.description,
    settings: JSON.stringify(profile.settings),
    secrets: Object.keys(secrets).length ? encrypt(JSON.stringify(secrets)) : '',
    by,
  };
}

// Picks a name not used yet: "Prod", "Prod (2)", "Prod (3)"...
async function uniqueName(base) {
  if (!(await getProfileRowByName(base))) return base;
  for (let n = 2; ; n++) {
    const suffix = ` (${n})`;
    const name = base.slice(0, 60 - suffix.length) + suffix;
    if (!(await getProfileRowByName(name))) return name;
  }
}

// ---------- validation ----------

// input: { name, description, settings: {...}, secrets: {...} } with raw values.
// Returns { profile, errors } where errors maps a field key (or "name") to a message.
async function validateProfile(input, { id = null, checkName = true } = {}) {
  const errors = {};
  const name = String(input.name ?? '').trim();
  const description = String(input.description ?? '').trim();

  if (!name) errors.name = 'Enter a name.';
  else if (name.length > 60) errors.name = 'Use at most 60 characters.';
  else if (/[\x00-\x1f\x7f]/.test(name)) errors.name = 'Remove control characters.';
  else if (checkName) {
    const other = await getProfileRowByName(name);
    if (other && other.id !== id) errors.name = `A profile named "${other.name}" already exists.`;
  }
  if (description.length > 300) errors.description = 'Use at most 300 characters.';

  const settings = {};
  for (const f of SETTING_FIELDS) {
    const raw = String(input.settings?.[f.key] ?? '').trim();
    const value = f.normalize ? f.normalize(raw) : raw;
    settings[f.key] = value;
    if (!value) {
      if (f.required) errors[f.key] = 'Required.';
      continue;
    }
    const problem = f.validate?.(value);
    if (problem) errors[f.key] = problem;
  }
  if (!errors.realm && !errors.sandboxRealm && settings.realm === settings.sandboxRealm) {
    errors.sandboxRealm = "Must differ from the portal realm, so developer clients can never receive real users' identities.";
  }

  const secrets = {};
  for (const f of SECRET_FIELDS) {
    const value = String(input.secrets?.[f.key] ?? '').trim();
    if (value.length > 512) errors[f.key] = 'Use at most 512 characters.';
    secrets[f.key] = value;
  }
  return { profile: { name, description, settings, secrets }, errors };
}

// Builds profile input from the edit form. Secret inputs: empty keeps the stored value,
// KEY_clear=on removes it.
export function profileInputFromForm(body, existing = null) {
  const secrets = {};
  for (const f of SECRET_FIELDS) {
    const typed = String(body[f.key] ?? '').trim();
    if (body[`${f.key}_clear`] === 'on') secrets[f.key] = '';
    else secrets[f.key] = typed || existing?.secrets[f.key] || '';
  }
  return {
    name: body.name,
    description: body.description,
    settings: Object.fromEntries(SETTING_FIELDS.map((f) => [f.key, body[f.key]])),
    secrets,
  };
}

// ---------- active profile ----------

export async function getActiveProfileId() {
  const row = await getSetting(ACTIVE_KEY);
  return row ? Number(row.value) : null;
}

export async function getActiveProfile() {
  const id = await getActiveProfileId();
  const row = id ? await getProfileRow(id) : null;
  return row ? fromRow(row) : null;
}

const listeners = [];
export const onKeycloakSettingsChange = (fn) => listeners.push(fn);

let warnedUnreadable = false;

async function apply({ notify = true } = {}) {
  const profile = await getActiveProfile();
  if (profile?.secretsUnreadable && !warnedUnreadable) {
    console.warn(`The client secrets of Keycloak profile "${profile.name}" can't be decrypted (did SETTINGS_KEY or SESSION_SECRET change?). Enter them again in the admin console.`);
    warnedUnreadable = true;
  }
  applyKeycloakSettings(profile ? { ...profile.settings, ...profile.secrets } : null);
  if (!notify) return;
  for (const fn of listeners) {
    try { await fn(); } catch (err) { console.error('Applying the Keycloak profile failed:', err); }
  }
}

export async function activateProfile(id, by) {
  const row = await getProfileRow(id);
  if (!row) return false;
  await setSetting(ACTIVE_KEY, String(row.id), by);
  console.log(`[admin] ${by} activated Keycloak profile "${row.name}"`);
  await apply();
  return true;
}

// ---------- profiles ----------

export async function listProfiles() {
  const [activeId, rows] = await Promise.all([getActiveProfileId(), listProfileRows()]);
  return rows.map((row) => ({ ...fromRow(row), active: row.id === activeId }));
}

export async function getProfile(id) {
  const row = await getProfileRow(id);
  return row ? { ...fromRow(row), active: row.id === await getActiveProfileId() } : null;
}

export async function createProfile(input, by) {
  const { profile, errors } = await validateProfile(input);
  if (Object.keys(errors).length) return { errors, profile };
  const id = await insertProfileRow(toRow(profile, by));
  console.log(`[admin] ${by} created Keycloak profile "${profile.name}"`);
  return { errors, id };
}

export async function updateProfile(id, input, by) {
  const { profile, errors } = await validateProfile(input, { id });
  if (Object.keys(errors).length) return { errors, profile };
  await updateProfileRow(id, toRow(profile, by));
  console.log(`[admin] ${by} updated Keycloak profile "${profile.name}"`);
  if (id === await getActiveProfileId()) await apply();
  return { errors };
}

export async function duplicateProfile(id, by) {
  const source = await getProfile(id);
  if (!source) return null;
  const copy = { ...source, name: await uniqueName(`${source.name.slice(0, 53)} (copy)`), secrets: source.secrets };
  return insertProfileRow(toRow(copy, by));
}

// The active profile can't be deleted: activate another one first.
export async function deleteProfile(id, by) {
  const row = await getProfileRow(id);
  if (!row) return { error: 'Profile not found.' };
  if (row.id === await getActiveProfileId()) return { error: 'This profile is active. Activate another profile before deleting it.' };
  await deleteProfileRow(row.id);
  console.log(`[admin] ${by} deleted Keycloak profile "${row.name}"`);
  return { error: null };
}

// ---------- export / import ----------

// ids: profile ids, or null for all. Client secrets are left out unless includeSecrets is set.
export async function exportProfiles(ids, { includeSecrets = false } = {}) {
  const profiles = ids ? (await Promise.all(ids.map(getProfile))).filter(Boolean) : await listProfiles();
  return {
    format: EXPORT_FORMAT,
    version: EXPORT_VERSION,
    exportedAt: new Date().toISOString(),
    includesSecrets: includeSecrets,
    profiles: profiles.map((p) => ({
      name: p.name,
      description: p.description,
      settings: p.settings,
      ...(includeSecrets ? { secrets: Object.fromEntries(Object.entries(p.secrets).filter(([, v]) => v)) } : {}),
    })),
  };
}

// onConflict decides what happens when a profile with the same name exists:
//   rename (import as "Name (2)"), overwrite (replace it; secrets missing from the file are kept), skip.
// Everything is validated first; nothing is written unless every profile in the file is valid.
export async function importProfiles(text, { onConflict = 'rename', by }) {
  let data;
  try { data = JSON.parse(text); } catch { return { error: 'This is not valid JSON.' }; }
  if (data?.format !== EXPORT_FORMAT) return { error: `This is not a CloakTail Keycloak profile export (expected "format": "${EXPORT_FORMAT}").` };
  if (data.version !== EXPORT_VERSION) return { error: `Unsupported export version ${data.version}; this CloakTail reads version ${EXPORT_VERSION}.` };
  if (!Array.isArray(data.profiles) || !data.profiles.length) return { error: 'The file contains no profiles.' };
  if (data.profiles.length > MAX_IMPORT) return { error: `The file contains more than ${MAX_IMPORT} profiles.` };

  const plan = [];
  const problems = [];
  const seen = new Set();
  for (const [i, raw] of data.profiles.entries()) {
    const label = `Profile ${i + 1}${typeof raw?.name === 'string' ? ` "${raw.name.slice(0, 60)}"` : ''}`;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      problems.push(`${label}: not an object.`);
      continue;
    }
    const name = String(raw.name ?? '').trim();
    if (seen.has(name.toLowerCase())) {
      problems.push(`${label}: the name appears more than once in the file.`);
      continue;
    }
    seen.add(name.toLowerCase());

    const existing = name ? await getProfileRowByName(name) : null;
    const action = existing ? onConflict : 'create';
    if (action === 'skip') {
      plan.push({ action, name: existing.name });
      continue;
    }

    const providedSecrets = raw.secrets && typeof raw.secrets === 'object' ? raw.secrets : {};
    const { profile, errors } = await validateProfile(
      { name, description: raw.description, settings: raw.settings, secrets: providedSecrets },
      { checkName: false },
    );
    if (Object.keys(errors).length) {
      problems.push(`${label}: ${Object.entries(errors).map(([k, m]) => `${LABELS[k] || k}: ${m}`).join(' ')}`);
      continue;
    }
    plan.push({ action, existing, profile, providedSecrets });
  }
  if (problems.length) return { error: 'Nothing was imported. Fix these problems in the file and try again:', problems };

  const result = { created: [], overwritten: [], skipped: [] };
  const activeId = await getActiveProfileId();
  let reapply = false;
  await transaction(async () => {
    for (const item of plan) {
      if (item.action === 'skip') {
        result.skipped.push(item.name);
      } else if (item.action === 'overwrite') {
        const current = fromRow(item.existing);
        const secrets = Object.fromEntries(SECRET_FIELDS.map((f) => [
          f.key, typeof item.providedSecrets[f.key] === 'string' ? item.profile.secrets[f.key] : current.secrets[f.key],
        ]));
        await updateProfileRow(item.existing.id, toRow({ ...item.profile, name: item.existing.name, secrets }, by));
        result.overwritten.push(item.existing.name);
        if (item.existing.id === activeId) reapply = true;
      } else {
        const name = await uniqueName(item.profile.name);
        await insertProfileRow(toRow({ ...item.profile, name }, by));
        result.created.push(name);
      }
    }
  });
  console.log(`[admin] ${by} imported Keycloak profiles: ${result.created.length} created, ${result.overwritten.length} overwritten, ${result.skipped.length} skipped`);
  if (reapply) await apply();
  return { result };
}

// ---------- one-time migration from .env / the old settings table ----------

const LEGACY = {
  url: 'KEYCLOAK_URL',
  realm: 'KEYCLOAK_REALM',
  samlIssuer: 'SAML_ISSUER',
  idpCert: 'SAML_IDP_CERT',
  adminClientId: 'KEYCLOAK_ADMIN_CLIENT_ID',
  adminClientSecret: 'KEYCLOAK_ADMIN_CLIENT_SECRET',
  sandboxRealm: 'SANDBOX_REALM',
  sandboxAdminClientId: 'SANDBOX_ADMIN_CLIENT_ID',
  sandboxAdminClientSecret: 'SANDBOX_ADMIN_CLIENT_SECRET',
};

// Before profiles existed, Keycloak parameters lived in .env (optionally overridden in the
// settings table). On the first start without any profile they become the active "Default" profile.
async function migrateLegacySettings() {
  if ((await listProfileRows()).length) return;
  const stored = new Map((await listSettingRows()).map((r) => [r.key, r.value]));
  const legacy = (key) => {
    const value = stored.get(key);
    if (value === undefined) return process.env[key] || '';
    if (!value.startsWith('enc:')) return value;
    try { return decrypt(value); } catch { return ''; }
  };
  if (!legacy('KEYCLOAK_URL')) return;

  const defaults = { realm: 'ep', samlIssuer: 'samlclient', adminClientId: 'samlclient-admin', sandboxRealm: 'ep-dev', sandboxAdminClientId: 'devportal-admin' };
  const values = Object.fromEntries(Object.entries(LEGACY).map(([key, env]) => [key, legacy(env) || defaults[key] || '']));
  const { profile, errors } = await validateProfile({
    name: 'Default',
    description: 'Migrated from .env',
    settings: values,
    secrets: values,
  });
  if (Object.keys(errors).length) {
    console.warn('Could not move the Keycloak settings from .env into a profile:', errors, '- create a profile in the admin console instead.');
    return;
  }
  await transaction(async () => {
    const id = await insertProfileRow(toRow(profile, 'migration'));
    await setSetting(ACTIVE_KEY, String(id), 'migration');
    for (const key of Object.values(LEGACY)) await deleteSetting(key);
  });
  console.log('Moved the Keycloak settings from .env into the Keycloak profile "Default", now active. '
    + `.env is no longer read for them; you can remove ${Object.values(LEGACY).join(', ')}.`);
}

await migrateLegacySettings();
// Applied at import, before auth.js builds the SAML strategy from config.
await apply({ notify: false });
