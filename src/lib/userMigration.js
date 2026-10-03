import crypto from 'node:crypto';
import { encrypt, decrypt } from './secretBox.js';
import { sandboxAdmin } from './keycloakAdmin.js';
import { getAppMigrationRow, putAppMigrationRow } from '../db.js';

// User migration for developer applications. An application that still signs its users in itself
// sends each not-yet-migrated user to /migrate (routes/migrate.js) with a signed request saying who
// they are; its "iss" is the application's client ID (OIDC client ID or SAML entity ID). CloakTail
// asks the user for a new password, creates them in the sandbox realm with the sandbox service
// account, then sends them back with a signed result. The developer turns it on and configures it on
// the application's page (/apps/:id/migration).

// Attributes set on every migrated user: the link back to the legacy account, and what makes a
// repeated request recognisable as "already migrated". The sandbox realm must keep them.
export const MIGRATION_ATTRIBUTES = { legacyId: 'legacy_id', migratedFrom: 'migrated_from', migratedAt: 'migrated_at' };

export const REQUEST_KEYS = {
  secret: 'Migration secret (HS256)',
  publicKey: 'Public key (PEM)',
  jwks: 'JWKS URL',
};

const MAX_RETURN_URLS = 20;

function urlProblem(value) {
  let url;
  try { url = new URL(value); } catch { return `"${value}" is not a full URL.`; }
  if (!['http:', 'https:'].includes(url.protocol)) return `"${value}": use an http:// or https:// URL.`;
  if (url.hash || url.username || url.password) return `"${value}": remove the fragment or credentials.`;
  return null;
}

function publicKeyProblem(pem) {
  try {
    const key = crypto.createPublicKey(pem);
    if (key.asymmetricKeyType === 'rsa' && key.asymmetricKeyDetails.modulusLength < 2048) return 'RSA keys need at least 2048 bits.';
    return null;
  } catch {
    return 'This is not a PEM public key (-----BEGIN PUBLIC KEY----- …).';
  }
}

const DEFAULT_SETTINGS = { returnUrls: [], requestKey: 'secret', publicKey: '', jwksUrl: '', requireOtp: true };
export const newMigrationSecret = () => crypto.randomBytes(32).toString('base64url');

// The app's migration settings, or null when it was never set up.
export async function getAppMigration(appId) {
  const row = await getAppMigrationRow(appId);
  if (!row) return null;
  let secret = '';
  try { secret = decrypt(row.secret); } catch { /* SETTINGS_KEY changed: secretUnreadable */ }
  return {
    appId: row.app_id,
    enabled: Boolean(row.enabled),
    settings: { ...DEFAULT_SETTINGS, ...JSON.parse(row.settings) },
    secret,
    secretUnreadable: !secret,
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedBy: row.updated_by,
    updatedAt: row.updated_at,
  };
}

export const defaultMigrationValues = () => ({ enabled: true, ...DEFAULT_SETTINGS, returnUrls: '' });

export const migrationValues = (migration) => ({
  enabled: migration.enabled, ...migration.settings, returnUrls: migration.settings.returnUrls.join('\n'),
});

// The settings form, as entered (returnUrls kept as text for redisplay).
export const parseMigrationForm = (body) => ({
  enabled: body.enabled === 'on',
  returnUrls: String(body.returnUrls ?? ''),
  requestKey: String(body.requestKey ?? ''),
  publicKey: String(body.publicKey ?? '').trim(),
  jwksUrl: String(body.jwksUrl ?? '').trim(),
  requireOtp: body.requireOtp === 'on',
});

// Returns { errors } keyed by field; saves when there are none. A new setup gets a migration secret.
export async function saveAppMigration(app, values, existing, by) {
  const errors = {};
  const returnUrls = [...new Set(values.returnUrls.split(/[\r\n]+/).map((l) => l.trim()).filter(Boolean))];
  if (!returnUrls.length) errors.returnUrls = 'Enter at least one return URL.';
  else if (returnUrls.length > MAX_RETURN_URLS) errors.returnUrls = `Use at most ${MAX_RETURN_URLS} return URLs.`;
  else {
    const problem = returnUrls.map(urlProblem).find(Boolean);
    if (problem) errors.returnUrls = problem;
  }
  if (!Object.hasOwn(REQUEST_KEYS, values.requestKey)) errors.requestKey = 'Choose how requests are signed.';
  if (values.requestKey === 'publicKey') {
    const problem = values.publicKey ? publicKeyProblem(values.publicKey) : 'Paste your application’s public key.';
    if (problem) errors.publicKey = problem;
  }
  if (values.requestKey === 'jwks') {
    const problem = values.jwksUrl ? urlProblem(values.jwksUrl) : 'Enter the URL of your application’s JWKS.';
    if (problem) errors.jwksUrl = problem;
  }
  if (Object.keys(errors).length) return { errors };

  await putAppMigrationRow(app.id, {
    enabled: values.enabled,
    settings: JSON.stringify({
      returnUrls,
      requestKey: values.requestKey,
      // Keep only what the chosen method uses.
      publicKey: values.requestKey === 'publicKey' ? values.publicKey : '',
      jwksUrl: values.requestKey === 'jwks' ? values.jwksUrl : '',
      requireOtp: values.requireOtp,
    }),
    secret: encrypt(existing && !existing.secretUnreadable ? existing.secret : newMigrationSecret()),
    by,
  });
  return { errors };
}

// A new migration secret; the old one stops working at once.
export async function regenerateMigrationSecret(app, migration, by) {
  await putAppMigrationRow(app.id, {
    enabled: migration.enabled,
    settings: JSON.stringify(migration.settings),
    secret: encrypt(newMigrationSecret()),
    by,
  });
}

// ---------- users ----------

// Whether a Keycloak user is the one this application already migrated for this legacy account.
export function isSameMigratedUser(user, app, legacyId) {
  const attr = (name) => user?.attributes?.[name]?.[0];
  return attr(MIGRATION_ATTRIBUTES.legacyId) === legacyId && attr(MIGRATION_ATTRIBUTES.migratedFrom) === app.client_id;
}

// Required actions for a new user: OTP setup at their first Keycloak sign-in, when required.
export const newUserRequiredActions = (migration) => (migration.settings.requireOtp ? ['CONFIGURE_TOTP'] : []);

// Whether the sandbox realm keeps the migration attributes. Returns null when it does, otherwise
// what an administrator must change (or why it couldn't be checked).
export async function sandboxAttributesProblem() {
  try {
    const profile = await sandboxAdmin.getUserProfileConfig();
    const declared = new Set((profile.attributes || []).map((a) => a.name));
    const missing = Object.values(MIGRATION_ATTRIBUTES).filter((n) => !declared.has(n));
    if (!missing.length || ['ENABLED', 'ADMIN_EDIT'].includes(profile.unmanagedAttributePolicy)) return null;
    return `The sandbox realm drops the attributes ${missing.join(', ')}, so a user who comes back would get "conflict" instead of `
      + '"already_migrated". An administrator must set Realm settings → General → Unmanaged attributes to "Admin can edit" or "Enabled".';
  } catch (err) {
    return `Couldn’t check the sandbox realm’s user attributes: ${err.message}`;
  }
}
