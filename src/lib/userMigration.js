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

// Why /migrate turns a request down: a stable code, and what the application must fix. The codes go
// to the request history and to /migrate/check, and /migrate/spec.md lists them. The check endpoint
// reports unknown_client and bad_signature as invalid_request, so it doesn't say which client IDs exist.
export const REQUEST_ERRORS = {
  invalid_request: 'The request is not a JWT signed by an application with user migration set up. Check that iss is exactly your client ID and that you sign with the method chosen on the migration page (the request history there says which).',
  malformed: 'The request is not a compact JWS (three base64url parts). Send the signed JWT itself, not its claims.',
  unknown_client: 'No application with user migration set up has this client ID as iss.',
  bad_signature: 'The signature doesn’t verify: wrong secret or key, or another algorithm than the migration page’s signing method.',
  migration_disabled: 'User migration is turned off for this application. Turn it on on the migration page.',
  secret_unreadable: 'CloakTail can’t decrypt this application’s migration secret. Generate a new one on the migration page.',
  aud_mismatch: 'aud must be the CloakTail migrate URL.',
  times_missing: 'iat and exp are required, as integers (seconds since 1970).',
  expired: 'exp has passed. Build a new request for every redirect.',
  iat_in_future: 'iat is in the future: check the server clock.',
  lifetime_too_long: 'exp - iat must be at most 600 seconds.',
  jti_missing: 'jti is required: a new random string (at most 200 characters) for every request.',
  jti_reused: 'This jti was already used. Use a new random jti for every request.',
  sub_invalid: 'sub must be the user’s id in your application, a string of 1 to 255 characters.',
  username_invalid: 'preferred_username is required: 1 to 255 characters, no spaces or control characters.',
  return_url_unregistered: 'return_url must be exactly one of the return URLs registered on the migration page.',
  claim_invalid: 'email, given_name, family_name and state must be strings (at most 254, 100, 100 and 500 characters).',
  email_invalid: 'email is not an email address.',
  // Only from /migrate/check and /migrate/simulate.
  status_invalid: 'status must be one of the result statuses.',
  rate_limited: 'Too many requests from this address. Try again in 15 minutes.',
};

// The statuses of a result, what they mean and what the application does. `detail` is the
// error_description CloakTail sends with it.
export const RESULT_STATUSES = {
  created: { meaning: 'The Keycloak account was created with the new password.', action: 'Mark the user migrated and start their session at once: they already signed in with their old password. From their next sign-in, they sign in with Keycloak.' },
  already_migrated: { meaning: 'CloakTail migrated this user (sub) for this application before, or the developer linked their existing account; no password was asked.', action: 'Mark the user migrated, then sign them in with Keycloak.' },
  conflict: { meaning: 'A different Keycloak account already has this username or email.', action: 'Don’t mark the user migrated. Tell them a person must sort it out; let them in the old way meanwhile. If the account is theirs, the developer links it to their sub and the next request answers already_migrated.', detail: 'A different account already uses this username or email address.' },
  cancelled: { meaning: 'The user cancelled. No account was created.', action: 'Let them in the old way this time; ask again next time.' },
  expired: { meaning: 'The user took longer than 30 minutes. No account was created.', action: 'Let them in the old way this time; ask again next time.', detail: 'The user took too long to choose a password.' },
  error: { meaning: 'Keycloak rejected the account. No account was created.', action: 'Let them in the old way this time; ask again next time.', detail: 'Keycloak rejected the account details.' },
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

// With OTP required, the user sets up their authenticator app on /migrate itself and is created with
// the OTP credential, so Keycloak must not ask again. A realm can add Configure OTP to every new user
// (a default action) whatever the create request says; the user is then updated without it.
export const OTP_SETUP_ACTION = 'CONFIGURE_TOTP';

// ---------- warnings ----------
// Things about a migration setup the developer should know, none of which stop it working now:
// { code, message, who_can_fix ('developer' | 'admin'), impact, ignorable_if } — stable codes, so
// pages and agents can act on them without parsing the message.

// Whether the sandbox realm keeps the migration attributes on users. CloakTail's own record decides
// "already migrated", so this only affects what other tools see on the Keycloak user.
async function attributesWarning() {
  try {
    const profile = await sandboxAdmin.getUserProfileConfig();
    const declared = new Set((profile.attributes || []).map((a) => a.name));
    const missing = Object.values(MIGRATION_ATTRIBUTES).filter((n) => !declared.has(n));
    if (!missing.length || ['ENABLED', 'ADMIN_EDIT'].includes(profile.unmanagedAttributePolicy)) return null;
    return {
      code: 'realm_drops_migration_attributes',
      message: `The sandbox realm drops the user attributes ${missing.join(', ')}, so migrated users in Keycloak don’t show which legacy account they came from. `
        + 'An administrator can set Realm settings → General → Unmanaged attributes to “Admin can edit” or “Enabled”.',
      who_can_fix: 'admin',
      impact: 'Low: CloakTail’s own record still recognises returning users (already_migrated). Only tools that read these attributes from Keycloak miss them.',
      ignorable_if: 'Nothing reads legacy_id, migrated_from or migrated_at from Keycloak users.',
    };
  } catch (err) {
    return {
      code: 'realm_check_failed',
      message: `Couldn’t check the sandbox realm’s user attributes: ${err.message}`,
      who_can_fix: 'admin',
      impact: 'None on migration itself.',
      ignorable_if: 'Migrations work; this is only a missing check.',
    };
  }
}

// Whether CloakTail can use the application's JWKS: reachable, JSON, with a signing key.
async function jwksWarning(jwksUrl) {
  const warn = (code, message) => ({
    code,
    message,
    who_can_fix: 'developer',
    impact: 'High: /migrate/start refuses every request (bad_signature) until CloakTail can read a signing key there.',
    ignorable_if: 'The JWKS URL is only unreachable from CloakTail for now and will be reachable when users migrate.',
  });
  let jwks;
  try {
    const res = await fetch(jwksUrl, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return warn('jwks_unreachable', `CloakTail got HTTP ${res.status} from the JWKS URL ${jwksUrl}.`);
    jwks = await res.json();
  } catch (err) {
    return warn('jwks_unreachable', `CloakTail can’t read the JWKS URL ${jwksUrl}: ${err.name === 'TimeoutError' ? 'no answer within 5 seconds' : err.message}.`);
  }
  const usable = (Array.isArray(jwks?.keys) ? jwks.keys : []).filter((k) => k.use !== 'enc' && k.kty && k.kid);
  if (!usable.length) return warn('jwks_no_usable_key', `The JWKS at ${jwksUrl} has no signing key with a kid. Requests must name one in their kid header.`);
  return null;
}

// The warnings for an application's migration setup (an empty list when there are none).
export async function migrationWarnings(migration) {
  if (!migration) return [];
  const checks = [migration.enabled ? attributesWarning() : null];
  if (migration.settings.requestKey === 'jwks' && migration.settings.jwksUrl) checks.push(jwksWarning(migration.settings.jwksUrl));
  return (await Promise.all(checks)).filter(Boolean);
}
