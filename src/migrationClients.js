import crypto from 'node:crypto';
import { encrypt, decrypt } from './lib/secretBox.js';
import { deriveKeycloakConfig } from './config.js';
import { createAdminClient } from './lib/keycloakAdmin.js';
import {
  listMigrationClientRows, getMigrationClientRow, getMigrationClientRowByClientId, insertMigrationClientRow,
  updateMigrationClientRow, deleteMigrationClientRow,
} from './db.js';

// User migration clients. A legacy application that still signs its users in itself sends each
// not-yet-migrated user to /migrate (routes/migrate.js) with a signed request saying who they are.
// CloakTail asks the user for a new password and creates them in the profile's sandbox realm (with
// the sandbox service account), then sends them back with a signed result. Each client belongs to
// one Keycloak profile and is reachable on that profile's domains.

// Attributes CloakTail sets on every migrated user: the link back to the legacy account, and what
// makes a repeated request recognisable as "already migrated". The sandbox realm must accept them
// (Realm settings → General → Unmanaged attributes: Enabled or Admin can edit; or declare them in User profile).
export const MIGRATION_ATTRIBUTES = { legacyId: 'legacy_id', migratedFrom: 'migrated_from', migratedAt: 'migrated_at' };

export const REQUEST_KEYS = {
  secret: 'Client secret (HS256)',
  publicKey: 'Public key (PEM)',
  jwks: 'JWKS URL',
};

const CLIENT_ID_RE = /^[\x21-\x7e]{1,255}$/;
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

// ---------- rows <-> clients ----------

const SETTING_DEFAULTS = {
  returnUrls: [],
  requestKey: 'secret',
  publicKey: '',
  jwksUrl: '',
  requireOtp: true,
};

function fromRow(row) {
  let secrets = { clientSecret: '' };
  let secretsUnreadable = false;
  if (row.secrets) {
    try {
      secrets = { ...secrets, ...JSON.parse(decrypt(row.secrets)) };
    } catch {
      secretsUnreadable = true;
    }
  }
  return {
    id: row.id,
    profileId: row.profile_id,
    clientId: row.client_id,
    name: row.name,
    enabled: Boolean(row.enabled),
    settings: { ...SETTING_DEFAULTS, ...JSON.parse(row.settings) },
    secrets,
    secretsUnreadable,
    migrated: row.migrated ?? null,
    conflicts: row.conflicts ?? null,
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedBy: row.updated_by,
    updatedAt: row.updated_at,
  };
}

const toRow = (client, by) => ({
  clientId: client.clientId,
  name: client.name,
  enabled: client.enabled,
  settings: JSON.stringify(client.settings),
  secrets: encrypt(JSON.stringify(client.secrets)),
  by,
});

export const newClientSecret = () => crypto.randomBytes(32).toString('base64url');

export const listMigrationClients = async (profileId) => (await listMigrationClientRows(profileId)).map(fromRow);

export async function getMigrationClient(profileId, id) {
  const row = await getMigrationClientRow(profileId, id);
  return row ? fromRow(row) : null;
}

// For /migrate: the client named by a request's issuer, in the profile serving the request.
export async function findMigrationClient(profileId, clientId) {
  if (typeof clientId !== 'string' || !CLIENT_ID_RE.test(clientId)) return null;
  const row = await getMigrationClientRowByClientId(profileId, clientId);
  return row ? fromRow(row) : null;
}

// ---------- form input and validation ----------

const lines = (text) => String(text ?? '').split(/[\r\n]+/).map((l) => l.trim()).filter(Boolean);

// The admin form, as entered.
export function migrationInputFromForm(body) {
  return {
    name: String(body.name ?? '').trim(),
    clientId: String(body.clientId ?? '').trim(),
    enabled: body.enabled === 'on',
    returnUrls: lines(body.returnUrls),
    requestKey: String(body.requestKey ?? ''),
    publicKey: String(body.publicKey ?? '').trim(),
    jwksUrl: String(body.jwksUrl ?? '').trim(),
    requireOtp: body.requireOtp === 'on',
  };
}

// Returns { client, errors }: the client to store, keeping its client secret.
async function validate(profileId, input, existing) {
  const errors = {};
  if (!input.name) errors.name = 'Enter a name.';
  else if (input.name.length > 80 || /[\x00-\x1f\x7f]/.test(input.name)) errors.name = 'Use at most 80 characters, without control characters.';

  if (!CLIENT_ID_RE.test(input.clientId)) errors.clientId = 'Use up to 255 printable characters, without spaces.';
  else {
    const other = await getMigrationClientRowByClientId(profileId, input.clientId);
    if (other && other.id !== existing?.id) errors.clientId = `Client "${input.clientId}" already exists in this profile.`;
  }

  if (!input.returnUrls.length) errors.returnUrls = 'Enter at least one return URL.';
  else if (input.returnUrls.length > MAX_RETURN_URLS) errors.returnUrls = `Use at most ${MAX_RETURN_URLS} return URLs.`;
  else {
    const problem = input.returnUrls.map((u) => urlProblem(u)).find(Boolean);
    if (problem) errors.returnUrls = problem;
  }

  if (!Object.hasOwn(REQUEST_KEYS, input.requestKey)) errors.requestKey = 'Choose how requests are signed.';
  if (input.requestKey === 'publicKey') {
    errors.publicKey = input.publicKey ? publicKeyProblem(input.publicKey) : 'Paste the application’s public key.';
    if (!errors.publicKey) delete errors.publicKey;
  }
  if (input.requestKey === 'jwks') {
    const problem = input.jwksUrl ? urlProblem(input.jwksUrl) : 'Enter the URL of the application’s JWKS.';
    if (problem) errors.jwksUrl = problem;
  }

  const client = {
    clientId: input.clientId,
    name: input.name,
    enabled: input.enabled,
    settings: {
      returnUrls: [...new Set(input.returnUrls)],
      requestKey: input.requestKey,
      // Keep only what the chosen method uses.
      publicKey: input.requestKey === 'publicKey' ? input.publicKey : '',
      jwksUrl: input.requestKey === 'jwks' ? input.jwksUrl : '',
      requireOtp: input.requireOtp,
    },
    secrets: { clientSecret: existing?.secrets.clientSecret || newClientSecret() },
  };
  return { client, errors };
}

// Returns { errors, id, clientSecret }; the client secret is shown to the administrator once.
export async function createMigrationClient(profileId, input, by) {
  const { client, errors } = await validate(profileId, input, null);
  if (Object.keys(errors).length) return { errors };
  const id = await insertMigrationClientRow(profileId, toRow(client, by));
  console.log(`[admin] ${by} created migration client "${client.clientId}" in profile ${profileId}`);
  return { errors, id, clientSecret: client.secrets.clientSecret };
}

export async function updateMigrationClient(existing, input, by) {
  const { client, errors } = await validate(existing.profileId, input, existing);
  if (Object.keys(errors).length) return { errors };
  await updateMigrationClientRow(existing.profileId, existing.id, toRow(client, by));
  console.log(`[admin] ${by} updated migration client "${client.clientId}" in profile ${existing.profileId}`);
  return { errors };
}

export async function regenerateMigrationClientSecret(existing, by) {
  const clientSecret = newClientSecret();
  await updateMigrationClientRow(existing.profileId, existing.id, toRow({ ...existing, secrets: { ...existing.secrets, clientSecret } }, by));
  console.log(`[admin] ${by} regenerated the secret of migration client "${existing.clientId}" in profile ${existing.profileId}`);
  return clientSecret;
}

export async function deleteMigrationClient(existing, by) {
  await deleteMigrationClientRow(existing.profileId, existing.id);
  console.log(`[admin] ${by} deleted migration client "${existing.clientId}" in profile ${existing.profileId}`);
}

// ---------- users ----------

// Whether a Keycloak user is the one this client already migrated for this legacy account.
export function isSameMigratedUser(user, client, legacyId) {
  const attr = (name) => user?.attributes?.[name]?.[0];
  return attr(MIGRATION_ATTRIBUTES.legacyId) === legacyId && attr(MIGRATION_ATTRIBUTES.migratedFrom) === client.clientId;
}

// Required actions for a new user: OTP setup at their first Keycloak sign-in, when required.
export const newUserRequiredActions = (client) => (client.settings.requireOtp ? ['CONFIGURE_TOTP'] : []);

// ---------- connection checks (admin console) ----------

const TIMEOUT_MS = 8000;

async function check(name, fn) {
  let timer;
  try {
    const result = await Promise.race([
      fn(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`No answer within ${TIMEOUT_MS / 1000} seconds.`)), TIMEOUT_MS); }),
    ]);
    return { name, ok: true, detail: result };
  } catch (err) {
    const cause = err.cause?.code || err.cause?.message;
    return { name, ok: false, detail: cause ? `${err.message} (${cause})` : err.message };
  } finally {
    clearTimeout(timer);
  }
}

// Checks the saved client against the profile's sandbox realm, where it creates users: that the
// sandbox service account can read users, that the realm keeps CloakTail's attributes, and that
// the application's keys can be read.
// profile: from keycloakProfiles.getProfile (settings and secrets).
export async function checkMigrationClient(profile, client) {
  const { sandbox } = deriveKeycloakConfig({ ...profile.settings, ...profile.secrets });
  // Throwaway Admin API client, so checks never touch the cached token of the live one.
  const admin = createAdminClient(() => sandbox, 'sandbox service account client secret');
  const checks = [
    check(`Sandbox service account "${sandbox.adminClientId}" in realm "${sandbox.realm}"`, async () => {
      const count = await admin.countUsers({});
      return `Signed in; can read users (${count} in the realm). It also needs manage-users to create them.`;
    }),
    check('User attributes', async () => {
      const profileConfig = await admin.getUserProfileConfig();
      const declared = new Set((profileConfig.attributes || []).map((a) => a.name));
      const policy = profileConfig.unmanagedAttributePolicy;
      const missing = Object.values(MIGRATION_ATTRIBUTES).filter((n) => !declared.has(n));
      if (!missing.length) return 'All declared in the user profile.';
      if (['ENABLED', 'ADMIN_EDIT'].includes(policy)) return `Kept as unmanaged attributes (policy ${policy}).`;
      throw new Error(`Keycloak would drop ${missing.join(', ')}, so a repeated request would look like a conflict. In realm "${sandbox.realm}", `
        + 'set Realm settings → General → Unmanaged attributes to "Admin can edit" or "Enabled", or declare them in Realm settings → User profile.');
    }),
  ];
  if (client.settings.requestKey === 'jwks') {
    checks.push(check('Application JWKS', async () => {
      const res = await fetch(client.settings.jwksUrl, { signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (!res.ok) throw new Error(`${client.settings.jwksUrl} answered HTTP ${res.status}.`);
      const { keys } = await res.json();
      const signing = (Array.isArray(keys) ? keys : []).filter((k) => k.use !== 'enc');
      if (!signing.length) throw new Error('It publishes no signing keys.');
      return `${signing.length} signing key${signing.length === 1 ? '' : 's'} published.`;
    }));
  }
  return Promise.all(checks);
}

// ---------- integration sample (admin console) ----------

// Node.js code for the application's side, with this client's values; no dependencies.
export function migrationSample(client, siteUrl) {
  const returnUrl = client.settings.returnUrls[0] || 'https://app.example.com/migrated';
  const signRequest = client.settings.requestKey === 'secret'
    ? `const request = signHs256(claims, process.env.CLOAKTAIL_CLIENT_SECRET);`
    : `// Sign with your private key (${client.settings.requestKey === 'jwks' ? 'one published in your JWKS' : 'matching the public key in CloakTail'}), e.g. with "jose":
// const request = await new SignJWT(claims).setProtectedHeader({ alg: 'RS256' }).sign(privateKey);`;
  return `import crypto from 'node:crypto';

const CLOAKTAIL = '${siteUrl}';
const CLIENT_ID = '${client.clientId}';
const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const hmac = (input, secret) => crypto.createHmac('sha256', secret).update(input).digest();

function signHs256(claims, secret) {
  const input = \`\${b64({ alg: 'HS256', typ: 'JWT' })}.\${b64(claims)}\`;
  return \`\${input}.\${hmac(input, secret).toString('base64url')}\`;
}

// 1. After the user signed in with their old password, if they aren't migrated yet:
export function sendToCloakTail(req, res, user) {
  const now = Math.floor(Date.now() / 1000);
  req.session.migrationState = crypto.randomUUID();
  const claims = {
    iss: CLIENT_ID,
    aud: \`\${CLOAKTAIL}/migrate\`,
    iat: now,
    exp: now + 300,
    jti: crypto.randomUUID(),            // new for every request
    sub: String(user.id),                // your user id, stored in Keycloak as ${MIGRATION_ATTRIBUTES.legacyId}
    preferred_username: user.username,
    email: user.email,                   // optional
    given_name: user.firstName,          // optional
    family_name: user.lastName,          // optional
    return_url: '${returnUrl}',
    state: req.session.migrationState,
  };
  ${signRequest.split('\n').join('\n  ')}
  res.redirect(\`\${CLOAKTAIL}/migrate/start?request=\${request}\`);
}

// 2. At the return URL: verify the result, then record the outcome.
export function readResult(req) {
  const [header, payload, signature] = String(req.query.result || '').split('.');
  const expected = hmac(\`\${header}.\${payload}\`, process.env.CLOAKTAIL_CLIENT_SECRET);
  const given = Buffer.from(signature || '', 'base64url');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) throw new Error('Bad signature');
  const result = JSON.parse(Buffer.from(payload, 'base64url'));
  if (JSON.parse(Buffer.from(header, 'base64url')).alg !== 'HS256') throw new Error('Bad algorithm');
  if (result.aud !== CLIENT_ID || result.exp < Date.now() / 1000) throw new Error('Wrong audience or expired');
  if (result.state !== req.session.migrationState) throw new Error('State mismatch');
  delete req.session.migrationState;
  return result; // { status, sub, preferred_username, keycloak_id, ... }
}
// status "created" or "already_migrated": mark the user migrated, then start your Keycloak (OIDC)
// sign-in with login_hint=preferred_username.${client.settings.requireOtp ? ' Keycloak asks them to set up OTP there.' : ''}
// "conflict": a different Keycloak account has that username or email; ask an administrator.
// "cancelled", "expired", "error": let them carry on with the old sign-in, and ask again next time.
`;
}
