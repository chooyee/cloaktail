import crypto from 'node:crypto';
import { config, currentProfileId } from '../config.js';
import { decodeJwt, verifyJwtHs256, signJwtHs256 } from './jwt.js';
import {
  getApiCredentialByClientId, getApiCredential, insertApiCredential, countApiCredentials, touchApiCredential,
} from '../db.js';
import { ServiceError, invalid } from '../services/errors.js';

// REST API credentials (routes/api.js). A developer creates them on /api-credentials; each acts as
// that developer, limited to its scopes and to the developer's current permissions, on the domains of
// the Keycloak profile it was created on. A client exchanges its client ID and secret for a short-lived
// access token (OAuth 2.0 client credentials grant), sent as "Authorization: Bearer" on every call.

export const SCOPES = {
  'apps:read': 'List and read applications, test runs, user migration settings and history',
  'apps:write': 'Register, change and delete applications; set up user migration; start tests; rotate secrets',
  'secrets:read': 'Read OIDC client secrets and user migration secrets',
  test_users: 'List, create and delete sandbox test users and set their passwords',
  tools: 'Generate SAML certificates',
};

export const EXPIRY_DAYS = { 30: '30 days', 90: '90 days', 365: '1 year', 0: 'Never' };
export const MAX_CREDENTIALS = 10;
export const TOKEN_TTL_S = 15 * 60;

const CLIENT_ID_PREFIX = 'ctc_';
const SECRET_PREFIX = 'cts_';
const hash = (secret) => crypto.createHash('sha256').update(secret).digest('hex');
const tokenKey = Buffer.from(crypto.hkdfSync('sha256', config.settingsKey, Buffer.alloc(0), 'cloaktail api token v1', 32));

const expired = (row) => row.expires_at && row.expires_at <= new Date().toISOString().slice(0, 19).replace('T', ' ');
export const parseScopes = (text) => (text || '').split(/\s+/).filter((s) => Object.hasOwn(SCOPES, s));

// Creates a credential. Returns { id, clientId, secret }: the secret is never shown again.
export async function createApiCredential(owner, { name, scopes, expiryDays }) {
  name = (name || '').trim();
  if (!name || name.length > 60) throw invalid('Give the credential a name of up to 60 characters, e.g. "Claude Code on my laptop".', { field: 'name' });
  scopes = [...new Set(scopes)].filter((s) => Object.hasOwn(SCOPES, s));
  if (!scopes.length) throw invalid('Choose at least one scope.', { field: 'scopes' });
  if (!Object.hasOwn(EXPIRY_DAYS, expiryDays)) throw invalid('Choose when the credential expires.', { field: 'expiryDays' });
  if (await countApiCredentials(owner) >= MAX_CREDENTIALS) {
    throw new ServiceError(422, 'quota_exceeded', `You have reached the limit of ${MAX_CREDENTIALS} API credentials. Revoke one first.`);
  }
  const days = Number(expiryDays);
  const expiresAt = days ? new Date(Date.now() + days * 86400_000).toISOString().slice(0, 19).replace('T', ' ') : null;
  const clientId = CLIENT_ID_PREFIX + crypto.randomBytes(12).toString('base64url');
  const secret = SECRET_PREFIX + crypto.randomBytes(32).toString('base64url');
  const id = await insertApiCredential({ owner, name, clientId, secretHash: hash(secret), scopes: scopes.join(' '), expiresAt });
  return { id, clientId, secret };
}

// The credential for a client ID and secret, on this request's profile; null when they don't match
// one, it has expired or it belongs to another profile's domains.
export async function authenticateClient(clientId, secret) {
  if (typeof clientId !== 'string' || typeof secret !== 'string' || !clientId.startsWith(CLIENT_ID_PREFIX)) return null;
  const row = await getApiCredentialByClientId(clientId);
  const given = Buffer.from(hash(secret));
  const ok = row && crypto.timingSafeEqual(given, Buffer.from(row.secret_hash));
  if (!ok || expired(row) || row.profile_id !== currentProfileId()) return null;
  return row;
}

// An access token for the credential, granting `scopes` (a subset of its own).
export function issueAccessToken(row, scopes, siteUrl) {
  const now = Math.floor(Date.now() / 1000);
  touchApiCredential(row.id).catch((err) => console.error('Recording API credential use failed:', err));
  return signJwtHs256({
    iss: siteUrl,
    aud: `${siteUrl}/api/v1`,
    sub: row.owner,
    cid: row.id,
    pid: row.profile_id,
    scope: scopes.join(' '),
    iat: now,
    exp: now + TOKEN_TTL_S,
    jti: crypto.randomUUID(),
  }, tokenKey);
}

// The credential and scopes of a bearer token, or null when the token is invalid, expired, from
// another profile, or its credential was revoked or has expired since (checked on every call).
export async function authenticateToken(token) {
  const jwt = decodeJwt(token);
  if (!jwt) return null;
  try { verifyJwtHs256(jwt, tokenKey); } catch { return null; }
  const { sub, cid, pid, scope, exp } = jwt.payload;
  if (typeof exp !== 'number' || exp <= Date.now() / 1000 || pid !== currentProfileId()) return null;
  const row = await getApiCredential(cid);
  if (!row || row.owner !== sub || expired(row)) return null;
  return { credential: row, scopes: parseScopes(scope).filter((s) => parseScopes(row.scopes).includes(s)) };
}
