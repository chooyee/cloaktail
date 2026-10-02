import crypto from 'node:crypto';
import { config, currentProfileId } from '../config.js';
import { decodeJwt, verifyJwtSignature, halfHash } from './jwt.js';
import { getOidcClientSecret } from './oidcClients.js';

// "Test connection" for OIDC clients: the portal plays the developer's app for one login. It runs
// the authorization code flow with PKCE as their client (with the portal's own redirect URI),
// redeems the code, then validates and explains the tokens and the userinfo response.

const TEST_TTL_MS = 10 * 60 * 1000;
const CLOCK_SKEW_S = 5;
const SCOPE = 'openid profile email';

// Pending tests keyed by the state parameter, which is how Keycloak's redirect finds its test.
const pending = new Map();

function prune() {
  const now = Date.now();
  for (const [k, v] of pending) if (v.expiresAt < now) pending.delete(k);
}

const random = () => crypto.randomBytes(32).toString('base64url');

// Returns the Keycloak URL to send the developer's browser to.
export function startOidcTest({ app, values, startedBy, redirectUri }) {
  prune();
  const state = random();
  const verifier = random();
  const test = {
    appId: app.id,
    kcId: app.kc_id,
    clientId: app.client_id,
    profileId: currentProfileId(),
    isPublic: values.clientType === 'public',
    redirectUri,
    nonce: random(),
    verifier,
    startedBy,
    expiresAt: Date.now() + TEST_TTL_MS,
  };
  pending.set(state, test);
  const url = new URL(config.sandbox.oidc.authorizationEndpoint);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: test.clientId,
    redirect_uri: redirectUri,
    scope: SCOPE,
    state,
    nonce: test.nonce,
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    prompt: 'login', // always show the login form so any test user can be chosen
  });
  return url.toString();
}

const decoded = (jwt) => (jwt ? { header: jwt.header, claims: jwt.payload } : null);
const listOf = (v) => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

// Handles Keycloak's redirect to the test callback. Returns { appId, ok, summary, result } or null
// if the state doesn't belong to a pending test.
export async function finishOidcTest(query) {
  const test = typeof query.state === 'string' ? pending.get(query.state) : null;
  // A response is only checked by the profile (sandbox realm) whose test it answers.
  if (!test || test.expiresAt < Date.now() || test.profileId !== currentProfileId()) return null;
  pending.delete(query.state);

  const op = config.sandbox.oidc;
  const checks = [];
  const add = (label, ok, detail) => checks.push({ label, ok, detail });
  const param = (name) => (typeof query[name] === 'string' ? query[name] : null);
  const details = { authResponse: { iss: param('iss'), sessionState: param('session_state') } };
  const result = { protocol: 'oidc', startedBy: test.startedBy, checks, details };
  const finish = () => {
    const ok = checks.every((c) => c.ok !== false);
    const failed = checks.filter((c) => c.ok === false).map((c) => c.label);
    const who = details.idToken?.claims.preferred_username ?? details.idToken?.claims.sub;
    return { appId: test.appId, ok, summary: ok ? `Signed in as ${who ?? '(unknown)'}` : `Failed: ${failed.join(', ')}`, result };
  };

  // ---------- authorization response ----------
  if (query.error) {
    add('Keycloak returned an authorization code', false,
      [param('error') ?? 'error', param('error_description')].filter(Boolean).join(': '));
    return finish();
  }
  const code = typeof query.code === 'string' ? query.code : '';
  add('Keycloak returned an authorization code', Boolean(code), code ? 'Code received' : 'No code in the redirect');
  // RFC 9207: Keycloak names itself in the redirect, which guards against mix-up attacks.
  if (query.iss !== undefined) add('Issuer in the redirect is the sandbox realm', query.iss === op.issuer, String(query.iss));
  if (!code) return finish();

  // ---------- token request ----------
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: test.redirectUri,
    code_verifier: test.verifier,
    client_id: test.clientId,
  });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
  if (!test.isPublic) {
    let secret = null;
    try { secret = await getOidcClientSecret(test.kcId); } catch (err) { add('Client secret available', false, err.message); return finish(); }
    // client_secret_basic: both parts form-encoded, as RFC 6749 section 2.3.1 requires.
    const enc = (s) => encodeURIComponent(s).replace(/%20/g, '+');
    headers.Authorization = `Basic ${Buffer.from(`${enc(test.clientId)}:${enc(secret ?? '')}`).toString('base64')}`;
  }
  let tokens = null;
  try {
    const res = await fetch(op.tokenEndpoint, { method: 'POST', headers, body: form, signal: AbortSignal.timeout(10_000) });
    const body = await res.json().catch(() => ({}));
    if (res.ok) tokens = body;
    add('Code exchanged for tokens', res.ok,
      res.ok ? `${test.isPublic ? 'Public client with PKCE' : 'Client secret (client_secret_basic) with PKCE'}`
        : `HTTP ${res.status}: ${[body.error, body.error_description].filter(Boolean).join(': ') || 'no details'}`);
  } catch (err) {
    add('Code exchanged for tokens', false, `${err.message}${err.cause?.code ? ` (${err.cause.code})` : ''}`);
  }
  if (!tokens) return finish();
  details.tokenResponse = {
    tokenType: tokens.token_type ?? null,
    expiresIn: tokens.expires_in ?? null,
    refreshExpiresIn: tokens.refresh_expires_in ?? null,
    scope: tokens.scope ?? null,
    refreshToken: Boolean(tokens.refresh_token),
  };
  add('Token type is Bearer', /^bearer$/i.test(tokens.token_type ?? ''), tokens.token_type ?? 'missing');

  // ---------- ID token ----------
  const idToken = decodeJwt(tokens.id_token);
  details.idToken = decoded(idToken);
  add('ID token received', Boolean(idToken), idToken ? `${idToken.header.alg}, key id ${idToken.header.kid ?? '(none)'}` : (tokens.id_token ? 'Not a valid JWT' : 'Missing: is the openid scope allowed?'));
  if (idToken) {
    const c = idToken.payload;
    try {
      add('ID token signature valid', true, `Verified with the realm key (${await verifyJwtSignature(idToken, op.jwksUri)})`);
    } catch (err) {
      add('ID token signature valid', false, err.message);
    }
    const now = Math.floor(Date.now() / 1000);
    const aud = listOf(c.aud);
    add('Issuer is the sandbox realm', c.iss === op.issuer, c.iss ?? 'missing');
    add('Audience is your client ID', aud.includes(test.clientId), aud.join(', ') || 'missing');
    if (aud.length > 1 || c.azp !== undefined) add('Authorized party is your client ID', c.azp === test.clientId, c.azp ?? 'missing');
    add('Not expired', typeof c.exp === 'number' && c.exp + CLOCK_SKEW_S > now,
      typeof c.exp === 'number' ? `Expires ${new Date(c.exp * 1000).toISOString()}` : 'No exp claim');
    add('Issued at a sane time', typeof c.iat === 'number' && c.iat <= now + CLOCK_SKEW_S,
      typeof c.iat === 'number' ? `Issued ${new Date(c.iat * 1000).toISOString()}` : 'No iat claim');
    add('Nonce matches the request', c.nonce === test.nonce, c.nonce === undefined ? 'No nonce claim' : (c.nonce === test.nonce ? 'Matches' : 'Different nonce'));
    if (c.at_hash !== undefined && tokens.access_token) {
      const expected = halfHash(tokens.access_token, idToken.header.alg);
      add('at_hash matches the access token', expected === c.at_hash, expected === c.at_hash ? 'Matches' : `Expected ${expected}, got ${c.at_hash}`);
    }
    add('Subject (sub) present', typeof c.sub === 'string' && c.sub.length > 0, c.sub ?? 'missing');
  }

  // ---------- access token (Keycloak issues JWTs; shown for reference) ----------
  const accessToken = decodeJwt(tokens.access_token);
  details.accessToken = decoded(accessToken);
  if (!tokens.access_token) add('Access token received', false, 'Missing');

  // ---------- userinfo ----------
  if (tokens.access_token) {
    try {
      const res = await fetch(op.userinfoEndpoint, {
        headers: { Authorization: `Bearer ${tokens.access_token}`, Accept: 'application/json' },
        signal: AbortSignal.timeout(10_000),
      });
      const body = await res.json().catch(() => null);
      details.userinfo = res.ok ? body : null;
      const sameSub = res.ok && body?.sub === idToken?.payload.sub;
      add('Userinfo endpoint answers for the same user', res.ok && sameSub,
        !res.ok ? `HTTP ${res.status}${body?.error ? `: ${body.error}` : ''}` : (sameSub ? `sub ${body.sub}` : `sub ${body?.sub} differs from the ID token's`));
    } catch (err) {
      add('Userinfo endpoint answers for the same user', false, err.message);
    }
  }

  // Informational: claims many apps rely on.
  const claims = { ...details.userinfo, ...idToken?.payload };
  const missing = ['email', 'preferred_username', 'given_name', 'family_name'].filter((k) => claims[k] === undefined);
  add('Common profile claims', null, missing.length ? `Missing: ${missing.join(', ')} (is the test user's profile filled in? are the profile and email scopes assigned?)` : 'email, preferred_username, given_name, family_name');
  return finish();
}
