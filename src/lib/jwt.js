import crypto from 'node:crypto';

// Just enough JOSE for "Test connection": decode a JWT and verify its signature against a JWKS.

const b64url = (s) => Buffer.from(s, 'base64url');

// Returns { header, payload, signingInput, signature } or null if it isn't a JWS compact JWT.
export function decodeJwt(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    return {
      header: JSON.parse(b64url(parts[0]).toString('utf8')),
      payload: JSON.parse(b64url(parts[1]).toString('utf8')),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: b64url(parts[2]),
    };
  } catch {
    return null;
  }
}

const PSS = { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST };
const ALGORITHMS = {
  RS256: ['sha256', {}], RS384: ['sha384', {}], RS512: ['sha512', {}],
  PS256: ['sha256', PSS], PS384: ['sha384', PSS], PS512: ['sha512', PSS],
  ES256: ['sha256', { dsaEncoding: 'ieee-p1363' }], ES384: ['sha384', { dsaEncoding: 'ieee-p1363' }], ES512: ['sha512', { dsaEncoding: 'ieee-p1363' }],
  EdDSA: [null, {}],
};

// A realm's keys, cached for 10 minutes per URL; fetched again (at most once a minute) when a
// token names a key id that isn't cached, so a Keycloak key rotation is picked up.
const cache = new Map(); // jwksUri -> { keys, fetchedAt }

async function loadJwks(jwksUri, { force = false } = {}) {
  const hit = cache.get(jwksUri);
  const age = hit ? Date.now() - hit.fetchedAt : Infinity;
  if (hit && (age < 60_000 || (!force && age < 600_000))) return hit.keys;
  const res = await fetch(jwksUri, { signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(`Could not fetch the realm keys from ${jwksUri} (HTTP ${res.status}).`);
  const { keys } = await res.json();
  cache.set(jwksUri, { keys: Array.isArray(keys) ? keys : [], fetchedAt: Date.now() });
  return cache.get(jwksUri).keys;
}

// Verifies a decoded JWT's signature with the matching key from jwksUri. Returns a description of
// the key used; throws with a readable message otherwise.
export async function verifyJwtSignature(jwt, jwksUri) {
  const { alg, kid } = jwt.header;
  if (!Object.hasOwn(ALGORITHMS, alg)) throw new Error(`Unsupported or unsigned algorithm "${alg}".`);
  const pick = (keys) => keys.filter((k) => k.use !== 'enc' && (!kid || k.kid === kid) && (!k.alg || k.alg === alg));
  let candidates = pick(await loadJwks(jwksUri));
  if (!candidates.length) candidates = pick(await loadJwks(jwksUri, { force: true }));
  if (!candidates.length) throw new Error(`The realm publishes no ${alg} key with id ${kid ?? '(none)'} at ${jwksUri}.`);
  const [hash, options] = ALGORITHMS[alg];
  for (const jwk of candidates) {
    let key;
    try { key = crypto.createPublicKey({ key: jwk, format: 'jwk' }); } catch { continue; }
    if (crypto.verify(hash, Buffer.from(jwt.signingInput), { key, ...options }, jwt.signature)) return `${alg}, key ${jwk.kid ?? '(no id)'}`;
  }
  throw new Error(`The ${alg} signature does not verify with the realm key ${kid ?? ''}.`.replace(' .', '.'));
}

// OIDC at_hash / c_hash: the left half of the token's hash with the ID token's algorithm, base64url.
export function halfHash(value, alg) {
  const bits = { 256: 'sha256', 384: 'sha384', 512: 'sha512' }[(alg || '').slice(2)];
  if (!bits) return null;
  const digest = crypto.createHash(bits).update(value).digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}
