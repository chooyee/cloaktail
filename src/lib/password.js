import crypto from 'node:crypto';
import { promisify } from 'node:util';

// Password hashing for local admin accounts: scrypt with a per-password random salt.
// Stored as scrypt$N$r$p$salt$hash so the cost can be raised later without breaking old hashes.

const scrypt = promisify(crypto.scrypt);
const COST = { N: 16384, r: 8, p: 1 };
const KEY_LENGTH = 64;
const MAX_LENGTH = 256;

const derive = (password, salt, length, { N, r, p }) =>
  scrypt(password.normalize('NFKC'), salt, length, { N, r, p, maxmem: 256 * N * r });

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await derive(password, salt, KEY_LENGTH, COST);
  return ['scrypt', COST.N, COST.r, COST.p, salt.toString('base64'), hash.toString('base64')].join('$');
}

export async function verifyPassword(password, stored) {
  const [alg, N, r, p, salt, hash] = String(stored).split('$');
  if (alg !== 'scrypt' || !hash || password.length > MAX_LENGTH) return false;
  const expected = Buffer.from(hash, 'base64');
  const actual = await derive(password, Buffer.from(salt, 'base64'), expected.length, { N: +N, r: +r, p: +p });
  return crypto.timingSafeEqual(actual, expected);
}

// Checked when the username doesn't exist, so response time doesn't reveal which usernames do.
export const DUMMY_HASH = await hashPassword(crypto.randomBytes(16).toString('hex'));

export function passwordProblem(password, username) {
  if (password.length < 12) return 'Use at least 12 characters.';
  if (password.length > MAX_LENGTH) return `Use at most ${MAX_LENGTH} characters.`;
  if (username && password.toLowerCase().includes(username.toLowerCase())) return 'The password must not contain the username.';
  return null;
}

// Random temporary password for accounts created from the command line.
export const temporaryPassword = () => crypto.randomBytes(15).toString('base64url');
