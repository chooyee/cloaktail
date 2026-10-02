import crypto from 'node:crypto';
import fs from 'node:fs';
import selfsigned from 'selfsigned';
import { config } from './config.js';
import { getSpKeyRow, listSpKeyRows, putSpKeyRow, promotePendingSpKey, deleteSpKeyRow, listProfileRows } from './db.js';
import { encrypt, decrypt } from './lib/secretBox.js';

// The portal's SAML signing key pairs, one per Keycloak profile: on a profile's domains CloakTail
// signs its AuthnRequests and LogoutRequests with that profile's key, and its Keycloak verifies them
// with the certificate (imported into the portal SAML client, with "Client signature required" on).
// Stored in the database, the private key encrypted.
//
// Rotation without surprises: while a profile has an active key, a newly generated or imported key
// is "pending" until an administrator has imported its certificate into Keycloak and activates it.

export const KEY_SIZES = [2048, 3072, 4096];
export const VALIDITY_YEARS = [1, 2, 3, 5, 10];

const listeners = [];
export const onSpKeyChange = (fn) => listeners.push(fn);
async function notify() {
  for (const fn of listeners) {
    try { await fn(); } catch (err) { console.error('Applying the new signing key failed:', err); }
  }
}

// ---------- reading ----------

function describe(row) {
  const x509 = new crypto.X509Certificate(row.certificate);
  const validTo = new Date(x509.validTo);
  return {
    status: row.status,
    certificate: row.certificate,
    subject: x509.subject.replace(/\n/g, ', '),
    fingerprint: x509.fingerprint256,
    keySize: x509.publicKey.asymmetricKeyDetails?.modulusLength ?? null,
    validFrom: new Date(x509.validFrom).toISOString().slice(0, 10),
    validTo: validTo.toISOString().slice(0, 10),
    daysLeft: Math.floor((validTo - Date.now()) / 86_400_000),
    createdBy: row.created_by,
    createdAt: row.created_at,
    activatedAt: row.activated_at,
  };
}

// For the admin pages: public details only, never the private key.
export async function getSpKeysView(profileId) {
  const [active, pending] = await Promise.all([getSpKeyRow(profileId, 'active'), getSpKeyRow(profileId, 'pending')]);
  return { active: active && describe(active), pending: pending && describe(pending) };
}

// Every profile's keys: profile id -> { active, pending } as in getSpKeysView.
export async function listSpKeysViews() {
  const views = new Map();
  for (const row of await listSpKeyRows()) {
    views.set(row.profile_id, { active: null, pending: null, ...views.get(row.profile_id), [row.status]: describe(row) });
  }
  return views;
}

const warnedUnreadable = new Set();

// The active key pairs for signing: profile id -> { certificate, privateKey }. A profile without
// one (or whose key can't be decrypted) is missing.
export async function getActiveSpKeys() {
  const keys = new Map();
  for (const row of await listSpKeyRows()) {
    if (row.status !== 'active') continue;
    try {
      keys.set(row.profile_id, { certificate: row.certificate, privateKey: decrypt(row.private_key) });
    } catch {
      if (!warnedUnreadable.has(row.profile_id)) {
        console.warn(`The SAML signing key of Keycloak profile #${row.profile_id} can't be decrypted (did SETTINGS_KEY or SESSION_SECRET change?). Generate or import a new one in the admin console.`);
        warnedUnreadable.add(row.profile_id);
      }
    }
  }
  return keys;
}

// ---------- validation ----------

// Checks a PEM certificate and unencrypted PEM private key belong together and are usable for
// SAML signing (RSA, 2048 bits or more). Returns { error } or the normalised PEMs.
export function checkKeyPair(certificatePem, privateKeyPem) {
  let x509;
  let key;
  try { x509 = new crypto.X509Certificate(certificatePem); } catch { return { error: 'The certificate is not a valid PEM certificate.', field: 'certificate' }; }
  try {
    key = crypto.createPrivateKey(privateKeyPem);
  } catch {
    return { error: 'The private key is not a valid, unencrypted PEM private key.', field: 'privateKey' };
  }
  if (key.asymmetricKeyType !== 'rsa') return { error: 'Use an RSA key; SAML signing here uses RSA-SHA256.', field: 'privateKey' };
  if (key.asymmetricKeyDetails.modulusLength < 2048) return { error: 'Use an RSA key of at least 2048 bits.', field: 'privateKey' };
  if (!x509.checkPrivateKey(key)) return { error: 'The private key does not belong to this certificate.', field: 'privateKey' };
  if (new Date(x509.validTo) < new Date()) return { error: `The certificate expired on ${x509.validTo}.`, field: 'certificate' };
  return {
    error: null,
    certificate: x509.toString(),
    privateKey: key.export({ type: 'pkcs8', format: 'pem' }),
  };
}

// ---------- changing ----------

// A new key becomes active straight away when the profile has none yet; otherwise it waits as pending.
async function store(profileId, { certificate, privateKey }, by) {
  const status = (await getSpKeyRow(profileId, 'active')) ? 'pending' : 'active';
  await putSpKeyRow(profileId, status, { certificate, privateKey: encrypt(privateKey), by });
  if (status === 'active') await notify();
  return status;
}

export async function generateSpKey(profile, { commonName, keySize, years }, by) {
  const notAfterDate = new Date();
  notAfterDate.setFullYear(notAfterDate.getFullYear() + years);
  const pems = await selfsigned.generate([{ name: 'commonName', value: commonName }], { keySize, algorithm: 'sha256', notAfterDate });
  const status = await store(profile.id, { certificate: pems.cert, privateKey: pems.private }, by);
  console.log(`[admin] ${by} generated a ${keySize}-bit SAML signing key for profile "${profile.name}" (${status})`);
  return status;
}

export async function importSpKey(profile, certificatePem, privateKeyPem, by) {
  const checked = checkKeyPair(certificatePem, privateKeyPem);
  if (checked.error) return checked;
  const status = await store(profile.id, checked, by);
  console.log(`[admin] ${by} imported a SAML signing key for profile "${profile.name}" (${status})`);
  return { error: null, status };
}

export async function activatePendingSpKey(profile, by) {
  if (!(await promotePendingSpKey(profile.id))) return false;
  console.log(`[admin] ${by} activated the pending SAML signing key of profile "${profile.name}"`);
  await notify();
  return true;
}

export async function discardPendingSpKey(profile, by) {
  await deleteSpKeyRow(profile.id, 'pending');
  console.log(`[admin] ${by} discarded the pending SAML signing key of profile "${profile.name}"`);
}

// ---------- one-time migration from certs/*.pem ----------

// Before keys were stored in the database they were files (npm run gen:sp-cert). On the first
// start without any stored key, an existing pair becomes the active key of every profile.
async function migrateKeyFiles() {
  const { spKeyFile, spCertFile } = config.saml;
  if (!fs.existsSync(spKeyFile) || !fs.existsSync(spCertFile)) return;
  if ((await listSpKeyRows()).length) return;
  const profiles = await listProfileRows();
  if (!profiles.length) return;
  const checked = checkKeyPair(fs.readFileSync(spCertFile, 'utf8'), fs.readFileSync(spKeyFile, 'utf8'));
  if (checked.error) {
    console.warn(`Not moving ${spKeyFile} into the database: ${checked.error} Generate a key in the admin console instead.`);
    return;
  }
  const privateKey = encrypt(checked.privateKey);
  for (const p of profiles) await putSpKeyRow(p.id, 'active', { certificate: checked.certificate, privateKey, by: 'migration' });
  console.log(`Moved the SAML signing key from ${spKeyFile} and ${spCertFile} into the database, for all ${profiles.length} Keycloak profiles. They are no longer read; delete them once you have a backup.`);
}

await migrateKeyFiles();
