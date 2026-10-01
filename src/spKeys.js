import crypto from 'node:crypto';
import fs from 'node:fs';
import selfsigned from 'selfsigned';
import { config } from './config.js';
import { getSpKeyRow, putSpKeyRow, promotePendingSpKey, deleteSpKeyRow } from './db.js';
import { encrypt, decrypt } from './lib/secretBox.js';

// The portal's SAML signing key pair: CloakTail signs its AuthnRequests and LogoutRequests with it,
// and Keycloak verifies them with the certificate (imported into the portal SAML client, with
// "Client signature required" on). Stored in the database, the private key encrypted.
//
// Rotation without surprises: while a key is active, a newly generated or imported key is
// "pending" until an administrator has imported its certificate into Keycloak and activates it.

export const KEY_SIZES = [2048, 3072, 4096];
export const VALIDITY_YEARS = [1, 2, 3, 5, 10];

const listeners = [];
export const onSpKeyChange = (fn) => listeners.push(fn);
function notify() {
  for (const fn of listeners) {
    try { fn(); } catch (err) { console.error('Applying the new signing key failed:', err); }
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

// For the admin page: public details only, never the private key.
export function getSpKeysView() {
  const active = getSpKeyRow('active');
  const pending = getSpKeyRow('pending');
  return { active: active && describe(active), pending: pending && describe(pending) };
}

let warnedUnreadable = false;

// The active key pair for signing, or null if none (or it can't be decrypted).
export function getActiveSpKey() {
  const row = getSpKeyRow('active');
  if (!row) return null;
  try {
    return { certificate: row.certificate, privateKey: decrypt(row.private_key) };
  } catch {
    if (!warnedUnreadable) {
      console.warn('The SAML signing key can\'t be decrypted (did SETTINGS_KEY or SESSION_SECRET change?). Generate or import a new one in the admin console.');
      warnedUnreadable = true;
    }
    return null;
  }
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

// A new key becomes active straight away when there is none yet; otherwise it waits as pending.
function store({ certificate, privateKey }, by) {
  const status = getSpKeyRow('active') ? 'pending' : 'active';
  putSpKeyRow(status, { certificate, privateKey: encrypt(privateKey), by });
  if (status === 'active') notify();
  return status;
}

export async function generateSpKey({ commonName, keySize, years }, by) {
  const notAfterDate = new Date();
  notAfterDate.setFullYear(notAfterDate.getFullYear() + years);
  const pems = await selfsigned.generate([{ name: 'commonName', value: commonName }], { keySize, algorithm: 'sha256', notAfterDate });
  const status = store({ certificate: pems.cert, privateKey: pems.private }, by);
  console.log(`[admin] ${by} generated a ${keySize}-bit SAML signing key (${status})`);
  return status;
}

export function importSpKey(certificatePem, privateKeyPem, by) {
  const checked = checkKeyPair(certificatePem, privateKeyPem);
  if (checked.error) return checked;
  const status = store(checked, by);
  console.log(`[admin] ${by} imported a SAML signing key (${status})`);
  return { error: null, status };
}

export function activatePendingSpKey(by) {
  if (!promotePendingSpKey()) return false;
  console.log(`[admin] ${by} activated the pending SAML signing key`);
  notify();
  return true;
}

export function discardPendingSpKey(by) {
  deleteSpKeyRow('pending');
  console.log(`[admin] ${by} discarded the pending SAML signing key`);
}

// ---------- one-time migration from certs/*.pem ----------

// Before keys were stored in the database they were files (npm run gen:sp-cert). On the first
// start without a stored key, an existing pair becomes the active key.
function migrateKeyFiles() {
  if (getSpKeyRow('active')) return;
  const { spKeyFile, spCertFile } = config.saml;
  if (!fs.existsSync(spKeyFile) || !fs.existsSync(spCertFile)) return;
  const checked = checkKeyPair(fs.readFileSync(spCertFile, 'utf8'), fs.readFileSync(spKeyFile, 'utf8'));
  if (checked.error) {
    console.warn(`Not moving ${spKeyFile} into the database: ${checked.error} Generate a key in the admin console instead.`);
    return;
  }
  putSpKeyRow('active', { certificate: checked.certificate, privateKey: encrypt(checked.privateKey), by: 'migration' });
  console.log(`Moved the SAML signing key from ${spKeyFile} and ${spCertFile} into the database. They are no longer read; delete them once you have a backup.`);
}

migrateKeyFiles();
