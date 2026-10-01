import crypto from 'node:crypto';
import { config } from '../config.js';

// Encryption at rest for secrets stored in the database (Keycloak client secrets, the portal's
// SAML signing key). AES-256-GCM with a key derived from SETTINGS_KEY (or SESSION_SECRET);
// changing that variable makes stored secrets unreadable.

const key = Buffer.from(crypto.hkdfSync('sha256', config.settingsKey, Buffer.alloc(0), 'cloaktail settings v1', 32));

export function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return ['enc', 'v1', iv.toString('base64'), cipher.getAuthTag().toString('base64'), data.toString('base64')].join(':');
}

export function decrypt(stored) {
  const [prefix, version, iv, tag, data] = stored.split(':');
  if (prefix !== 'enc' || version !== 'v1') throw new Error('unknown format');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]).toString('utf8');
}
