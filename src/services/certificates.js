import crypto from 'node:crypto';
import selfsigned from 'selfsigned';
import { ServiceError, invalid } from './errors.js';

// The certificate generator: a key pair and self-signed X.509 certificate for a developer's SAML SP
// (request signing / assertion encryption). Nothing is stored; the key is returned once.
// Used by the HTML page (routes/tools.js) and the REST API (routes/api.js).

export const KEY_SIZES = [2048, 3072, 4096];
export const VALIDITY_YEARS = [1, 2, 3, 5];
export const CERTIFICATE_DEFAULTS = { commonName: '', organization: '', keySize: 2048, years: 2 };

const WINDOW_MS = 10 * 60 * 1000;
const MAX_PER_WINDOW = 10; // key generation is CPU-heavy; limit per user
const recent = new Map();

function rateLimited(username) {
  const now = Date.now();
  const hits = (recent.get(username) || []).filter((t) => now - t < WINDOW_MS);
  hits.push(now);
  recent.set(username, hits);
  return hits.length > MAX_PER_WINDOW;
}

// Restricted character set: the CN is also echoed into a copy-paste OpenSSL command.
const SAFE = /^[A-Za-z0-9 ._:/@-]*$/;

// values: { commonName, organization, keySize, years }. Returns the key, certificate and its details.
export async function generateCertificate(username, values) {
  if (!values.commonName || values.commonName.length > 64 || !SAFE.test(values.commonName)) {
    throw invalid('Common name is required: up to 64 characters (letters, digits, space . - _ : / @), e.g. myapp.example.com.', { field: 'commonName' });
  }
  if (values.organization.length > 64 || !SAFE.test(values.organization)) {
    throw invalid('Organization: up to 64 characters (letters, digits, space . - _ : / @).', { field: 'organization' });
  }
  if (!KEY_SIZES.includes(values.keySize)) throw invalid('Choose a key size.', { field: 'keySize' });
  if (!VALIDITY_YEARS.includes(values.years)) throw invalid('Choose a validity period.', { field: 'years' });
  if (rateLimited(username)) throw new ServiceError(429, 'rate_limited', 'You have generated many certificates recently. Try again in 10 minutes.');

  const notAfterDate = new Date();
  notAfterDate.setFullYear(notAfterDate.getFullYear() + values.years);
  const attrs = [{ name: 'commonName', value: values.commonName }];
  if (values.organization) attrs.push({ name: 'organizationName', value: values.organization });

  const pems = await selfsigned.generate(attrs, { keySize: values.keySize, algorithm: 'sha256', notAfterDate });
  const cert = new crypto.X509Certificate(pems.cert);
  return {
    privateKey: pems.private,
    certificate: pems.cert,
    subject: cert.subject.replace(/\n/g, ', '),
    validTo: cert.validTo,
    fingerprint: cert.fingerprint256,
    fileBase: values.commonName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'saml-sp',
  };
}
