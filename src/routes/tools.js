import crypto from 'node:crypto';
import express from 'express';
import selfsigned from 'selfsigned';
import { requirePermission } from '../middleware.js';

// Developer tools. The certificate generator creates a key pair and self-signed X.509 certificate
// for a developer's SAML SP (request signing / assertion encryption). Nothing is stored: the key is
// returned once, with no-store caching, and the page tells developers it is for sandbox testing only.
export const toolsRouter = express.Router();
toolsRouter.use(requirePermission('apps.own'));

const KEY_SIZES = [2048, 3072, 4096];
const VALIDITY_YEARS = [1, 2, 3, 5];
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

const defaults = { commonName: '', organization: '', keySize: 2048, years: 2 };
const render = (res, locals) =>
  res.render('pages/tools/certificate', {
    title: 'Certificate generator', KEY_SIZES, VALIDITY_YEARS, values: defaults, error: null, result: null, ...locals,
  });

toolsRouter.get('/certificate', (req, res) => render(res, {}));

toolsRouter.post('/certificate', async (req, res) => {
  const values = {
    commonName: (req.body.commonName || '').trim(),
    organization: (req.body.organization || '').trim(),
    keySize: Number(req.body.keySize),
    years: Number(req.body.years),
  };
  const fail = (error) => render(res, { values, error });

  // Restricted character set: the CN is also echoed into a copy-paste OpenSSL command.
  const SAFE = /^[A-Za-z0-9 ._:/@-]*$/;
  if (!values.commonName || values.commonName.length > 64 || !SAFE.test(values.commonName)) {
    return fail('Common name is required: up to 64 characters (letters, digits, space . - _ : / @), e.g. myapp.example.com.');
  }
  if (values.organization.length > 64 || !SAFE.test(values.organization)) {
    return fail('Organization: up to 64 characters (letters, digits, space . - _ : / @).');
  }
  if (!KEY_SIZES.includes(values.keySize)) return fail('Choose a key size.');
  if (!VALIDITY_YEARS.includes(values.years)) return fail('Choose a validity period.');
  if (rateLimited(req.user.username)) return fail('You have generated many certificates recently. Try again in 10 minutes.');

  const notAfterDate = new Date();
  notAfterDate.setFullYear(notAfterDate.getFullYear() + values.years);
  const attrs = [{ name: 'commonName', value: values.commonName }];
  if (values.organization) attrs.push({ name: 'organizationName', value: values.organization });

  const pems = await selfsigned.generate(attrs, { keySize: values.keySize, algorithm: 'sha256', notAfterDate });
  const cert = new crypto.X509Certificate(pems.cert);

  res.set('Cache-Control', 'no-store');
  render(res, {
    values,
    result: {
      privateKey: pems.private,
      certificate: pems.cert,
      subject: cert.subject.replace(/\n/g, ', '),
      validTo: cert.validTo,
      fingerprint: cert.fingerprint256,
      fileBase: values.commonName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'saml-sp',
    },
  });
});
