import express from 'express';
import { KEY_SIZES, VALIDITY_YEARS, CERTIFICATE_DEFAULTS, generateCertificate } from '../services/certificates.js';
import { ServiceError } from '../services/errors.js';
import { requirePermission } from '../middleware.js';

// Developer tools. The certificate generator creates a key pair and self-signed X.509 certificate
// for a developer's SAML SP (request signing / assertion encryption). Nothing is stored: the key is
// returned once, with no-store caching, and the page tells developers it is for sandbox testing only.
export const toolsRouter = express.Router();
toolsRouter.use(requirePermission('apps.own'));

// Public tools, open without signing in. The SAML and JWT decoders run entirely in the browser, so
// pasted messages and tokens (which can hold personal data or grant access) never reach the server.
export const publicToolsRouter = express.Router();
publicToolsRouter.get('/decode', (req, res) => res.render('pages/tools/decode', {
  title: 'SAML decoder',
  description: 'Decode a SAMLRequest or SAMLResponse into readable XML: base64 for the HTTP-POST binding, base64 then DEFLATE for the Redirect binding. Runs in your browser.',
}));
publicToolsRouter.get('/decode/jwt', (req, res) => res.render('pages/tools/jwt', {
  title: 'JWT decoder',
  description: 'Decode an OpenID Connect ID token or access token (JWT): header, claims and readable times, and verify its signature with a JWKS, public key or secret. Runs in your browser.',
}));

const render = (res, locals) =>
  res.render('pages/tools/certificate', {
    title: 'Certificate generator', KEY_SIZES, VALIDITY_YEARS, values: CERTIFICATE_DEFAULTS, error: null, result: null, ...locals,
  });

toolsRouter.get('/certificate', (req, res) => render(res, {}));

toolsRouter.post('/certificate', async (req, res) => {
  const values = {
    commonName: (req.body.commonName || '').trim(),
    organization: (req.body.organization || '').trim(),
    keySize: Number(req.body.keySize),
    years: Number(req.body.years),
  };
  let result;
  try {
    result = await generateCertificate(req.user.username, values);
  } catch (err) {
    if (err instanceof ServiceError) return render(res, { values, error: err.message });
    throw err;
  }
  res.set('Cache-Control', 'no-store');
  render(res, { values, result });
});
