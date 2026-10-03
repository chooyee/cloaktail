import express from 'express';
import { SCOPES, EXPIRY_DAYS, MAX_CREDENTIALS, createApiCredential, parseScopes } from '../lib/apiCredentials.js';
import { listApiCredentials, getApiCredential, deleteApiCredential } from '../db.js';
import { ServiceError } from '../services/errors.js';
import { requirePermission, sendError } from '../middleware.js';

// Developers' REST API credentials (lib/apiCredentials.js): create one, see its secret once, revoke it.
export const apiCredentialsRouter = express.Router();
apiCredentialsRouter.use(requirePermission('apps.own'));

const DEFAULTS = { name: '', scopes: Object.keys(SCOPES), expiryDays: '90' };

async function renderPage(req, res, locals = {}) {
  const credentials = (await listApiCredentials(req.user.username)).map((c) => ({ ...c, scopeList: parseScopes(c.scopes) }));
  if (locals.created) res.set('Cache-Control', 'no-store');
  res.status(locals.error ? 422 : 200).render('pages/api-credentials', {
    title: 'API credentials',
    credentials,
    SCOPES,
    EXPIRY_DAYS,
    max: MAX_CREDENTIALS,
    apiUrl: `${req.siteUrl}/api/v1`,
    siteUrl: req.siteUrl,
    values: DEFAULTS,
    error: null,
    message: null,
    created: null,
    ...locals,
  });
}

apiCredentialsRouter.get('/', (req, res) => renderPage(req, res));

apiCredentialsRouter.post('/', async (req, res) => {
  const values = {
    name: (req.body.name || '').trim(),
    scopes: [].concat(req.body.scopes ?? []),
    expiryDays: String(req.body.expiryDays ?? ''),
  };
  let created;
  try {
    created = await createApiCredential(req.user.username, values);
  } catch (err) {
    if (err instanceof ServiceError) return renderPage(req, res, { values, error: err.message });
    throw err;
  }
  renderPage(req, res, { created: { ...created, name: values.name } });
});

apiCredentialsRouter.post('/:id/delete', async (req, res) => {
  const row = await getApiCredential(Number(req.params.id));
  if (!row || row.owner !== req.user.username) return sendError(req, res, 404, 'API credential not found.');
  await deleteApiCredential(row.id);
  renderPage(req, res, { message: `Credential “${row.name}” revoked. Tokens issued with it stopped working.` });
});
