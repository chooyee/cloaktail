import { config } from '../config.js';
import { sandboxAdmin } from './keycloakAdmin.js';

// Translates between the portal's OIDC "application" form and a Keycloak OpenID Connect client
// representation. Claims come from the realm's default client scopes (profile, email, roles...).

export const CLIENT_TYPES = {
  confidential: 'Confidential (server-side app with a client secret)',
  public: 'Public (single-page or native app, no secret)',
};

const MAX_URIS = 20;

export const defaultOidcValues = () => ({
  name: '',
  clientId: '',
  clientType: 'confidential',
  redirectUris: [],
  postLogoutRedirectUris: [],
  webOrigins: [],
  homeUrl: '',
  requirePkce: true,
  serviceAccount: false,
});

const str = (v) => (typeof v === 'string' ? v.trim() : '');
const lines = (v) => [...new Set(str(v).split(/[\s,]+/).filter(Boolean))];

export function parseOidcForm(body) {
  return {
    name: str(body.name),
    clientId: str(body.clientId),
    clientType: str(body.clientType),
    redirectUris: lines(body.redirectUris),
    postLogoutRedirectUris: lines(body.postLogoutRedirectUris),
    webOrigins: lines(body.webOrigins),
    homeUrl: str(body.homeUrl),
    requirePkce: body.requirePkce === 'on',
    serviceAccount: body.serviceAccount === 'on',
  };
}

// A redirect URI: an absolute http(s) URL. Keycloak also accepts a trailing * as a wildcard; only
// allow it after a path separator (https://app.example.com* would match app.example.com.evil.test).
function checkRedirectUri(value, label) {
  const wildcard = value.endsWith('*');
  const base = wildcard ? value.slice(0, -1) : value;
  let url;
  try { url = new URL(base); } catch { return `${label}: ${value} is not a full URL, e.g. https://myapp.example.com/callback`; }
  if (!['http:', 'https:'].includes(url.protocol)) return `${label}: ${value} must start with http:// or https://`;
  if (base.includes('*') || (wildcard && !/^https?:\/\/[^/]+\/(.*\/)?$/.test(base))) {
    return `${label}: ${value} may only end in /* as a wildcard.`;
  }
  if (url.hash) return `${label}: ${value} cannot contain a # fragment.`;
  return null;
}

// Validates and normalizes in place. Returns an error message or null.
export function validateOidcApp(values, { isNew }) {
  if (!values.name || values.name.length > 80) return 'Application name is required (max 80 characters).';
  if (isNew) {
    if (!values.clientId || values.clientId.length > 255 || !/^[\x21-\x7e]+$/.test(values.clientId)) {
      return 'Client ID is required: up to 255 printable characters, no spaces (for example my-billing-app).';
    }
  }
  if (!(values.clientType in CLIENT_TYPES)) return 'Choose a client type.';
  if (!values.redirectUris.length) return 'Enter at least one redirect URI: where Keycloak sends the user back with the authorization code.';
  for (const [list, label] of [[values.redirectUris, 'Redirect URI'], [values.postLogoutRedirectUris, 'Post-logout redirect URI']]) {
    if (list.length > MAX_URIS) return `Use at most ${MAX_URIS} entries for ${label.toLowerCase()}s.`;
    for (const uri of list) {
      const problem = checkRedirectUri(uri, label);
      if (problem) return problem;
    }
  }
  if (values.webOrigins.length > MAX_URIS) return `Use at most ${MAX_URIS} web origins.`;
  for (const origin of values.webOrigins) {
    if (origin === '+') continue;
    let url;
    try { url = new URL(origin); } catch { return `Web origin ${origin} is not an origin, e.g. https://myapp.example.com (or + for the redirect URIs' origins).`; }
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== origin.replace(/\/$/, '')) {
      return `Web origin ${origin}: enter only the scheme and host (and port), e.g. https://myapp.example.com.`;
    }
  }
  values.webOrigins = values.webOrigins.map((o) => o.replace(/\/$/, ''));
  if (values.homeUrl) {
    try {
      if (!['http:', 'https:'].includes(new URL(values.homeUrl).protocol)) throw new Error();
    } catch { return 'Home URL must be a full http:// or https:// URL.'; }
  }
  if (values.clientType === 'public') values.serviceAccount = false;
  return null;
}

// The portal's own test redirect URIs are added to every client, on every domain of the profile,
// so "Test connection" works; they are hidden from the form.
const isTestRedirect = (uri) => config.sandbox.testOidcRedirectUris.includes(uri);

function toClientRep(values, owner) {
  const isPublic = values.clientType === 'public';
  return {
    name: values.name,
    description: `Developer portal application owned by ${owner}`,
    protocol: 'openid-connect',
    enabled: true,
    publicClient: isPublic,
    clientAuthenticatorType: 'client-secret',
    standardFlowEnabled: true,
    implicitFlowEnabled: false,
    directAccessGrantsEnabled: false,
    serviceAccountsEnabled: !isPublic && values.serviceAccount,
    frontchannelLogout: true,
    baseUrl: values.homeUrl || '',
    redirectUris: [...new Set([...values.redirectUris, ...config.sandbox.testOidcRedirectUris])],
    webOrigins: values.webOrigins,
    attributes: {
      'pkce.code.challenge.method': values.requirePkce ? 'S256' : '',
      'post.logout.redirect.uris': values.postLogoutRedirectUris.join('##'),
    },
  };
}

export function fromOidcClientRep(rep) {
  const a = rep.attributes || {};
  return {
    name: rep.name || rep.clientId,
    clientId: rep.clientId,
    clientType: rep.publicClient ? 'public' : 'confidential',
    redirectUris: (rep.redirectUris || []).filter((u) => !isTestRedirect(u)),
    postLogoutRedirectUris: (a['post.logout.redirect.uris'] || '').split('##').filter(Boolean),
    webOrigins: rep.webOrigins || [],
    homeUrl: rep.baseUrl || '',
    requirePkce: a['pkce.code.challenge.method'] === 'S256',
    serviceAccount: Boolean(rep.serviceAccountsEnabled),
  };
}

// ---------- Keycloak operations ----------

export async function createOidcClient(values, owner) {
  return sandboxAdmin.createClient({ ...toClientRep(values, owner), clientId: values.clientId });
}

export async function updateOidcClient(kcId, values, owner) {
  await sandboxAdmin.updateClient(kcId, toClientRep(values, owner));
}

export async function loadOidcClient(kcId) {
  const rep = await sandboxAdmin.getClient(kcId);
  if (rep.protocol !== 'openid-connect') throw new Error(`Keycloak client ${rep.clientId} is not an OpenID Connect client.`);
  return { rep, values: fromOidcClientRep(rep) };
}

// The client secret of a confidential client (null for a public one).
export async function getOidcClientSecret(kcId) {
  return (await sandboxAdmin.getClientSecret(kcId))?.value ?? null;
}

export async function regenerateOidcClientSecret(kcId) {
  return (await sandboxAdmin.regenerateClientSecret(kcId))?.value ?? null;
}
