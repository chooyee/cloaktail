import { config } from '../config.js';

// Minimal Keycloak Admin REST API client, one instance per realm.
// Authenticates with the client-credentials grant of a confidential OIDC client in that realm
// whose service account holds the needed realm-management roles.

export class KeycloakError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

// Client-credentials grant; returns the token response ({ access_token, expires_in, ... }).
export async function requestAdminToken({ configured, realmUrl, adminClientId, adminClientSecret }, secretLabel) {
  if (!configured) {
    throw new KeycloakError('Keycloak is not configured yet. An administrator must activate a Keycloak profile in the admin console.', 503);
  }
  if (!adminClientSecret) {
    throw new KeycloakError(`The ${secretLabel} is not set in the Keycloak profile; this feature is unavailable.`, 503);
  }
  const res = await fetch(`${realmUrl}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: adminClientId,
      client_secret: adminClientSecret,
    }),
  });
  if (!res.ok) {
    throw new KeycloakError(`Could not get Keycloak admin token for ${realmUrl} (${res.status}): ${await res.text()}`, 502);
  }
  return res.json();
}

// getSettings returns the realm's current settings (config.keycloak or config.sandbox), read on
// every call because the active Keycloak profile can change at runtime.
export function createAdminClient(getSettings, secretLabel) {
  let cachedToken = null; // { value, expiresAt, for }

  async function getToken() {
    const settings = getSettings();
    // A token is only reused for the realm and credentials it was issued for.
    const issuedFor = `${settings.realmUrl}\n${settings.adminClientId}\n${settings.adminClientSecret}`;
    if (cachedToken?.for === issuedFor && cachedToken.expiresAt > Date.now() + 10_000) return cachedToken.value;
    const body = await requestAdminToken(settings, secretLabel);
    cachedToken = { value: body.access_token, expiresAt: Date.now() + body.expires_in * 1000, for: issuedFor };
    return cachedToken.value;
  }

  async function request(method, path, { query, body, rawBody, contentType } = {}) {
    const url = new URL(getSettings().adminApiUrl + path);
    for (const [k, v] of Object.entries(query || {})) {
      if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
    }
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${await getToken()}`,
        ...(body || rawBody ? { 'Content-Type': contentType || 'application/json' } : {}),
      },
      body: rawBody ?? (body ? JSON.stringify(body) : undefined),
    });
    if (res.status === 401) cachedToken = null;
    if (!res.ok) {
      let message = `Keycloak request failed (${res.status})`;
      try {
        const err = await res.json();
        message = err.errorMessage || err.error_description || err.error || message;
      } catch { /* non-JSON body */ }
      throw new KeycloakError(message, res.status);
    }
    if (res.status === 201) return res.headers.get('Location')?.split('/').pop();
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }

  const id = (value) => encodeURIComponent(value);

  return {
    // ---------- users ----------
    listUsers: ({ search, first = 0, max = 20 }) =>
      request('GET', '/users', { query: { search, first, max, briefRepresentation: true } }),

    countUsers: ({ search }) => request('GET', '/users/count', { query: { search } }),

    getUser: (userId) => request('GET', `/users/${id(userId)}`),

    createUser: ({ username, email, firstName, lastName, enabled = true, emailVerified = false, password, temporary, requiredActions }) =>
      request('POST', '/users', {
        body: {
          username,
          email: email || undefined,
          firstName: firstName || undefined,
          lastName: lastName || undefined,
          enabled,
          emailVerified,
          requiredActions,
          credentials: password ? [{ type: 'password', value: password, temporary: Boolean(temporary) }] : undefined,
        },
      }),

    // Merge into the full representation so fields we don't manage (attributes, etc.) are kept.
    updateUser: async (userId, changes) => {
      const current = await request('GET', `/users/${id(userId)}`);
      return request('PUT', `/users/${id(userId)}`, { body: { ...current, ...changes } });
    },

    resetPassword: (userId, password, temporary) =>
      request('PUT', `/users/${id(userId)}/reset-password`, {
        body: { type: 'password', value: password, temporary },
      }),

    logoutUser: (userId) => request('POST', `/users/${id(userId)}/logout`),

    deleteUser: (userId) => request('DELETE', `/users/${id(userId)}`),

    // ---------- clients ----------
    listClients: ({ first = 0, max = 20 } = {}) => request('GET', '/clients', { query: { first, max } }),

    createClient: (rep) => request('POST', '/clients', { body: rep }),

    getClient: (clientUuid) => request('GET', `/clients/${id(clientUuid)}`),

    // PUT does not touch protocol mappers; those are managed through their own endpoints.
    updateClient: async (clientUuid, changes) => {
      const current = await request('GET', `/clients/${id(clientUuid)}`);
      const { protocolMappers, ...rest } = { ...current, ...changes, attributes: { ...current.attributes, ...changes.attributes } };
      return request('PUT', `/clients/${id(clientUuid)}`, { body: rest });
    },

    deleteClient: (clientUuid) => request('DELETE', `/clients/${id(clientUuid)}`),

    listProtocolMappers: (clientUuid) => request('GET', `/clients/${id(clientUuid)}/protocol-mappers/models`),

    addProtocolMapper: (clientUuid, mapper) =>
      request('POST', `/clients/${id(clientUuid)}/protocol-mappers/models`, { body: mapper }),

    deleteProtocolMapper: (clientUuid, mapperId) =>
      request('DELETE', `/clients/${id(clientUuid)}/protocol-mappers/models/${id(mapperId)}`),

    // Converts SAML SP metadata XML into a Keycloak client representation (nothing is saved).
    convertClientDescription: (xml) =>
      request('POST', '/client-description-converter', { rawBody: xml, contentType: 'text/plain' }),
  };
}

// Portal realm: developer and admin accounts.
export const keycloakAdmin = createAdminClient(() => config.keycloak, 'portal service account client secret');

// Sandbox realm: developers' SAML clients and test users.
export const sandboxAdmin = createAdminClient(() => config.sandbox, 'sandbox service account client secret');
