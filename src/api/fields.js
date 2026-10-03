import {
  NAME_ID_FORMATS, USER_ATTRIBUTES, ATTRIBUTE_NAME_FORMATS, ENCRYPTION_KEY_ALGORITHMS, defaultAppValues,
} from '../lib/samlClients.js';
import { CLIENT_TYPES, defaultOidcValues } from '../lib/oidcClients.js';
import { invalid } from '../services/errors.js';

// The REST API's JSON fields (snake_case) and the portal's form values (camelCase) they map to.
// One definition per field drives reading request bodies, writing responses and the OpenAPI schemas
// (api/openapi.js), so the three can't disagree. Values are then checked by the same validators as
// the HTML forms (lib/samlClients.js, lib/oidcClients.js).

const MAX_URIS = 20;
const uris = (description) => ({ type: 'array', items: { type: 'string', format: 'uri' }, maxItems: MAX_URIS, description });
const url = (description) => ({ type: 'string', format: 'uri', description });

const COMMON = {
  name: { key: 'name', schema: { type: 'string', minLength: 1, maxLength: 80, description: 'Display name, shown to you and on the Keycloak login page.' } },
};

export const APP_FIELDS = {
  oidc: {
    ...COMMON,
    client_id: { key: 'clientId', createOnly: true, schema: { type: 'string', minLength: 1, maxLength: 255, pattern: '^[\\x21-\\x7e]+$', description: 'OAuth client_id, unique in the sandbox realm. Printable characters, no spaces. Cannot change.', example: 'my-billing-app' } },
    client_type: { key: 'clientType', schema: { type: 'string', enum: Object.keys(CLIENT_TYPES), default: 'confidential', description: 'confidential: a server-side app with a client secret. public: a single-page or native app, no secret (PKCE instead).' } },
    redirect_uris: { key: 'redirectUris', schema: uris('Where Keycloak may send the authorization code. At least one. A trailing /* is a wildcard, only after a /.') },
    post_logout_redirect_uris: { key: 'postLogoutRedirectUris', schema: uris('Where Keycloak may send the user after logout.') },
    web_origins: { key: 'webOrigins', schema: { ...uris('CORS origins (scheme, host, port) for browser calls to the token endpoint; "+" means the origins of the redirect URIs.'), items: { type: 'string' } } },
    home_url: { key: 'homeUrl', schema: url('The app\'s home page (optional).') },
    require_pkce: { key: 'requirePkce', schema: { type: 'boolean', default: true, description: 'Require PKCE with S256.' } },
    service_account: { key: 'serviceAccount', schema: { type: 'boolean', default: false, description: 'Allow the client credentials grant (confidential clients only).' } },
  },
  saml: {
    ...COMMON,
    client_id: { key: 'clientId', createOnly: true, schema: { type: 'string', minLength: 1, maxLength: 255, description: 'The SP entity ID (the Issuer of your AuthnRequests), unique in the sandbox realm. Cannot change.', example: 'https://myapp.example.com/saml' } },
    acs_url: { key: 'acsUrl', schema: url('Assertion Consumer Service URL (HTTP-POST binding). Required.') },
    slo_url: { key: 'sloUrl', schema: url('Single logout URL (optional).') },
    home_url: { key: 'homeUrl', schema: url('The app\'s home page (optional).') },
    name_id_format: { key: 'nameIdFormat', schema: { type: 'string', enum: Object.keys(NAME_ID_FORMATS), default: 'username' } },
    sign_documents: { key: 'signDocuments', schema: { type: 'boolean', default: true, description: 'Keycloak signs the whole response.' } },
    sign_assertions: { key: 'signAssertions', schema: { type: 'boolean', default: true, description: 'Keycloak signs the assertion. At least one of sign_documents and sign_assertions must be true.' } },
    client_signature: { key: 'clientSignature', schema: { type: 'boolean', default: false, description: 'Require signed AuthnRequests (then signing_cert is required).' } },
    signing_cert: { key: 'signingCert', schema: { type: 'string', description: 'Your SP\'s signing certificate, PEM.' } },
    encrypt_assertions: { key: 'encryptAssertions', schema: { type: 'boolean', default: false, description: 'Encrypt assertions (then encryption_cert is required).' } },
    encryption_cert: { key: 'encryptionCert', schema: { type: 'string', description: 'Your SP\'s encryption certificate, PEM.' } },
    encryption_key_algorithm: { key: 'encryptionKeyAlgorithm', schema: { type: 'string', enum: Object.keys(ENCRYPTION_KEY_ALGORITHMS), default: 'rsa-oaep-mgf1p', description: 'rsa-oaep-mgf1p works with passport-saml/node-saml and most libraries; rsa-oaep-11 is Keycloak\'s default.' } },
    attributes: { key: 'attributes', schema: { type: 'array', items: { type: 'string', enum: Object.keys(USER_ATTRIBUTES) }, default: ['email', 'firstName', 'lastName'], description: 'User properties sent as SAML attributes.' } },
    attribute_name_format: { key: 'attributeNameFormat', schema: { type: 'string', enum: ATTRIBUTE_NAME_FORMATS, default: 'Basic' } },
  },
};

export const APP_DEFAULTS = { oidc: defaultOidcValues, saml: defaultAppValues };

const typeName = (schema) => (schema.type === 'array' ? 'an array of strings' : schema.type === 'boolean' ? 'true or false' : 'a string');

// Reads a JSON object into form values, on top of `base` (defaults, or the current values for a
// PATCH). Unknown fields and wrong types are refused, so a typo doesn't pass silently.
export function valuesFromJson(fields, body, base, { isNew = true, ignore = [] } = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw invalid('Send a JSON object.');
  const values = structuredClone(base);
  for (const [name, value] of Object.entries(body)) {
    if (ignore.includes(name)) continue;
    const field = fields[name];
    if (!field) throw invalid(`Unknown field "${name}". Known fields: ${Object.keys(fields).join(', ')}.`, { field: name });
    const { schema } = field;
    if (schema.type === 'boolean') {
      if (typeof value !== 'boolean') throw invalid(`${name} must be ${typeName(schema)}.`, { field: name });
      values[field.key] = value;
    } else if (schema.type === 'integer') {
      if (!Number.isInteger(value)) throw invalid(`${name} must be an integer.`, { field: name });
      values[field.key] = value;
    } else if (schema.type === 'array') {
      if (!Array.isArray(value) || value.some((v) => typeof v !== 'string')) throw invalid(`${name} must be ${typeName(schema)}.`, { field: name });
      const items = [...new Set(value.map((v) => v.trim()).filter(Boolean))];
      const allowed = schema.items.enum;
      const bad = allowed && items.find((v) => !allowed.includes(v));
      if (bad) throw invalid(`${name}: "${bad}" is not one of ${allowed.join(', ')}.`, { field: name });
      values[field.key] = items;
    } else {
      if (typeof value !== 'string') throw invalid(`${name} must be ${typeName(schema)}.`, { field: name });
      if (field.createOnly && !isNew) {
        if (value.trim() !== base[field.key]) throw invalid(`${name} cannot change. Register a new application instead.`, { field: name });
        continue;
      }
      values[field.key] = value.trim();
    }
  }
  return values;
}

export function jsonFromValues(fields, values) {
  return Object.fromEntries(Object.entries(fields).map(([name, f]) => [name, values[f.key] ?? null]));
}

// The API name of a form-value key, for errors that name a field.
export const apiFieldName = (fields, key) => Object.entries(fields).find(([, f]) => f.key === key)?.[0]
  ?? key.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

// ---------- user migration ----------

const REQUEST_SIGNING = { secret: 'secret', public_key: 'publicKey', jwks: 'jwks' };

export const MIGRATION_FIELDS = {
  enabled: { key: 'enabled', schema: { type: 'boolean', default: true, description: 'Whether /migrate/start accepts requests. Off: requests are refused with migration_disabled.' } },
  return_urls: { key: 'returnUrls', schema: { type: 'array', items: { type: 'string', format: 'uri' }, minItems: 1, maxItems: 20, description: 'Where CloakTail may send users back with the result. A request\'s return_url must match one exactly.' } },
  request_signing: { key: 'requestKey', schema: { type: 'string', enum: Object.keys(REQUEST_SIGNING), default: 'secret', description: 'How your app signs requests: secret = HS256 with the migration secret; public_key = your private key, CloakTail holds public_key; jwks = your private key, CloakTail fetches jwks_url.' } },
  public_key: { key: 'publicKey', schema: { type: 'string', description: 'PEM public key (-----BEGIN PUBLIC KEY-----). Required with request_signing public_key.' } },
  jwks_url: { key: 'jwksUrl', schema: { type: 'string', format: 'uri', description: 'Your JWKS URL. Required with request_signing jwks.' } },
  require_otp: { key: 'requireOtp', schema: { type: 'boolean', default: true, description: 'Migrated users add an authenticator app on the CloakTail migration page, next to their new password.' } },
};

// JSON -> the migration form's values (lib/userMigration.js parseMigrationForm), on top of `base`.
export function migrationValuesFromJson(body, base) {
  const values = valuesFromJson(MIGRATION_FIELDS, body, { ...base, requestKey: Object.keys(REQUEST_SIGNING).find((k) => REQUEST_SIGNING[k] === base.requestKey) ?? base.requestKey });
  values.requestKey = REQUEST_SIGNING[values.requestKey] ?? values.requestKey;
  values.returnUrls = values.returnUrls.join('\n');
  return values;
}

export function migrationSettingsJson(settings, enabled) {
  return {
    enabled,
    return_urls: settings.returnUrls,
    request_signing: Object.keys(REQUEST_SIGNING).find((k) => REQUEST_SIGNING[k] === settings.requestKey),
    public_key: settings.publicKey || null,
    jwks_url: settings.jwksUrl || null,
    require_otp: settings.requireOtp,
  };
}

// ---------- test users and certificates ----------

export const TEST_USER_FIELDS = {
  username: { key: 'username', schema: { type: 'string', pattern: '^[a-z0-9][a-z0-9._-]{2,39}$', description: '3-40 lowercase letters, digits, . _ -' } },
  email: { key: 'email', schema: { type: 'string', format: 'email' } },
  first_name: { key: 'firstName', schema: { type: 'string', minLength: 1 } },
  last_name: { key: 'lastName', schema: { type: 'string', minLength: 1 } },
  password: { key: 'password', schema: { type: 'string', minLength: 8, writeOnly: true } },
};

export const CERTIFICATE_FIELDS = {
  common_name: { key: 'commonName', schema: { type: 'string', maxLength: 64, pattern: '^[A-Za-z0-9 ._:/@-]+$', example: 'myapp.example.com' } },
  organization: { key: 'organization', schema: { type: 'string', maxLength: 64, pattern: '^[A-Za-z0-9 ._:/@-]*$' } },
  key_size: { key: 'keySize', schema: { type: 'integer', enum: [2048, 3072, 4096], default: 2048 } },
  validity_years: { key: 'years', schema: { type: 'integer', enum: [1, 2, 3, 5], default: 2 } },
};

// The JSON Schema of an object made of these fields.
export const objectSchema = (fields, { required = [], omit = [] } = {}) => ({
  type: 'object',
  additionalProperties: false,
  ...(required.length ? { required } : {}),
  properties: Object.fromEntries(Object.entries(fields).filter(([n]) => !omit.includes(n)).map(([n, f]) => [n, f.schema])),
});
