import { SCOPES, TOKEN_TTL_S } from '../lib/apiCredentials.js';
import { RESULT_STATUSES } from '../lib/userMigration.js';
import { APP_FIELDS, MIGRATION_FIELDS, TEST_USER_FIELDS, CERTIFICATE_FIELDS, objectSchema } from './fields.js';

// /api/v1/openapi.json: the REST API (routes/api.js) as OpenAPI 3.1. Request schemas come from the
// field definitions the API reads bodies with (api/fields.js). Keep paths in step with routes/api.js.

const ref = (name) => ({ $ref: `#/components/schemas/${name}` });
const json = (schema) => ({ content: { 'application/json': { schema } } });
const problemResponse = (description) => ({ description, content: { 'application/problem+json': { schema: ref('Problem') } } });

const ERRORS = {
  400: problemResponse('Bad request (invalid_json, public_client, not_oidc, signed_requests_required, …)'),
  401: problemResponse('invalid_token: missing, invalid or expired access token, or the credential was revoked'),
  403: problemResponse('insufficient_scope, or forbidden (the account lacks the apps.own permission)'),
  404: problemResponse('not_found, keycloak_client_missing or migration_not_configured'),
  409: problemResponse('duplicate_client_id (with existing_app_id when it is yours), duplicate_username or secret_unreadable'),
  422: problemResponse('validation_failed (with field), quota_exceeded or keycloak_rejected'),
  429: problemResponse('rate_limited'),
};
const errors = (...codes) => Object.fromEntries(codes.map((c) => [c, ERRORS[c]]));

// Adds ?format=dotenv to an operation: its answer can be NAME=value lines instead of JSON.
const formatParam = { name: 'format', in: 'query', schema: { enum: ['json', 'dotenv'], default: 'json' }, description: 'dotenv: answer NAME=value lines (text/plain) to write straight into a .env file.' };
function withDotenv(operation, { onlyDotenv = false } = {}) {
  const ok = operation.responses[200];
  const text = { 'text/plain': { schema: { type: 'string' }, example: 'OIDC_CLIENT_SECRET=…\n' } };
  ok.content = onlyDotenv ? { ...text, ...ok.content } : { ...ok.content, ...text };
  operation.parameters = [...(operation.parameters ?? []), formatParam];
  return operation;
}

const idParam = { name: 'id', in: 'path', required: true, schema: { type: 'integer' }, description: 'Application id (from GET /apps or the create response).' };

function op(scope, { id, summary, description, body, ok = 200, response, errorCodes = [], params = [] }) {
  return {
    operationId: id,
    summary,
    ...(description ? { description } : {}),
    security: [{ oauth2: [scope] }, { bearerAuth: [] }],
    ...(params.length ? { parameters: params } : {}),
    ...(body ? { requestBody: { required: true, ...json(body) } } : {}),
    responses: {
      [ok]: response ? { description: 'OK', ...json(response) } : { description: 'Done' },
      ...errors(401, 403, ...errorCodes),
    },
  };
}

// It names no host: the server and token URLs are relative, so clients resolve them against wherever
// they fetched the document, and one document is right on every domain.
export function openApiSpec() {
  const base = '/api/v1';
  const oidcCreate = objectSchema(APP_FIELDS.oidc, { required: ['protocol', 'name', 'client_id', 'redirect_uris'] });
  oidcCreate.properties = { protocol: { const: 'oidc' }, ...oidcCreate.properties };
  const samlCreate = objectSchema(APP_FIELDS.saml, { required: ['protocol', 'name', 'client_id', 'acs_url'] });
  samlCreate.properties = { protocol: { const: 'saml' }, ...samlCreate.properties };
  const patch = (protocol) => {
    const s = objectSchema(APP_FIELDS[protocol], { omit: ['client_id'] });
    s.properties = { protocol: { const: protocol, description: 'Optional; must be the app\'s protocol.' }, ...s.properties };
    return s;
  };

  return {
    openapi: '3.1.0',
    info: {
      title: 'CloakTail developer API',
      version: '1.0.0',
      license: { name: 'MIT', identifier: 'MIT' },
      description: [
        'Everything a developer does in the CloakTail portal: register SAML and OpenID Connect applications in the Keycloak sandbox realm, read their secrets, set up user migration, manage test users, test logins and generate certificates.',
        '',
        '**Base URL.** Every path is relative to the CloakTail site this document was fetched from: the API is at `/api/v1` on that host.',
        '',
        `**Authentication.** Create an API credential on the site's API credentials page (\`/api-credentials\`), then exchange its client ID and secret for an access token with the OAuth 2.0 client credentials grant at \`POST ${base}/oauth/token\`. Tokens last ${TOKEN_TTL_S / 60} minutes. Send them as \`Authorization: Bearer <token>\`.`,
        '',
        `**Coding agents:** read \`${base}/agent.md\` first (for people: \`/developers\`): it gives the order of calls for common tasks and the rules for handling secrets.`,
        '',
        '**Errors** are RFC 9457 problem details (`application/problem+json`) with a stable `code`; validation errors also name the `field`.',
      ].join('\n'),
    },
    servers: [{ url: base }],
    tags: [
      { name: 'Auth', description: 'Exchange an API credential for an access token.' },
      { name: 'Account', description: 'Who you are, your quotas and the sandbox realm.' },
      { name: 'Applications', description: 'SAML and OpenID Connect clients in the sandbox realm.' },
      { name: 'Secrets', description: 'OIDC client secrets and migration secrets. Never print or commit them.' },
      { name: 'Testing', description: 'Test logins, completed by a person in a browser.' },
      { name: 'User migration', description: 'Move an application\'s existing users into Keycloak as they sign in.' },
      { name: 'Test users', description: 'Your accounts in the sandbox realm to sign in with.' },
      { name: 'Tools', description: 'Certificates for SAML SPs.' },
    ],
    paths: {
      '/oauth/token': {
        post: {
          tags: ['Auth'],
          operationId: 'getToken',
          summary: 'Get an access token (client credentials grant)',
          description: 'Authenticate with HTTP Basic (client_secret_basic) or client_id and client_secret in the body (client_secret_post). Errors follow RFC 6749 (`error`, `error_description`).',
          security: [],
          requestBody: {
            required: true,
            content: {
              'application/x-www-form-urlencoded': { schema: ref('TokenRequest') },
              'application/json': { schema: ref('TokenRequest') },
            },
          },
          responses: {
            200: { description: 'Token', ...json(ref('TokenResponse')) },
            400: { description: 'unsupported_grant_type or invalid_scope', ...json(ref('OAuthError')) },
            401: { description: 'invalid_client', ...json(ref('OAuthError')) },
            429: { description: 'slow_down', ...json(ref('OAuthError')) },
          },
        },
      },
      '/me': {
        get: { tags: ['Account'], ...op('apps:read', { id: 'getMe', summary: 'Who the token acts as, its scopes, quotas and the sandbox IdP endpoints', response: ref('Me') }), security: [{ oauth2: [] }, { bearerAuth: [] }] },
      },
      '/apps': {
        get: {
          tags: ['Applications'],
          ...op('apps:read', {
            id: 'listApps', summary: 'List your applications', response: { type: 'object', properties: { apps: { type: 'array', items: ref('AppSummary') } } },
            params: [{ name: 'all', in: 'query', schema: { type: 'boolean' }, description: 'Every developer\'s apps (needs the apps.view_all permission).' }],
          }),
        },
        post: {
          tags: ['Applications'],
          ...op('apps:write', {
            id: 'createApp', summary: 'Register an application', ok: 201, response: ref('App'),
            description: 'Creates the client in the sandbox realm. A retry with the same client_id gets 409 duplicate_client_id with existing_app_id: carry on with that app.',
            body: { oneOf: [ref('OidcAppCreate'), ref('SamlAppCreate')], discriminator: { propertyName: 'protocol', mapping: { oidc: '#/components/schemas/OidcAppCreate', saml: '#/components/schemas/SamlAppCreate' } } },
            errorCodes: [409, 422],
          }),
        },
      },
      '/saml-metadata': {
        post: {
          tags: ['Applications'],
          ...op('apps:write', {
            id: 'parseSamlMetadata', summary: 'Read SP metadata XML into SAML app fields (creates nothing)',
            description: 'Returns fields for POST /apps; add a name.',
            body: { type: 'object', required: ['metadata'], properties: { metadata: { type: 'string', description: 'SP metadata XML (<EntityDescriptor …>).' } } },
            response: ref('SamlAppCreate'), errorCodes: [422],
          }),
        },
      },
      '/apps/{id}': {
        get: { tags: ['Applications'], ...op('apps:read', { id: 'getApp', summary: 'An application, with what your code needs to integrate (integration)', params: [idParam], response: ref('App'), errorCodes: [404] }) },
        patch: {
          tags: ['Applications'],
          ...op('apps:write', {
            id: 'updateApp', summary: 'Change an application', description: 'Send only the fields to change. Arrays replace the whole list. client_id and protocol cannot change.',
            params: [idParam], body: { anyOf: [patch('oidc'), patch('saml')] }, response: ref('App'), errorCodes: [404, 422],
          }),
        },
        delete: { tags: ['Applications'], ...op('apps:write', { id: 'deleteApp', summary: 'Delete an application and its Keycloak client', params: [idParam], ok: 204, errorCodes: [404] }) },
      },
      '/apps/{id}/client-secret': {
        get: withDotenv({ tags: ['Secrets'], ...op('secrets:read', { id: 'getClientSecret', summary: 'The client secret of a confidential OIDC client', params: [idParam], response: ref('ClientSecret'), errorCodes: [400, 404] }) }),
      },
      '/apps/{id}/env': {
        get: withDotenv({
          tags: ['Secrets'],
          ...op('secrets:read', {
            id: 'getAppEnv', summary: 'Every variable the application needs, as .env lines',
            description: 'OIDC: OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET (confidential clients), OIDC_REDIRECT_URI, OIDC_POST_LOGOUT_REDIRECT_URI (when set). SAML: SAML_IDP_METADATA_URL, SAML_IDP_SSO_URL, SAML_IDP_CERT (base64 DER, one line), SAML_SP_ENTITY_ID, SAML_ACS_URL. With user migration set up, also CLOAKTAIL_URL and CLOAKTAIL_MIGRATION_SECRET. Answers dotenv unless format=json. Write it to a file with curl -o; never print it.',
            params: [idParam], response: { type: 'object', properties: { variables: { type: 'object', additionalProperties: { type: 'string' } } } }, errorCodes: [404],
          }),
        }, { onlyDotenv: true }),
      },
      '/apps/{id}/client-secret/rotate': {
        post: { tags: ['Secrets'], ...op('apps:write', { id: 'rotateClientSecret', summary: 'Replace the client secret; the old one stops working at once', description: 'The new secret is in the response when the token also has secrets:read.', params: [idParam], response: ref('ClientSecret'), errorCodes: [400, 404] }) },
      },
      '/apps/{id}/tests': {
        get: { tags: ['Testing'], ...op('apps:read', { id: 'listTestRuns', summary: 'The last 10 test logins', params: [idParam], response: { type: 'object', properties: { runs: { type: 'array', items: ref('TestRunSummary') } } }, errorCodes: [404] }) },
        post: {
          tags: ['Testing'],
          ...op('apps:write', {
            id: 'startTest', summary: 'Start a test login', ok: 201, params: [idParam], errorCodes: [400, 404],
            description: 'A login needs a person: they open test_url in a browser within 10 minutes and sign in as a test user. Then poll GET /apps/{id}/tests.',
            response: { type: 'object', properties: { test_url: { type: 'string', format: 'uri' }, expires_in: { type: 'integer' }, instructions: { type: 'string' } } },
          }),
        },
      },
      '/apps/{id}/tests/{runId}': {
        get: {
          tags: ['Testing'],
          ...op('apps:read', {
            id: 'getTestRun', summary: 'A test login\'s checks, assertion or tokens, and claims', errorCodes: [404],
            params: [idParam, { name: 'runId', in: 'path', required: true, schema: { type: 'integer' } }],
            response: { type: 'object', properties: { id: { type: 'integer' }, ok: { type: 'boolean' }, summary: { type: 'string' }, created_at: { type: 'string', format: 'date-time' }, result: { type: 'object' } } },
          }),
        },
      },
      '/apps/{id}/migration': {
        get: { tags: ['User migration'], ...op('apps:read', { id: 'getMigration', summary: 'User migration settings, counts and endpoints', params: [idParam], response: ref('Migration'), errorCodes: [404] }) },
        put: {
          tags: ['User migration'],
          ...op('apps:write', {
            id: 'putMigration', summary: 'Set up or change user migration', ok: 200, params: [idParam], response: ref('Migration'), errorCodes: [404, 422],
            description: 'Fields left out keep their current value (their default on first setup; return_urls is required then). The first setup answers 201 and creates the migration secret: read it with GET /apps/{id}/migration/secret. Validation errors list every field in errors.',
            body: objectSchema(MIGRATION_FIELDS),
          }),
        },
      },
      '/apps/{id}/migration/secret': {
        get: withDotenv({ tags: ['Secrets', 'User migration'], ...op('secrets:read', { id: 'getMigrationSecret', summary: 'The migration secret', params: [idParam], response: ref('MigrationSecret'), errorCodes: [404, 409] }) }),
      },
      '/apps/{id}/migration/secret/rotate': {
        post: { tags: ['Secrets', 'User migration'], ...op('apps:write', { id: 'rotateMigrationSecret', summary: 'Replace the migration secret; the old one stops working at once', params: [idParam], response: ref('MigrationSecret'), errorCodes: [404] }) },
      },
      '/apps/{id}/migration/events': {
        get: {
          tags: ['User migration'],
          ...op('apps:read', {
            id: 'listMigrationEvents', summary: 'Migration request history, newest first', errorCodes: [404],
            params: [idParam, { name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 200, default: 50 } }],
            response: { type: 'object', properties: { events: { type: 'array', items: ref('MigrationEvent') } } },
          }),
        },
      },
      '/apps/{id}/migration/users': {
        get: {
          tags: ['User migration'],
          ...op('apps:read', {
            id: 'listMigratedUsers', summary: 'Which Keycloak user each migrated legacy user (sub) became',
            description: 'CloakTail\'s own record. It decides already_migrated, whatever attributes the realm keeps on users.',
            params: [idParam], response: { type: 'object', properties: { users: { type: 'array', items: ref('MigratedUser') } } }, errorCodes: [404],
          }),
        },
      },
      '/apps/{id}/migration/users/{sub}': {
        put: {
          tags: ['User migration'],
          ...op('apps:write', {
            id: 'linkMigratedUser', summary: 'Link a legacy user to an existing Keycloak account',
            description: 'Resolves a conflict: the next migration request for this sub answers already_migrated with that account. 201 when new, 200 when it replaced a link.',
            params: [idParam, { name: 'sub', in: 'path', required: true, schema: { type: 'string', maxLength: 255 }, description: 'The user\'s id in the application (the sub of its requests).' }],
            body: { type: 'object', required: ['username'], additionalProperties: false, properties: { username: { type: 'string', description: 'The existing Keycloak username, or its email address, in the sandbox realm.' } } },
            ok: 201, response: ref('MigratedUser'), errorCodes: [404, 422],
          }),
        },
        delete: {
          tags: ['User migration'],
          ...op('apps:write', {
            id: 'unlinkMigratedUser', summary: 'Forget a migrated user: the next request for this sub migrates again', ok: 204, errorCodes: [404],
            params: [idParam, { name: 'sub', in: 'path', required: true, schema: { type: 'string' } }],
          }),
        },
      },
      '/test-users': {
        get: { tags: ['Test users'], ...op('test_users', { id: 'listTestUsers', summary: 'Your test users in the sandbox realm', response: { type: 'object', properties: { test_users: { type: 'array', items: ref('TestUser') }, max: { type: 'integer' } } } }) },
        post: { tags: ['Test users'], ...op('test_users', { id: 'createTestUser', summary: 'Create a test user', ok: 201, body: objectSchema(TEST_USER_FIELDS, { required: Object.keys(TEST_USER_FIELDS) }), response: ref('TestUser'), errorCodes: [409, 422] }) },
      },
      '/test-users/{id}/password': {
        post: { tags: ['Test users'], ...op('test_users', { id: 'setTestUserPassword', summary: 'Set a test user\'s password', ok: 204, params: [{ ...idParam, description: 'Test user id.' }], body: { type: 'object', required: ['password'], properties: { password: { type: 'string', minLength: 8 } } }, errorCodes: [404, 422] }) },
      },
      '/test-users/{id}': {
        delete: { tags: ['Test users'], ...op('test_users', { id: 'deleteTestUser', summary: 'Delete a test user', ok: 204, params: [{ ...idParam, description: 'Test user id.' }], errorCodes: [404] }) },
      },
      '/tools/certificate': {
        post: {
          tags: ['Tools'],
          ...op('tools', {
            id: 'generateCertificate', summary: 'Generate a key pair and self-signed certificate for a SAML SP', errorCodes: [422, 429],
            description: 'Nothing is stored: save private_key_pem straight to a file and never print it.',
            body: objectSchema(CERTIFICATE_FIELDS, { required: ['common_name'] }),
            response: { type: 'object', properties: { private_key_pem: { type: 'string' }, certificate_pem: { type: 'string' }, subject: { type: 'string' }, valid_to: { type: 'string', format: 'date-time' }, fingerprint_sha256: { type: 'string' } } },
          }),
        },
      },
    },
    components: {
      securitySchemes: {
        oauth2: { type: 'oauth2', description: 'API credential from /api-credentials.', flows: { clientCredentials: { tokenUrl: `${base}/oauth/token`, scopes: SCOPES } } },
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', description: 'An access token from POST /oauth/token.' },
      },
      schemas: {
        Problem: {
          type: 'object',
          required: ['type', 'title', 'status', 'code', 'detail'],
          properties: {
            type: { type: 'string' }, title: { type: 'string' }, status: { type: 'integer' },
            code: { type: 'string', description: 'Stable reason; see agent.md#errors.' },
            detail: { type: 'string', description: 'What went wrong and how to fix it.' },
            field: { type: 'string', description: 'The request field at fault, when there is one.' },
            errors: { type: 'array', items: { type: 'object', properties: { field: { type: 'string' }, message: { type: 'string' } } } },
            existing_app_id: { type: 'integer', description: 'With duplicate_client_id, when the app is yours.' },
          },
        },
        TokenRequest: {
          type: 'object',
          required: ['grant_type'],
          properties: {
            grant_type: { const: 'client_credentials' },
            client_id: { type: 'string', description: 'Unless sent with HTTP Basic.' },
            client_secret: { type: 'string', description: 'Unless sent with HTTP Basic.' },
            scope: { type: 'string', description: 'Space-separated subset of the credential\'s scopes. Default: all of them.' },
          },
        },
        TokenResponse: {
          type: 'object',
          properties: { access_token: { type: 'string' }, token_type: { const: 'Bearer' }, expires_in: { type: 'integer' }, scope: { type: 'string' } },
        },
        OAuthError: { type: 'object', properties: { error: { type: 'string' }, error_description: { type: 'string' } } },
        Me: {
          type: 'object',
          properties: {
            username: { type: 'string' },
            credential: { type: 'object', properties: { name: { type: 'string' }, client_id: { type: 'string' }, expires_at: { type: ['string', 'null'], format: 'date-time' } } },
            scopes: { type: 'array', items: { type: 'string' } },
            quotas: { type: 'object', additionalProperties: { type: 'object', properties: { used: { type: 'integer' }, max: { type: 'integer' } } } },
            sandbox: { type: 'object', description: 'The sandbox realm\'s OIDC and SAML endpoints.' },
          },
        },
        OidcAppCreate: oidcCreate,
        SamlAppCreate: samlCreate,
        AppSummary: {
          type: 'object',
          properties: {
            id: { type: 'integer' }, protocol: { enum: ['oidc', 'saml'] }, name: { type: 'string' }, client_id: { type: 'string' }, owner: { type: 'string' },
            created_at: { type: 'string', format: 'date-time' },
            last_test: { type: ['object', 'null'], properties: { ok: { type: 'boolean' }, at: { type: 'string', format: 'date-time' } } },
            url: { type: 'string', format: 'uri' },
          },
        },
        App: {
          type: 'object',
          description: 'id, protocol and the fields of OidcAppCreate or SamlAppCreate, plus:',
          properties: {
            id: { type: 'integer' },
            protocol: { enum: ['oidc', 'saml'] },
            owner: { type: 'string' },
            enabled: { type: 'boolean' },
            created_at: { type: 'string', format: 'date-time' },
            integration: {
              type: 'object',
              description: 'What the application\'s code needs. OIDC: issuer, discovery_url, endpoints, client_id, client_secret (the URL to read it from; null for public clients), scopes. SAML: idp_entity_id, idp_sso_url, idp_slo_url, idp_metadata_url, idp_certificate_pem, sp_entity_id, name_id_format, idp_initiated_sso_url.',
            },
            migration: { type: 'object', properties: { configured: { type: 'boolean' }, enabled: { type: 'boolean' }, url: { type: 'string' } } },
            portal_url: { type: 'string', format: 'uri' },
          },
          additionalProperties: true,
        },
        ClientSecret: { type: 'object', properties: { client_id: { type: 'string' }, client_secret: { type: 'string' }, rotated: { type: 'boolean' } } },
        TestRunSummary: { type: 'object', properties: { id: { type: 'integer' }, ok: { type: 'boolean' }, summary: { type: 'string' }, created_at: { type: 'string', format: 'date-time' }, url: { type: 'string' } } },
        Migration: {
          type: 'object',
          properties: {
            configured: { type: 'boolean' },
            ...objectSchema(MIGRATION_FIELDS).properties,
            secret_readable: { type: ['boolean', 'null'] },
            counts: { type: 'object', description: 'Requests by status, plus migratedUsers.', additionalProperties: { type: 'integer' } },
            warnings: { type: 'array', items: ref('Warning'), description: 'Things to know about the setup. Act on code; impact says how much it matters.' },
            endpoints: {
              type: 'object',
              properties: {
                start: { type: 'string' }, request_aud_and_result_iss: { type: 'string' }, check: { type: 'string' },
                simulate: { type: 'string' }, status: { type: 'string' }, spec: { type: 'string' }, secret: { type: 'string' }, users: { type: 'string' }, env: { type: 'string' },
              },
            },
          },
        },
        Warning: {
          type: 'object',
          required: ['code', 'message', 'who_can_fix', 'impact', 'ignorable_if'],
          properties: {
            code: { enum: ['realm_drops_migration_attributes', 'realm_check_failed', 'jwks_unreachable', 'jwks_no_usable_key'] },
            message: { type: 'string' },
            who_can_fix: { enum: ['developer', 'admin'] },
            impact: { type: 'string', description: 'Starts with High, Low or None.' },
            ignorable_if: { type: 'string' },
          },
        },
        MigratedUser: {
          type: 'object',
          properties: {
            sub: { type: 'string' }, keycloak_id: { type: 'string' }, username: { type: 'string' },
            migrated_at: { type: 'string', format: 'date-time' }, linked_by: { type: ['string', 'null'], description: 'Who linked it by hand; null when migrated by the user.' },
          },
        },
        MigrationSecret: { type: 'object', properties: { client_id: { type: 'string' }, migration_secret: { type: 'string' }, rotated: { type: 'boolean' } } },
        MigrationEvent: {
          type: 'object',
          properties: {
            id: { type: 'integer' },
            status: { enum: ['started', 'rejected', ...Object.keys(RESULT_STATUSES)] },
            legacy_id: { type: ['string', 'null'] }, username: { type: ['string', 'null'] }, keycloak_id: { type: ['string', 'null'] },
            detail: { type: ['string', 'null'], description: 'For rejected requests: the error code and reason.' },
            created_at: { type: 'string', format: 'date-time' }, updated_at: { type: 'string', format: 'date-time' },
          },
        },
        TestUser: {
          type: 'object',
          properties: {
            id: { type: 'integer' }, username: { type: 'string' }, email: { type: ['string', 'null'] },
            first_name: { type: ['string', 'null'] }, last_name: { type: ['string', 'null'] }, enabled: { type: ['boolean', 'null'] },
            missing_in_keycloak: { type: 'boolean' }, created_at: { type: 'string', format: 'date-time' },
          },
        },
      },
    },
  };
}

// The operations of the document as a flat list, grouped by tag in the document's tag order: for the
// reference page and the agent guide's endpoint table, so both list exactly what the spec does.
export function endpointGroups(spec = openApiSpec()) {
  const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const groups = spec.tags.map((t) => ({ id: slug(t.name), name: t.name, description: t.description, endpoints: [] }));
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(item)) {
      const ok = Object.keys(op.responses).find((code) => code.startsWith('2'));
      const content = op.requestBody?.content ?? {};
      const bodyType = content['application/json'] ? 'application/json' : Object.keys(content)[0];
      const endpoint = {
        method: method.toUpperCase(),
        path,
        operationId: op.operationId,
        summary: op.summary,
        description: op.description ?? '',
        // The scope the call needs: "any" for a token with any scope, "none" for no token at all.
        scope: op.security?.find((s) => s.oauth2)?.oauth2[0] ?? (op.security?.length ? 'any' : 'none'),
        ok: Number(ok),
        body: bodyType ?? null,
      };
      groups.find((g) => g.name === op.tags[0]).endpoints.push(endpoint);
    }
  }
  return groups.filter((g) => g.endpoints.length);
}
