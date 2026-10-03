// Copy for the developer API's public pages (/developers, /developers/api), shared with their JSON-LD
// and /llms.txt so the page, search engines and answer engines say the same thing. URLs are paths:
// callers prefix the request's own site URL.
// Last content change of these pages (sitemap lastmod, JSON-LD dateModified).
export const devUpdated = '2026-10-03';

export const devTitle = 'Keycloak SSO API for AI coding agents';
export const devDescription = 'Let Claude Code, Cursor or any AI coding agent set up Keycloak OpenID Connect and SAML for your app, with a REST API, OpenAPI 3.1 and an agent guide.';
export const devTagline = 'Your AI coding agent sets up Keycloak SSO. You review the pull request.';
export const devSummary = 'CloakTail’s developer API does everything the portal does: it registers OpenID Connect and SAML clients in a Keycloak sandbox realm, reads their secrets, sets up user migration and creates test users. It is described precisely enough for a coding agent to do the whole integration: an OpenAPI 3.1 document, a step-by-step agent guide with acceptance criteria, stable error codes and safe retries.';

export const devKeywords = [
  'Keycloak API', 'Keycloak REST API', 'AI coding agent', 'Claude Code', 'Cursor', 'GitHub Copilot', 'OpenAPI',
  'OpenID Connect client registration', 'SAML SP registration', 'OIDC client secret', 'Keycloak user migration',
  'OAuth 2.0 client credentials', 'SSO automation', 'llms.txt',
];

// What the API does, one card per area: the endpoints it uses and the scope they need.
export const capabilities = [
  {
    id: 'apps', icon: 'apps', title: 'Register OIDC and SAML clients',
    text: 'Create, change and delete clients in the sandbox realm: confidential or public OIDC clients with PKCE, or SAML SPs from fields or pasted SP metadata. Each response carries the issuer, endpoints or IdP certificate your code needs.',
    scope: 'apps:write',
    endpoints: [['POST', '/apps'], ['PATCH', '/apps/{id}'], ['POST', '/saml-metadata']],
  },
  {
    id: 'secrets', icon: 'key', title: 'Read and rotate secrets',
    text: 'Write every variable your app needs, secrets included, straight into its .env as NAME=value lines, so the agent never has to see a value. Rotate secrets when needed. Secrets need their own scope: you decide whether an agent may read them.',
    scope: 'secrets:read',
    endpoints: [['GET', '/apps/{id}/env'], ['GET', '/apps/{id}/client-secret']],
  },
  {
    id: 'migration', icon: 'users', title: 'Migrate existing users',
    text: 'Set up user migration for an app that signs users in itself today: return URLs, request signing and OTP. Users move into Keycloak one by one as they sign in: one CloakTail page for a new password and an authenticator app, then straight back into the app. CloakTail keeps its own record, so returning users are recognised, lost results can be recovered and conflicts resolved.',
    scope: 'apps:write',
    endpoints: [['PUT', '/apps/{id}/migration'], ['PUT', '/apps/{id}/migration/users/{sub}'], ['GET', '/apps/{id}/migration/events']],
  },
  {
    id: 'tests', icon: 'play', title: 'Verify real logins',
    text: 'Start a test login and read the result as JSON: every check, the signatures, the assertion or ID token, and the claims. A person signs in once; the agent reads the evidence.',
    scope: 'apps:write',
    endpoints: [['POST', '/apps/{id}/tests'], ['GET', '/apps/{id}/tests/{runId}']],
  },
  {
    id: 'test-users', icon: 'testUser', title: 'Create test users',
    text: 'Create sandbox accounts with the profile your app expects, set their passwords and delete them, so every login can be tried without real people.',
    scope: 'test_users',
    endpoints: [['POST', '/test-users'], ['POST', '/test-users/{id}/password']],
  },
  {
    id: 'tools', icon: 'certificate', title: 'Generate SAML certificates',
    text: 'Create a key pair and self-signed certificate for signed AuthnRequests or encrypted assertions. Nothing is stored: the private key goes straight into your project.',
    scope: 'tools',
    endpoints: [['POST', '/tools/certificate']],
  },
];

// Setting it up, for the person.
export const devSteps = [
  { title: 'Create an API credential', text: 'In CloakTail, open API credentials and choose scopes and an expiry. You get a client ID and a secret, shown once.' },
  { title: 'Give it to your agent safely', text: 'Save the client ID and secret as CLOAKTAIL_CLIENT_ID and CLOAKTAIL_CLIENT_SECRET in a git-ignored .env.cloaktail (or your shell profile), apart from your app’s own .env. Never paste the secret into a chat.' },
  { title: 'Ask for the integration', text: 'Tell your agent what you want, e.g. “add OpenID Connect login”, and where to start: the agent guide. It does the rest and hands you a test login.' },
];

// What the agent does for "add OpenID Connect login", in order: method, path, what and why.
export const agentRun = [
  ['POST', '/oauth/token', 'Exchanges the credential for a 15-minute access token.'],
  ['GET', '/me', 'Checks whose account it acts for, its scopes and quotas.'],
  ['POST', '/apps', 'Registers a confidential OIDC client with your app’s callback URL.'],
  ['GET', '/apps/{id}/env', 'Writes the issuer, client ID and secret into your .env without printing them.'],
  [null, null, 'Writes the login code with your framework’s OIDC library, configured from the discovery URL.'],
  ['POST', '/test-users', 'Creates a sandbox user to sign in with.'],
  ['POST', '/apps/{id}/tests', 'Starts a test login and gives you the link.'],
  ['GET', '/apps/{id}/tests/{runId}', 'Reads the result once you have signed in, and fixes anything that failed.'],
];

// Why an agent gets it right: what the documents promise, precisely.
export const agentContract = [
  { title: 'One guide, every step', text: 'agent.md gives the order of calls for each task, the values to choose, and “done when” criteria the agent checks before it stops.' },
  { title: 'Exact schemas', text: 'OpenAPI 3.1 built from the same field definitions the API validates with. Unknown fields are rejected, so typos fail loudly.' },
  { title: 'Stable error codes', text: 'Every error is RFC 9457 problem+json with a code, the field at fault and how to fix it. The guide maps each code to an action.' },
  { title: 'Safe to retry', text: 'Creating twice answers 409 with the existing id, so an agent that retries continues instead of duplicating.' },
  { title: 'No hard-coded hosts', text: 'Every URL in the documents is relative to where they were fetched, so one guide works on every CloakTail domain.' },
  { title: 'Discoverable', text: 'Linked from llms.txt, an RFC 9727 API catalog at /.well-known/api-catalog, and Link headers on every API response.' },
];

export const devSecurity = [
  { title: 'Scoped and expiring', text: 'Each credential has only the scopes you choose and expires when you decide: after 30, 90 or 365 days, or never. Up to 10 per developer.' },
  { title: 'Revocable at once', text: 'Revoke a credential and its tokens stop working on the next call. Losing your developer role stops it too.' },
  { title: 'Short-lived tokens', text: 'Agents trade the credential for an access token that lasts 15 minutes. The secret is stored only as a hash.' },
  { title: 'Secrets stay out of chat', text: 'Agents read the credential from the environment, pass it to curl on stdin, and write secrets straight from the API into .env files. The guide forbids printing, logging or committing them.' },
];

export const devFaq = [
  { q: 'Which AI coding agents work with the CloakTail API?', a: 'Any agent that can run shell commands or make HTTP requests: Claude Code, Cursor, GitHub Copilot agent mode, Windsurf, Codex and others. Point it at the agent guide (/api/v1/agent.md); it needs no plugin.' },
  { q: 'Does the agent see my secrets?', a: 'Only if the credential has the secrets:read scope. The agent guide requires agents to write secrets straight into your git-ignored .env without printing them. Leave secrets:read out to copy secrets from the portal yourself.' },
  { q: 'Can the API change production Keycloak?', a: 'No. Everything happens in the isolated sandbox realm: clients, test users and migrated users. It is for development and testing only.' },
  { q: 'How does the agent authenticate?', a: 'With the OAuth 2.0 client credentials grant: it exchanges your API credential’s client ID and secret at /api/v1/oauth/token for a bearer token that lasts 15 minutes.' },
  { q: 'Can an agent run a test login by itself?', a: 'It starts the test and reads the result, but a person signs in: the agent gives you a link and a test user, you sign in once, and it reads every check as JSON.' },
  { q: 'Is there an OpenAPI specification?', a: 'Yes: an OpenAPI 3.1 document at /api/v1/openapi.json, with an interactive reference at /developers/api. It works with code generators, Postman and Swagger tools.' },
];

// ---------- schema.org data ----------

const breadcrumbs = (baseUrl, items) => ({
  '@context': 'https://schema.org',
  '@type': 'BreadcrumbList',
  itemListElement: [['CloakTail', '/'], ...items].map(([name, path], i) => ({
    '@type': 'ListItem', position: i + 1, name, item: `${baseUrl}${path}`,
  })),
});

export function devStructuredData(baseUrl) {
  const url = `${baseUrl}/developers`;
  return [
    {
      '@context': 'https://schema.org',
      '@type': 'TechArticle',
      headline: devTitle,
      description: devDescription,
      url,
      dateModified: devUpdated,
      keywords: devKeywords.join(', '),
      about: ['Keycloak', 'OpenID Connect', 'SAML 2.0', 'AI coding agents'],
      publisher: { '@type': 'Organization', name: 'CloakTail', url: baseUrl },
      encoding: { '@type': 'MediaObject', encodingFormat: 'text/markdown', contentUrl: `${baseUrl}/api/v1/agent.md` },
    },
    {
      '@context': 'https://schema.org',
      '@type': 'HowTo',
      name: 'Let an AI coding agent set up Keycloak SSO with CloakTail',
      totalTime: 'PT10M',
      step: devSteps.map((s, i) => ({ '@type': 'HowToStep', position: i + 1, name: s.title, text: s.text, url: `${url}#setup` })),
    },
    {
      '@context': 'https://schema.org',
      '@type': 'FAQPage',
      mainEntity: devFaq.map((f) => ({ '@type': 'Question', name: f.q, acceptedAnswer: { '@type': 'Answer', text: f.a } })),
    },
    breadcrumbs(baseUrl, [['Developers', '/developers']]),
  ];
}

export function apiStructuredData(baseUrl) {
  return [
    {
      '@context': 'https://schema.org',
      '@type': 'WebAPI',
      name: 'CloakTail developer API',
      description: devSummary,
      url: `${baseUrl}/developers/api`,
      documentation: `${baseUrl}/api/v1/openapi.json`,
      provider: { '@type': 'Organization', name: 'CloakTail', url: baseUrl },
      dateModified: devUpdated,
      keywords: devKeywords.join(', '),
    },
    breadcrumbs(baseUrl, [['Developers', '/developers'], ['API reference', '/developers/api']]),
  ];
}
