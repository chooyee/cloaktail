// Public product copy, shared by the landing page, /llms.txt, /llms-full.txt and the JSON-LD, so
// search engines, answer engines and people all read the same facts.

export const tagline = 'Keycloak SSO, tested before you ship.';

export const summary = 'CloakTail is the self-service developer portal for Keycloak SAML and OpenID Connect (OIDC). Developers register a SAML or OIDC client in an isolated sandbox realm, sign in as a test user, and inspect every assertion, token and claim before their app goes near production.';

export const facts = ['SAML 2.0', 'OpenID Connect', 'OAuth 2.0 + PKCE', 'Keycloak', 'Signature & JWKS checks', 'Metadata import', 'Isolated sandbox realm'];

// Search keywords for the JSON-LD and the landing page's meta keywords.
export const keywords = [
  'Keycloak', 'SAML 2.0', 'OpenID Connect', 'OIDC', 'OAuth 2.0', 'PKCE', 'SSO', 'single sign-on',
  'SAML testing', 'OIDC testing', 'SAML debugger', 'SAML decoder', 'JWT decoder', 'ID token', 'JWKS',
  'SP metadata', 'Keycloak client', 'identity provider sandbox',
];

// `ctx` holds the runtime values the copy mentions: { sandboxRealm, maxApps, maxTestUsers }.
export const quickstart = ({ sandboxRealm }) => [
  { title: 'Create your account', time: '1 min', text: 'Register as a developer, then sign in with Keycloak.', href: '/register', link: 'Sign up' },
  { title: 'Add a test user', time: '1 min', text: `A made-up identity in the ${sandboxRealm} sandbox to sign in with.`, href: '/test-users', link: 'Test users' },
  { title: 'Register your client', time: '2 min', text: 'SAML: enter your entity ID and ACS URL, or import your SP metadata. OIDC: enter your client ID and redirect URIs.', href: '/apps/new', link: 'New application' },
  { title: 'Test end to end', time: '1 min', text: 'Run a test login and inspect every check, signature, attribute and claim.', href: '/apps', link: 'Applications' },
];

export const features = ({ sandboxRealm }) => [
  { tag: 'Self-service', title: 'SAML and OIDC clients on demand', text: 'Create, edit and delete your own Keycloak clients. SAML: Name ID format, attributes, signing and encryption, or import your SP metadata. OIDC: confidential or public, redirect URIs, web origins and PKCE.' },
  { tag: 'Sandbox', title: 'Isolated realm', text: `Everything lives in ${sandboxRealm}, away from production identities. Break things freely: nothing reaches real users.` },
  { tag: 'Test', title: 'Test login with evidence', text: 'SAML: the Name ID, attributes, signatures and raw response. OIDC: the code exchange, ID token signature, issuer, audience, nonce and userinfo. The last 10 runs are kept per app.' },
  { tag: 'Identities', title: 'Test users', text: 'Create sandbox users with the profile your app expects, and see exactly which attributes or claims it will receive.' },
  { tag: 'Reference', title: 'Copy-ready configuration', text: 'SAML metadata and endpoints, or the OIDC issuer, discovery URL and client secret, with a sample config, one click each.' },
  { tag: 'Tools', title: 'SAML and JWT decoders', text: 'Decode a SAMLRequest or SAMLResponse, or an ID or access token, and verify a JWT signature against a JWKS. Everything runs in your browser.' },
];

export const testSteps = ({ sandboxRealm }) => [
  { who: 'CloakTail', what: 'Starts a login as your client: a SAML AuthnRequest, or an OIDC authorization request with PKCE' },
  { who: `Keycloak · ${sandboxRealm}`, what: 'Shows its sign-in page for your client' },
  { who: 'You', what: 'Sign in as one of your test users' },
  { who: 'CloakTail', what: 'Validates the signed response or tokens and shows every check' },
];

export const testIntro = 'CloakTail starts a real login with your entity ID or client ID, so Keycloak treats it exactly like your app, then shows you what came back.';

export const testLimits = 'SAML clients that require signed requests are tested from your own app, since only your app holds its private key, and encrypted assertions can be checked but not read. For OIDC, CloakTail keeps the decoded claims, never the tokens.';

// When the public copy was last reviewed. Shown on the pages and in the JSON-LD; bump it when the
// copy changes, since answer engines favour content that is visibly current.
export const updated = '2026-10-02';
export const updatedLabel = new Date(`${updated}T00:00:00Z`)
  .toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });

// Troubleshooting guides. `q`/`a` are the short FAQ on the landing page; each also has its own page
// at /troubleshooting/<slug>. Text may use `backticks` for code (see inline()).
export const problems = [
  {
    slug: 'keycloak-saml-invalid-requester',
    protocol: 'SAML',
    q: '“Invalid requester” on the Keycloak page',
    a: 'The client requires signed requests, or the entity ID your app sends doesn’t match the one you registered. The portal can’t sign for your app, so test signed requests from your app with the certificate you uploaded.',
    symptom: 'Instead of the sign-in form, Keycloak shows an error page saying “Invalid requester”. Your app never receives a SAML response.',
    causes: [
      'The `Issuer` in your app’s AuthnRequest doesn’t match the entity ID (Keycloak client ID) of any client in the sandbox realm. Typical differences: a trailing slash, `http` instead of `https`, or the entity ID of another environment.',
      'The application has “Require signed requests” turned on, and your app sent the request unsigned.',
      'Your app signed the request with a key that doesn’t match the certificate in “Your app’s signing certificate (PEM)”, for example after it generated a new key pair.',
    ],
    check: [
      'Decode the `SAMLRequest` your app sends: base64 for the HTTP-POST binding, base64 then DEFLATE for the Redirect binding. Compare its `<saml:Issuer>` with the entity ID on the application page in CloakTail, character for character.',
      'Look for a `<ds:Signature>` element in the request (POST binding) or `Signature` and `SigAlg` query parameters (Redirect binding).',
      'If the application doesn’t require signed requests, run a test login from CloakTail. It sends a request with the registered entity ID, so if it reaches the sign-in page but your app’s request doesn’t, the difference is in your app’s request.',
    ],
    fix: [
      'Make your app’s SP entity ID (issuer) exactly match the application’s entity ID.',
      'If you sign requests, paste your app’s current signing certificate into the application settings, and make sure your SAML library is configured to sign AuthnRequests.',
      'If you don’t need signed requests yet, turn off “Require signed requests” while you develop, and turn it back on before testing the final setup. While it is on, CloakTail’s test login is unavailable; the IdP-initiated login link on the application page still works.',
    ],
  },
  {
    slug: 'keycloak-saml-invalid-redirect-uri',
    protocol: 'SAML',
    q: '“Invalid redirect uri”',
    a: 'Your app sent an Assertion Consumer Service URL that isn’t registered. Correct the ACS URL in the application settings, including the scheme, host, port and path.',
    symptom: 'Keycloak shows an error page saying “Invalid redirect uri” before or instead of the sign-in form.',
    causes: [
      'The `AssertionConsumerServiceURL` in your app’s AuthnRequest isn’t one of the client’s valid redirect URIs. CloakTail registers exactly the ACS URL and logout URL you entered, without wildcards.',
      'Your app runs behind a reverse proxy or load balancer and builds its ACS URL from the internal address: `http` instead of `https`, an internal host name, or an extra port.',
      'Small differences such as `localhost` versus `127.0.0.1`, a different port, or a trailing slash.',
    ],
    check: [
      'Decode the `SAMLRequest` and compare its `AssertionConsumerServiceURL` attribute with the ACS URL on the application page.',
    ],
    fix: [
      'Correct the ACS URL in the application settings so it matches what your app sends, including scheme, host, port and path.',
      'Or fix your app’s base URL or proxy settings (for example trusting `X-Forwarded-Proto`) so it sends the registered URL.',
      'Each application has one ACS URL. If you test several environments, such as local and staging, register one application per environment.',
    ],
  },
  {
    slug: 'saml-audience-check-failed',
    protocol: 'SAML',
    q: 'Audience check failed',
    a: 'Your app validates against a different entity ID. It must match the application’s entity ID exactly, character for character.',
    symptom: 'Sign-in on Keycloak succeeds, but your app rejects the SAML response with an audience, audience restriction or “not intended for this SP” error.',
    causes: [
      'Keycloak puts the client ID, which is your application’s entity ID, in the assertion’s `<saml:Audience>`. Your app compares it with the entity ID it is configured with, and the two differ.',
      'Your app is configured for another environment, or the values differ only by a trailing slash or `http`/`https`.',
    ],
    check: [
      'Run a test login in CloakTail and read the Audience in the checks, or the `<saml:Audience>` element in the raw XML. Compare it with your app’s SP entity ID or audience setting.',
    ],
    fix: [
      'Change your app’s entity ID or audience setting to match the application’s entity ID exactly.',
      'The entity ID can’t be changed after an application is created. If the registered one is wrong, create a new application with the right entity ID and delete the old one.',
    ],
  },
  {
    slug: 'saml-signature-validation-failed-keycloak',
    protocol: 'SAML',
    q: 'Signature check failed in my app',
    a: 'Your app has the wrong IdP certificate. Configure it from the IdP metadata URL so it always uses the realm’s current signing key.',
    symptom: 'Sign-in on Keycloak succeeds, but your app rejects the SAML response with an invalid signature or “no valid signature” error.',
    causes: [
      'Your app has a different IdP certificate pinned: the one from another realm or environment, an old one from before the realm’s keys were rotated, or your own SP certificate pasted by mistake.',
      'The certificate was copied with broken line breaks or missing PEM armour.',
      'Your SAML library requires a signed assertion but only the response is signed, or the other way round.',
    ],
    check: [
      'Run a test login in CloakTail. It validates the response and assertion signatures against the sandbox realm’s current keys. If CloakTail reports both as valid but your app rejects them, the problem is the certificate or signature settings in your app.',
      'Compare the certificate configured in your app with the one in the IdP metadata.',
    ],
    fix: [
      'Configure your app from the sandbox IdP metadata URL rather than a pasted certificate, so it always uses the realm’s current signing key.',
      'Match the signing options to what your library expects: “Sign SAML responses” and “Sign assertions” are both on by default in CloakTail.',
    ],
  },
  {
    slug: 'saml-attributes-missing-keycloak',
    protocol: 'SAML',
    q: 'Expected attributes are missing',
    a: 'The test user’s profile is incomplete, or the attribute isn’t selected in the application settings. Fill in the user’s email and name, then test again.',
    symptom: 'Sign-in works, but your app is missing the user’s email, first name, last name or username.',
    causes: [
      'The attribute isn’t selected in the application settings. CloakTail sends only the selected attributes, from: `email`, `firstName`, `lastName` and `username`.',
      'The test user has no value for it. Keycloak leaves an attribute out of the assertion when the user’s profile field is empty.',
      'Your app looks for a different attribute name, such as an OID (`urn:oid:0.9.2342.19200300.100.1.3`) or a claim URI, or a different name format.',
    ],
    check: [
      'Run a test login in CloakTail and open the Attributes tab: it lists exactly the attributes Keycloak sent, with their names and values.',
    ],
    fix: [
      'Select the attributes your app needs in the application settings.',
      'Fill in the test user’s email, first name and last name, then test again.',
      'Map CloakTail’s attribute names (`email`, `firstName`, `lastName`, `username`) in your app, and choose the attribute name format your app expects (Basic, URI Reference or Unspecified).',
    ],
  },
  {
    slug: 'keycloak-oidc-invalid-redirect-uri',
    protocol: 'OIDC',
    q: '“Invalid parameter: redirect_uri”',
    a: 'Your app sent a redirect_uri that isn’t one of the client’s redirect URIs. Add the exact URI to the application, or fix the URL your app builds.',
    symptom: 'Instead of the sign-in form, Keycloak shows an error page saying “Invalid parameter: redirect_uri”. After sign-out, the same mismatch on `post_logout_redirect_uri` shows “Invalid redirect uri”.',
    causes: [
      'The `redirect_uri` in your app’s authorization request doesn’t match any redirect URI registered for the client. Keycloak compares them exactly; a `*` is only a wildcard at the end.',
      'Your app runs behind a reverse proxy or load balancer and builds the callback URL from its internal address: `http` instead of `https`, an internal host name, or an extra port.',
      'Small differences such as `localhost` versus `127.0.0.1`, a different port, or a trailing slash.',
      'On sign-out: the `post_logout_redirect_uri` isn’t in the application’s post-logout redirect URIs.',
    ],
    check: [
      'Copy the authorization URL your app opens (the browser address bar, or the network tab of the developer tools), URL-decode its `redirect_uri` parameter, and compare it with the redirect URIs on the application page in CloakTail, character for character.',
    ],
    fix: [
      'Add the exact URI your app sends to the application’s redirect URIs. While developing, a trailing wildcard such as `http://localhost:5173/*` is allowed.',
      'Or fix your app’s base URL or proxy settings (for example trusting `X-Forwarded-Proto`) so it sends the registered URI.',
      'For sign-out, add your app’s post-logout page to the post-logout redirect URIs and send `id_token_hint` with the logout request.',
    ],
  },
  {
    slug: 'keycloak-oidc-invalid-client-credentials',
    protocol: 'OIDC',
    q: '“invalid_client” or “unauthorized_client” from the token endpoint',
    a: 'Your app authenticates with the wrong client ID or secret, or as the wrong client type. Copy the client ID and the current secret from the application page.',
    symptom: 'Sign-in on Keycloak succeeds, but your app’s code exchange fails: HTTP 401 with `invalid_client` (“Invalid client or Invalid client credentials”), or HTTP 400 with `unauthorized_client`.',
    causes: [
      'The client secret in your app is out of date, for example after the secret was regenerated, or it belongs to another environment.',
      'The client is confidential but your app is configured as a public client and sends no secret, or the other way round.',
      'A typo in the client ID, or your app is pointed at a different realm.',
      'Your app uses the client credentials grant, but the application’s service account is off (`unauthorized_client`).',
    ],
    check: [
      'Run a test login in CloakTail. It redeems the code with the application’s current credentials. If the test passes but your app fails, the client is fine and the credentials in your app are wrong.',
      'Compare your app’s client ID, client secret and token endpoint with the application page.',
    ],
    fix: [
      'Copy the client ID and secret from the application page into your app’s configuration, and keep the secret server-side.',
      'Match the client type: confidential for server-side apps that keep a secret, public for single-page and native apps, which use PKCE instead.',
      'For machine-to-machine calls, turn on “Service account” in the application settings.',
    ],
  },
  {
    slug: 'keycloak-oidc-pkce-missing-code-challenge',
    protocol: 'OIDC',
    q: '“Missing parameter: code_challenge_method”',
    a: 'The client requires PKCE but your app didn’t send a code challenge. Turn on PKCE with S256 in your OIDC library, or turn off “Require PKCE” while you develop.',
    symptom: 'Keycloak redirects back to your app with `error=invalid_request` and “Missing parameter: code_challenge_method”, or the code exchange later fails with `invalid_grant` and “PKCE verification failed”.',
    causes: [
      'The application has “Require PKCE (S256)” on, and your app’s authorization request has no `code_challenge` and `code_challenge_method=S256`.',
      'Your app sends the `plain` method, which the client doesn’t accept.',
      'Your app sends a challenge but redeems the code with a different `code_verifier`, typically because it lost the verifier between redirect and callback: a new session, a second browser tab, or a server instance without shared sessions.',
    ],
    check: [
      'Look for `code_challenge` and `code_challenge_method` in the authorization URL your app opens, and for `code_verifier` in its token request.',
      'Run a test login in CloakTail: it always uses PKCE with S256, so it shows whether the client itself works.',
    ],
    fix: [
      'Enable PKCE with S256 in your OIDC library, and store the verifier in the user’s session until the callback.',
      'If your library can’t do PKCE yet, turn off “Require PKCE” in the application settings while you develop. Keep it on for public clients.',
    ],
  },
  {
    slug: 'keycloak-oidc-invalid-grant-code-not-valid',
    protocol: 'OIDC',
    q: '“invalid_grant: Code not valid”',
    a: 'The authorization code was already used, has expired, or is redeemed with a different redirect_uri or client. Exchange each code once, straight away, with the same redirect_uri.',
    symptom: 'Sign-in on Keycloak succeeds, but your app’s token request fails with HTTP 400 `invalid_grant`, and “Code not valid”, “Incorrect redirect_uri” or “Session not active”.',
    causes: [
      'The code was redeemed twice: the callback ran twice (a page refresh, a double request, or a framework that runs effects twice in development). Codes are single-use.',
      'The code expired. Keycloak gives about a minute; a paused debugger or a slow callback is enough.',
      'The token request’s `redirect_uri` differs from the one in the authorization request (“Incorrect redirect_uri”).',
      'The code is redeemed with a different client ID than the one that requested it.',
    ],
    check: [
      'Log your app’s callback and token request: how often it runs, how long after the redirect, and the `redirect_uri` and `client_id` it sends.',
    ],
    fix: [
      'Redeem each code exactly once, immediately, and ignore repeated callbacks for a code already used.',
      'Send the same `redirect_uri` in the token request as in the authorization request, and the same client ID.',
    ],
  },
  {
    slug: 'keycloak-oidc-id-token-issuer-audience-mismatch',
    protocol: 'OIDC',
    q: 'ID token rejected: issuer or audience mismatch',
    a: 'Your app expects a different issuer or audience. The issuer is the realm URL exactly as Keycloak advertises it, and the ID token’s audience is your client ID. Configure your library from the discovery document.',
    symptom: 'Sign-in and code exchange succeed, but your app rejects the tokens with “unexpected iss”, “issuer mismatch”, “jwt audience invalid” or a similar validation error.',
    causes: [
      'Your app reaches Keycloak at a different URL than the one in the tokens, for example an internal Docker host name. Keycloak puts its public URL in `iss`, so the two never match.',
      'The configured issuer has a trailing slash, the wrong realm, or `http` instead of `https`.',
      'Your app validates the access token as if it were the ID token: Keycloak access tokens are for APIs and usually have the audience `account`, not your client ID.',
      'Your app is configured with another environment’s client ID.',
    ],
    check: [
      'Run a test login in CloakTail and read the issuer and audience checks, or paste your app’s token into the JWT decoder to see its `iss`, `aud` and `azp`.',
      'Open the realm’s discovery document (`/.well-known/openid-configuration`) and compare its `issuer` with your app’s setting.',
    ],
    fix: [
      'Set your app’s issuer to the `issuer` from the discovery document, exactly, and let your library read the endpoints and keys from there.',
      'Validate the ID token against your client ID. Validate access tokens in the API that receives them, with that API’s audience.',
      'If your app must call Keycloak at an internal URL, configure Keycloak’s hostname so tokens always carry one public issuer.',
    ],
  },
];

export const findProblem = (slug) => problems.find((p) => p.slug === slug) || null;

export const PROTOCOL_NAMES = { SAML: 'SAML 2.0', OIDC: 'OpenID Connect' };
// Troubleshooting guides grouped by protocol, in display order: [{ protocol, name, problems }].
export const problemGroups = () => Object.entries(PROTOCOL_NAMES).map(([protocol, name]) => ({
  protocol, name, problems: problems.filter((p) => p.protocol === protocol),
}));

// Ways to test a Keycloak SAML or OIDC integration, compared fairly: the alternatives are often the
// better choice, and saying when is what makes the comparison worth citing.
export const alternatives = [
  {
    name: 'Hosted mock IdP or debugger',
    examples: 'such as mocksaml.com, SAMLtest.id or oidcdebugger.com',
    bestFor: 'Checking that your SAML or OIDC library works at all, in minutes and without an account.',
    tradeoff: 'It isn’t Keycloak. Your users will sign in through your organization’s Keycloak, with its own signing keys, Name ID formats, mappers, token claims and error pages, and a generic provider won’t reproduce those.',
  },
  {
    name: 'Keycloak on your laptop',
    examples: 'for example in Docker',
    bestFor: 'Full control, offline work, and learning Keycloak administration.',
    tradeoff: 'You set up the realm, clients, mappers and users yourself, read SAML responses and tokens with browser tools, and your configuration can drift from your organization’s.',
  },
  {
    name: 'A ticket to your identity team',
    examples: 'for a client in a shared test realm',
    bestFor: 'Onboarding to production, where an administrator should review the configuration.',
    tradeoff: 'Every change waits for someone else, and you usually can’t see what Keycloak sent or why a login failed.',
  },
  {
    name: 'CloakTail',
    examples: 'your organization’s Keycloak, self-service',
    bestFor: 'Developers integrating an app with their organization’s Keycloak, who want to change the client themselves and see every check of a real login.',
    tradeoff: 'OIDC clients get the realm’s default scopes and claims, without custom mappers. SAML clients that require signed requests are tested from your own app, encrypted assertions can be checked but not read, and the sandbox is for testing, not production.',
  },
];

const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Copy text as HTML: escaped, with `backticks` as <code>.
export const inline = (text) => escapeHtml(text).replace(/`([^`]+)`/g, '<code>$1</code>');

export const registration = ({ maxApps, maxTestUsers }) => [
  { q: 'Who can register', a: 'Developers building apps that sign in through Keycloak. Use your work email.' },
  { q: 'What you need', a: 'A username (3–40 lowercase letters, digits, . _ -), your name, and a password of at least 8 characters. The realm’s password policy may add rules.' },
  { q: 'What you get', a: `The developer role: up to ${maxApps} SAML or OIDC clients and ${maxTestUsers} test users in the sandbox, plus the certificate generator.` },
  { q: 'Before you start', a: 'You’ll be asked to accept the disclaimer: the sandbox is for testing only, so never use real personal data.' },
];

const plainQuotes = (s) => s.replace(/[“”]/g, '"');
const origin = (url) => url.replace(/\/+$/, '');

// schema.org data for the landing page: what CloakTail is, the quickstart, and the FAQ.
export function structuredData(ctx, url) {
  return [
    {
      '@context': 'https://schema.org',
      '@type': 'SoftwareApplication',
      name: 'CloakTail',
      url,
      applicationCategory: 'DeveloperApplication',
      applicationSubCategory: 'SAML and OpenID Connect single sign-on testing',
      operatingSystem: 'Web',
      isAccessibleForFree: true,
      dateModified: updated,
      description: summary,
      featureList: features(ctx).map((f) => `${f.title}: ${f.text}`),
      keywords: keywords.join(', '),
    },
    {
      '@context': 'https://schema.org',
      '@type': 'HowTo',
      name: 'Test a SAML or OpenID Connect integration against Keycloak with CloakTail',
      totalTime: 'PT5M',
      step: quickstart(ctx).map((s, i) => ({
        '@type': 'HowToStep',
        position: i + 1,
        name: s.title,
        text: s.text,
        url: `${origin(url)}/#quickstart`,
      })),
    },
    {
      '@context': 'https://schema.org',
      '@type': 'FAQPage',
      mainEntity: problems.map((p) => ({
        '@type': 'Question',
        name: plainQuotes(p.q),
        url: `${origin(url)}/troubleshooting/${p.slug}`,
        acceptedAnswer: { '@type': 'Answer', text: p.a },
      })),
    },
  ];
}

// schema.org data for one troubleshooting page.
export function problemStructuredData(problem, baseUrl) {
  const url = `${baseUrl}/troubleshooting/${problem.slug}`;
  return [
    {
      '@context': 'https://schema.org',
      '@type': 'TechArticle',
      headline: `${plainQuotes(problem.q)}: causes and fixes for Keycloak ${problem.protocol}`,
      description: problem.a,
      url,
      dateModified: updated,
      about: ['Keycloak', PROTOCOL_NAMES[problem.protocol]],
      publisher: { '@type': 'Organization', name: 'CloakTail', url: baseUrl },
    },
    {
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'CloakTail', item: `${baseUrl}/` },
        { '@type': 'ListItem', position: 2, name: 'Troubleshooting', item: `${baseUrl}/troubleshooting` },
        { '@type': 'ListItem', position: 3, name: plainQuotes(problem.q), item: url },
      ],
    },
  ];
}

// One troubleshooting guide as Markdown, under a heading of the given level.
function problemMarkdown(p, level, baseUrl) {
  const h = '#'.repeat(level);
  const list = (items) => items.map((t) => `- ${t}`);
  return [
    `${h} ${plainQuotes(p.q)}`, '',
    `Source: ${baseUrl}/troubleshooting/${p.slug}`, '',
    p.a, '',
    `**What you see:** ${p.symptom}`, '',
    `${h}# Why it happens`, '', ...list(p.causes), '',
    `${h}# How to confirm`, '', ...list(p.check), '',
    `${h}# How to fix it`, '', ...list(p.fix), '',
  ];
}

// Markdown for answer engines (https://llmstxt.org). `full` adds every section of the landing page
// and the full troubleshooting guides. `sandbox` carries the live IdP URLs, empty until Keycloak
// is configured.
export function llmsText({ baseUrl, sandbox, registrationEnabled, full, ...ctx }) {
  const link = (path) => `${baseUrl}${path}`;
  const lines = [`# CloakTail`, '', `> ${summary}`, ''];
  lines.push(
    'CloakTail runs an isolated Keycloak sandbox realm for testing. It is for development and testing only: never use real personal data or production credentials there.',
    '',
    `Last updated: ${updated}`,
    '',
  );
  if (sandbox.descriptorUrl) {
    lines.push(
      '## Sandbox identity provider',
      '',
      `- SAML IdP metadata URL: ${sandbox.descriptorUrl}`,
      `- SAML IdP entity ID: ${sandbox.realmUrl}`,
      `- SAML SSO / SLO URL (HTTP-POST and Redirect bindings): ${sandbox.samlEndpoint}`,
      ...(sandbox.oidc?.issuer ? [
        `- OpenID Connect issuer: ${sandbox.oidc.issuer}`,
        `- OpenID Connect discovery document: ${sandbox.oidc.discoveryUrl}`,
        `- JWKS (token signing keys): ${sandbox.oidc.jwksUri}`,
      ] : []),
      '',
    );
  }
  const tools = [
    `- [SAML decoder](${link('/tools/decode')}): decode a SAMLRequest or SAMLResponse (HTTP-POST or Redirect binding) into readable XML, in the browser`,
    `- [JWT decoder](${link('/tools/decode/jwt')}): decode an ID token or access token and verify its signature against a JWKS, PEM public key or secret, in the browser`,
  ];
  // Troubleshooting guides under one ### heading per protocol; render(problem) gives its lines.
  const troubleshooting = (render) => problemGroups().flatMap((g) => {
    const items = g.problems.flatMap(render);
    return [`### ${g.name}`, '', ...items, ...(items.at(-1) === '' ? [] : [''])];
  });

  if (!full) {
    lines.push(
      '## Docs',
      '',
      `- [Full product guide](${link('/llms-full.txt')}): features, quickstart, how test logins work, comparison with other ways to test, registration and every troubleshooting guide, in one Markdown file`,
      `- [Product page](${link('/')}): the same content as HTML`,
      `- [Disclaimer](${link('/disclaimer')}): terms for using the sandbox`,
      '',
      '## Tools',
      '',
      ...tools,
      '',
      '## Troubleshooting Keycloak SAML and OIDC errors',
      '',
      ...troubleshooting((p) => [`- [${plainQuotes(p.q)}](${link(`/troubleshooting/${p.slug}`)}): ${p.a}`]),
      '## Get started',
      '',
      ...(registrationEnabled ? [`- [Create a developer account](${link('/register')})`] : []),
      `- [Sign in](${link('/login')})`,
      '',
    );
    return lines.join('\n');
  }

  lines.push('## Quickstart', '', 'From zero to a verified login in four steps, about 5 minutes in total.', '');
  quickstart(ctx).forEach((s, i) => lines.push(`${i + 1}. **${s.title}** (${s.time}): ${s.text}`));
  lines.push('', '## Features', '');
  for (const f of features(ctx)) lines.push(`- **${f.title}**: ${f.text}`);
  lines.push('', '## How a test login works', '', testIntro, '');
  testSteps(ctx).forEach((s, i) => lines.push(`${i + 1}. ${s.who}: ${s.what}`));
  lines.push('', testLimits, '', '## Tools', '', ...tools, '', '## Ways to test a Keycloak SAML or OIDC integration', '');
  for (const alt of alternatives) {
    lines.push(`### ${alt.name} (${alt.examples})`, '', `- **Best for:** ${alt.bestFor}`, `- **Trade-off:** ${alt.tradeoff}`, '');
  }
  lines.push('## Registration', '');
  if (!registrationEnabled) lines.push('Self-registration is currently closed; ask an administrator for an account.', '');
  for (const r of registration(ctx)) lines.push(`- **${r.q}**: ${r.a}`);
  lines.push('', '## Troubleshooting', '', ...troubleshooting((p) => problemMarkdown(p, 4, baseUrl)));
  lines.push('## Links', '');
  if (registrationEnabled) lines.push(`- [Create a developer account](${link('/register')})`);
  lines.push(`- [Sign in](${link('/login')})`, `- [Disclaimer](${link('/disclaimer')})`, '');
  return lines.join('\n');
}
