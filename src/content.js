// Public product copy, shared by the landing page, /llms.txt, /llms-full.txt and the JSON-LD, so
// search engines, answer engines and people all read the same facts.

export const tagline = 'SAML SSO, tested before you ship.';

export const summary = 'CloakTail is the self-service developer portal for Keycloak SAML. Developers register a SAML client in an isolated sandbox realm, sign in as a test user, and inspect every assertion before their app goes near production.';

export const facts = ['SAML 2.0', 'Keycloak', 'HTTP-POST & Redirect bindings', 'RSA-SHA256 signatures', 'Metadata import', 'Isolated sandbox realm'];

// `ctx` holds the runtime values the copy mentions: { sandboxRealm, maxApps, maxTestUsers }.
export const quickstart = ({ sandboxRealm }) => [
  { title: 'Create your account', time: '1 min', text: 'Register as a developer, then sign in with Keycloak.', href: '/register', link: 'Sign up' },
  { title: 'Add a test user', time: '1 min', text: `A made-up identity in the ${sandboxRealm} sandbox to sign in with.`, href: '/test-users', link: 'Test users' },
  { title: 'Register your SAML client', time: '2 min', text: 'Enter your entity ID and ACS URL, or import your SP metadata.', href: '/apps/new', link: 'New application' },
  { title: 'Test end to end', time: '1 min', text: 'Run a test login and inspect every check, attribute and signature.', href: '/apps', link: 'Applications' },
];

export const features = ({ sandboxRealm }) => [
  { tag: 'Self-service', title: 'SAML clients on demand', text: 'Create, edit and delete your own Keycloak SAML clients. Name ID format, attributes, signing and encryption are all set from a form.' },
  { tag: 'Import', title: 'SP metadata import', text: 'Paste or upload your app’s metadata XML. Keycloak converts it and the portal pre-fills the form for you to review.' },
  { tag: 'Sandbox', title: 'Isolated realm', text: `Everything lives in ${sandboxRealm}, away from production identities. Break things freely: nothing reaches real users.` },
  { tag: 'Test', title: 'Test login with evidence', text: 'Pass/fail checks, the Name ID, session index, attributes and the raw response, with the last 10 runs kept per app.' },
  { tag: 'Identities', title: 'Test users', text: 'Create sandbox users with the profile your app expects, and see exactly which attributes it will receive.' },
  { tag: 'Reference', title: 'Copy-ready configuration', text: 'Metadata URL, entity ID, SSO and SLO endpoints, the signing certificate and a sample config, one click each.' },
];

export const testSteps = ({ sandboxRealm }) => [
  { who: 'CloakTail', what: 'Sends an AuthnRequest as your entity ID' },
  { who: `Keycloak · ${sandboxRealm}`, what: 'Shows its sign-in page for your client' },
  { who: 'You', what: 'Sign in as one of your test users' },
  { who: 'CloakTail', what: 'Validates the signed response and shows every check' },
];

export const testIntro = 'CloakTail sends a real AuthnRequest with your entity ID, so Keycloak treats it exactly like your app, then shows you what came back.';

export const testLimits = 'Clients that require signed requests are tested from your own app, since only your app holds its private key. Encrypted assertions can be checked but not read by CloakTail.';

// When the public copy was last reviewed. Shown on the pages and in the JSON-LD; bump it when the
// copy changes, since answer engines favour content that is visibly current.
export const updated = '2026-10-01';
export const updatedLabel = new Date(`${updated}T00:00:00Z`)
  .toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });

// Troubleshooting guides. `q`/`a` are the short FAQ on the landing page; each also has its own page
// at /troubleshooting/<slug>. Text may use `backticks` for code (see inline()).
export const problems = [
  {
    slug: 'keycloak-saml-invalid-requester',
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
];

export const findProblem = (slug) => problems.find((p) => p.slug === slug) || null;

// Ways to test a Keycloak SAML integration, compared fairly: the alternatives are often the better
// choice, and saying when is what makes the comparison worth citing.
export const alternatives = [
  {
    name: 'Hosted mock IdP',
    examples: 'such as mocksaml.com or SAMLtest.id',
    bestFor: 'Checking that your SAML library works at all, in minutes and without an account.',
    tradeoff: 'It isn’t Keycloak. Your users will sign in through your organization’s Keycloak, with its own signing keys, Name ID formats, attribute mappers and error pages, and a generic IdP won’t reproduce those.',
  },
  {
    name: 'Keycloak on your laptop',
    examples: 'for example in Docker',
    bestFor: 'Full control, offline work, and learning Keycloak administration.',
    tradeoff: 'You set up the realm, client, mappers and users yourself, read SAML responses with browser tools, and your configuration can drift from your organization’s.',
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
    tradeoff: 'SAML only. Clients that require signed requests are tested from your own app, encrypted assertions can be checked but not read, and the sandbox is for testing, not production.',
  },
];

const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Copy text as HTML: escaped, with `backticks` as <code>.
export const inline = (text) => escapeHtml(text).replace(/`([^`]+)`/g, '<code>$1</code>');

export const registration = ({ maxApps, maxTestUsers }) => [
  { q: 'Who can register', a: 'Developers building apps that sign in through Keycloak. Use your work email.' },
  { q: 'What you need', a: 'A username (3–40 lowercase letters, digits, . _ -), your name, and a password of at least 8 characters. The realm’s password policy may add rules.' },
  { q: 'What you get', a: `The developer role: up to ${maxApps} SAML clients and ${maxTestUsers} test users in the sandbox, plus the certificate generator.` },
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
      applicationSubCategory: 'SAML single sign-on testing',
      operatingSystem: 'Web',
      isAccessibleForFree: true,
      dateModified: updated,
      description: summary,
      featureList: features(ctx).map((f) => `${f.title}: ${f.text}`),
      keywords: 'Keycloak, SAML 2.0, SSO, SAML testing, SAML debugger, SP metadata, identity provider sandbox',
    },
    {
      '@context': 'https://schema.org',
      '@type': 'HowTo',
      name: 'Test a SAML integration against Keycloak with CloakTail',
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
      headline: `${plainQuotes(problem.q)}: causes and fixes for Keycloak SAML`,
      description: problem.a,
      url,
      dateModified: updated,
      about: ['Keycloak', 'SAML 2.0'],
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
      `- IdP metadata URL: ${sandbox.descriptorUrl}`,
      `- IdP entity ID: ${sandbox.realmUrl}`,
      `- SSO / SLO URL (HTTP-POST and Redirect bindings): ${sandbox.samlEndpoint}`,
      '',
    );
  }

  if (!full) {
    lines.push(
      '## Docs',
      '',
      `- [Full product guide](${link('/llms-full.txt')}): features, quickstart, how test logins work, comparison with other ways to test, registration and every troubleshooting guide, in one Markdown file`,
      `- [Product page](${link('/')}): the same content as HTML`,
      `- [Disclaimer](${link('/disclaimer')}): terms for using the sandbox`,
      '',
      '## Troubleshooting Keycloak SAML errors',
      '',
      ...problems.map((p) => `- [${plainQuotes(p.q)}](${link(`/troubleshooting/${p.slug}`)}): ${p.a}`),
      '',
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
  lines.push('', testLimits, '', '## Ways to test a Keycloak SAML integration', '');
  for (const alt of alternatives) {
    lines.push(`### ${alt.name} (${alt.examples})`, '', `- **Best for:** ${alt.bestFor}`, `- **Trade-off:** ${alt.tradeoff}`, '');
  }
  lines.push('## Registration', '');
  if (!registrationEnabled) lines.push('Self-registration is currently closed; ask an administrator for an account.', '');
  for (const r of registration(ctx)) lines.push(`- **${r.q}**: ${r.a}`);
  lines.push('', '## Troubleshooting', '');
  for (const p of problems) lines.push(...problemMarkdown(p, 3, baseUrl));
  lines.push('## Links', '');
  if (registrationEnabled) lines.push(`- [Create a developer account](${link('/register')})`);
  lines.push(`- [Sign in](${link('/login')})`, `- [Disclaimer](${link('/disclaimer')})`, '');
  return lines.join('\n');
}
