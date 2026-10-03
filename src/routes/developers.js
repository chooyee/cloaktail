import express from 'express';
import { agentGuide } from '../api/agentGuide.js';
import { endpointGroups } from '../api/openapi.js';
import { renderMarkdown } from '../lib/markdown.js';
import { SCOPES, TOKEN_TTL_S } from '../lib/apiCredentials.js';
import * as dev from '../developersContent.js';

// Public pages about the developer REST API (routes/api.js), for people and search engines:
// /developers (what it does, setup, the agent guide) and /developers/api (the endpoint reference,
// rendered on the server from the OpenAPI document, and Swagger UI to try calls). Coding agents read
// the same guide as Markdown at /api/v1/agent.md and the schemas at /api/v1/openapi.json; both pages
// point to them with <link rel> so agents that land here find them.
export const developersRouter = express.Router();

const headLinks = [
  { rel: 'service-desc', type: 'application/openapi+json', href: '/api/v1/openapi.json', title: 'CloakTail developer API (OpenAPI 3.1)' },
  { rel: 'alternate', type: 'text/markdown', href: '/api/v1/agent.md', title: 'Agent guide (Markdown)' },
];

developersRouter.get('/', (req, res) => {
  // The page has its own title and intro: drop the guide's H1 and nest its sections under the page's.
  const guide = renderMarkdown(agentGuide().replace(/^# .*\n+/, ''), { shiftHeadings: 1 });
  res.render('pages/developers/index', {
    title: dev.devTitle,
    description: dev.devDescription,
    keywords: dev.devKeywords,
    structuredData: dev.devStructuredData(req.siteUrl),
    headLinks,
    ...dev,
    guideHtml: guide.html,
    toc: guide.headings.filter((h) => h.depth === 2),
    SCOPES,
    siteUrl: req.siteUrl,
  });
});

developersRouter.get('/api', (req, res) => {
  const groups = endpointGroups();
  res.render('pages/developers/api', {
    title: 'API reference: Keycloak OIDC and SAML client API',
    description: 'Every CloakTail API endpoint: register Keycloak OIDC and SAML clients, read secrets, migrate users and test logins. OpenAPI 3.1, with a live console.',
    keywords: dev.devKeywords,
    structuredData: dev.apiStructuredData(req.siteUrl),
    headLinks,
    groups,
    endpointCount: groups.reduce((n, g) => n + g.endpoints.length, 0),
    tokenMinutes: TOKEN_TTL_S / 60,
    apiUrl: `${req.siteUrl}/api/v1`,
  });
});
