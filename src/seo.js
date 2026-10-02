// Crawler files: robots.txt, sitemap.xml, llms.txt and llms-full.txt. Served live by app.js and
// written to disk by `npm run seo:export`, from the same code.
import { config } from './config.js';
import * as content from './content.js';

// The public pages search engines may index; everything else is noindex (see app.js).
export const indexedPaths = ({ registrationEnabled = config.registration.enabled } = {}) => [
  '/', '/troubleshooting', ...content.problems.map((p) => `/troubleshooting/${p.slug}`), '/tools/decode', '/disclaimer',
  ...(registrationEnabled ? ['/register'] : []),
];

// AI search and answer engines are named explicitly so they're clearly welcome on the public pages.
// To opt out of AI training only, give GPTBot, Google-Extended, CCBot and ClaudeBot their own
// group with "Disallow: /" and keep the search bots (OAI-SearchBot, Claude-SearchBot, ...) here.
const aiCrawlers = [
  'GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Claude-SearchBot', 'Claude-User',
  'PerplexityBot', 'Perplexity-User', 'Google-Extended', 'Applebot-Extended', 'CCBot', 'Bingbot',
];

export const robotsText = ({ baseUrl = config.baseUrl } = {}) => [
  'User-agent: *',
  ...aiCrawlers.map((bot) => `User-agent: ${bot}`),
  'Allow: /llms.txt',
  'Allow: /llms-full.txt',
  'Disallow: /admin',
  'Disallow: /auth/',
  'Disallow: /saml/',
  '',
  `Sitemap: ${baseUrl}/sitemap.xml`,
  '',
].join('\n');

export function sitemapXml({ baseUrl = config.baseUrl, registrationEnabled } = {}) {
  const urls = indexedPaths({ registrationEnabled })
    .map((p) => `  <url><loc>${baseUrl}${p}</loc><lastmod>${content.updated}</lastmod></url>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
}

// Markdown for answer engines (https://llmstxt.org). `sandbox` is the IdP URLs of the profile
// serving the request.
export const llmsText = ({ full, baseUrl = config.baseUrl, sandbox = config.sandbox } = {}) => content.llmsText({
  baseUrl,
  sandbox,
  sandboxRealm: sandbox.realm || 'sandbox',
  registrationEnabled: config.registration.enabled,
  maxApps: config.sandbox.maxAppsPerDeveloper,
  maxTestUsers: config.sandbox.maxTestUsersPerDeveloper,
  full,
});
