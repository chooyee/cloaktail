import crypto from 'node:crypto';
import { config } from './config.js';
import { ADMIN_USERNAME_RE, countAdminAccounts, createFirstAdminAccount } from './db.js';
import { hashPassword, passwordProblem } from './lib/password.js';

// First administrator, Keycloak-style: either from ADMIN_BOOTSTRAP_USERNAME/PASSWORD at startup
// (unattended Docker deploys), or from the /admin/setup page while no administrator exists.
// The setup page asks for a one-time token printed to the server log, so whoever first reaches
// the URL can't claim the console (a localhost check doesn't hold behind Docker or a proxy).

let setupToken = null;

export const setupRequired = async () => (await countAdminAccounts()) === 0;

// Generated on first need and printed once; kept in memory, so a restart issues a new one.
export async function ensureSetupToken() {
  if (setupToken || !(await setupRequired())) return;
  setupToken = crypto.randomBytes(18).toString('base64url');
  console.log([
    '',
    '================================================================',
    ' No CloakTail administrator exists yet. Create one at:',
    `   ${config.baseUrl}/admin/setup`,
    ` Setup token: ${setupToken}`,
    '================================================================',
    '',
  ].join('\n'));
}

export function setupTokenMatches(value) {
  if (!setupToken) return false;
  const digest = (v) => crypto.createHash('sha256').update(String(v)).digest();
  return crypto.timingSafeEqual(digest(value), digest(setupToken));
}

export function finishSetup() {
  setupToken = null;
}

// Called once at startup.
export async function bootstrapAdmin() {
  if (!(await setupRequired())) return;
  const username = (process.env.ADMIN_BOOTSTRAP_USERNAME || '').trim().toLowerCase();
  const password = process.env.ADMIN_BOOTSTRAP_PASSWORD || '';
  if (username || password) {
    const problem = ADMIN_USERNAME_RE.test(username)
      ? passwordProblem(password, username)
      : 'username must be 3-40 lowercase letters, digits, dots, dashes or underscores.';
    if (problem) {
      console.error(`ADMIN_BOOTSTRAP_USERNAME/PASSWORD ignored: ${problem}`);
    } else if (await createFirstAdminAccount({
      username,
      passwordHash: await hashPassword(password),
      createdBy: 'bootstrap',
      // The password sits in the environment, so it is treated as temporary.
      mustChangePassword: true,
    })) {
      console.log(`Created administrator "${username}" from ADMIN_BOOTSTRAP_USERNAME. They must change the password at first sign-in.`);
      return;
    }
  }
  await ensureSetupToken();
}
