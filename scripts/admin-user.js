// Recovery tool for admin console accounts (/admin). The first administrator is created on the
// /admin/setup page or from ADMIN_BOOTSTRAP_USERNAME/PASSWORD, not here.
// In Docker: docker exec <container> npm run admin -- reset <username>
//
//   npm run admin -- reset <username>    new temporary password, unlocks the account, ends its sessions
//   npm run admin -- list
import { getAdminAccount, setAdminPassword, listAdminAccounts, closeDb } from '../src/db.js';
import { hashPassword, temporaryPassword } from '../src/lib/password.js';

const [command, rawUsername = ''] = process.argv.slice(2);
const username = rawUsername.trim().toLowerCase();

if (command === 'list') {
  const accounts = await listAdminAccounts();
  if (!accounts.length) console.log('No administrators yet. Open /admin/setup and use the setup token from the server log.');
  for (const a of accounts) {
    const locked = a.locked_until && Date.parse(a.locked_until) > Date.now();
    console.log(`${a.username}\tlast sign-in: ${a.last_login_at || 'never'}${locked ? '\tLOCKED' : ''}${a.must_change_password ? '\tmust change password' : ''}`);
  }
} else if (command === 'reset' && username) {
  if (!(await getAdminAccount(username))) {
    console.error(`No administrator "${username}". Run: npm run admin -- list`);
    process.exit(1);
  }
  const password = temporaryPassword();
  await setAdminPassword(username, await hashPassword(password), { mustChangePassword: true });
  console.log(`Reset the password of "${username}" and signed out their sessions.`);
  console.log(`Temporary password: ${password}`);
  console.log('It must be changed at the next sign-in, at /admin/login.');
} else {
  console.log('Usage: npm run admin -- reset <username> | list');
  process.exit(1);
}
await closeDb();
