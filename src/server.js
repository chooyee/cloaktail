import app from './app.js';
import { config } from './config.js';
import { bootstrapAdmin } from './adminSetup.js';
import { getSpKeysView } from './spKeys.js';

app.listen(config.port, async () => {
  console.log(`App listening on ${config.baseUrl}`);
  if (!config.keycloak.configured) {
    console.warn(`No active Keycloak profile: sign-in is unavailable until an administrator activates one at ${config.baseUrl}/admin/keycloak.`);
  } else if (!config.keycloak.adminClientSecret) {
    console.warn('The active Keycloak profile has no portal service account secret: sign-up and user pages will fail.');
  }
  const { active } = getSpKeysView();
  if (!active) {
    console.warn(`No SAML signing certificate: sign-in is unavailable until an administrator creates one at ${config.baseUrl}/admin/signing.`);
  } else if (active.daysLeft < 30) {
    console.warn(`The SAML signing certificate ${active.daysLeft < 0 ? 'has expired' : `expires in ${active.daysLeft} days`} (${active.validTo}). Replace it at ${config.baseUrl}/admin/signing.`);
  }
  // First administrator from ADMIN_BOOTSTRAP_* or, failing that, a setup token for /admin/setup.
  await bootstrapAdmin().catch((err) => console.error('Admin bootstrap failed:', err));
});
