import app from './app.js';
import { config } from './config.js';
import { bootstrapAdmin } from './adminSetup.js';
import { getSpKeysView } from './spKeys.js';
import { listTenants } from './keycloakProfiles.js';

app.listen(config.port, async () => {
  console.log(`App listening on ${config.baseUrl}`);
  const tenants = listTenants();
  if (!tenants.length) {
    console.warn(`No Keycloak profile serves any domain: the portal is unavailable until an administrator assigns one at ${config.baseUrl}/admin/keycloak.`);
  }
  for (const t of tenants) {
    console.log(`  ${t.siteUrl} -> Keycloak profile "${t.profileName}"${t.keycloak.adminClientSecret ? '' : ' (no portal service account secret: sign-up and user pages will fail)'}`);
  }
  const { active } = await getSpKeysView();
  if (!active) {
    console.warn(`No SAML signing certificate: sign-in is unavailable until an administrator creates one at ${config.baseUrl}/admin/signing.`);
  } else if (active.daysLeft < 30) {
    console.warn(`The SAML signing certificate ${active.daysLeft < 0 ? 'has expired' : `expires in ${active.daysLeft} days`} (${active.validTo}). Replace it at ${config.baseUrl}/admin/signing.`);
  }
  // First administrator from ADMIN_BOOTSTRAP_* or, failing that, a setup token for /admin/setup.
  await bootstrapAdmin().catch((err) => console.error('Admin bootstrap failed:', err));
});
