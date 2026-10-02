import app from './app.js';
import { config } from './config.js';
import { bootstrapAdmin } from './adminSetup.js';
import { listSpKeysViews } from './spKeys.js';
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
  // Each profile in use signs with its own key.
  const spKeys = await listSpKeysViews();
  const inUse = new Map(tenants.map((t) => [t.profileId, t.profileName]));
  for (const [profileId, name] of inUse) {
    const active = spKeys.get(profileId)?.active;
    const page = `${config.baseUrl}/admin/keycloak/profiles/${profileId}/signing`;
    if (!active) {
      console.warn(`Keycloak profile "${name}" has no SAML signing certificate: sign-in on its domains is unavailable until an administrator creates one at ${page}.`);
    } else if (active.daysLeft < 30) {
      console.warn(`The SAML signing certificate of Keycloak profile "${name}" ${active.daysLeft < 0 ? 'has expired' : `expires in ${active.daysLeft} days`} (${active.validTo}). Replace it at ${page}.`);
    }
  }
  // First administrator from ADMIN_BOOTSTRAP_* or, failing that, a setup token for /admin/setup.
  await bootstrapAdmin().catch((err) => console.error('Admin bootstrap failed:', err));
});
