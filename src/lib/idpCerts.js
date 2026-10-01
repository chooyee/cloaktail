// Reads a realm's SAML signing certificate(s) from its descriptor, cached for an hour per URL,
// so a Keycloak key rotation is picked up without an app restart.
const cache = new Map(); // descriptorUrl -> { certs, fetchedAt }

export async function loadIdpCerts(descriptorUrl) {
  const hit = cache.get(descriptorUrl);
  if (hit && Date.now() - hit.fetchedAt < 3600_000) return hit.certs;
  const certs = await fetchIdpCerts(descriptorUrl);
  cache.set(descriptorUrl, { certs, fetchedAt: Date.now() });
  return certs;
}

// Uncached; used directly by the admin console's connection test.
export async function fetchIdpCerts(descriptorUrl, { signal } = {}) {
  const res = await fetch(descriptorUrl, { signal });
  if (!res.ok) throw new Error(`Failed to fetch Keycloak SAML descriptor ${descriptorUrl} (${res.status})`);
  const xml = await res.text();
  const certs = [...xml.matchAll(/<md:KeyDescriptor use="signing">([\s\S]*?)<\/md:KeyDescriptor>/g)]
    .flatMap((m) => [...m[1].matchAll(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g)].map((c) => c[1].trim()));
  if (!certs.length) throw new Error(`No signing certificate found in ${descriptorUrl}`);
  return certs;
}

// node-saml accepts a callback for idpCert; this adapts loadIdpCerts to it.
// (node-saml promisifies it, so it must not itself return a Promise.)
export const idpCertCallback = (descriptorUrl) => (callback) => {
  loadIdpCerts(descriptorUrl).then((certs) => callback(null, certs), (err) => callback(err));
};
