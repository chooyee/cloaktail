import crypto from 'node:crypto';
import { config } from '../config.js';
import { sandboxAdmin, KeycloakError } from './keycloakAdmin.js';
import { listApps, deleteApp, listTestUsers, deleteTestUser } from '../db.js';

// Translates between the portal's "application" form and a Keycloak SAML client representation.

export const NAME_ID_FORMATS = {
  username: 'Username',
  email: 'Email',
  persistent: 'Persistent (stable opaque ID)',
  transient: 'Transient (new ID each login)',
};

export const USER_ATTRIBUTES = {
  email: 'Email',
  firstName: 'First name',
  lastName: 'Last name',
  username: 'Username',
};

export const ATTRIBUTE_NAME_FORMATS = ['Basic', 'URI Reference', 'Unspecified'];

const MAPPER_PREFIX = 'portal-attr-';

export const defaultAppValues = () => ({
  name: '',
  clientId: '',
  acsUrl: '',
  sloUrl: '',
  homeUrl: '',
  nameIdFormat: 'username',
  signDocuments: true,
  signAssertions: true,
  clientSignature: false,
  signingCert: '',
  encryptAssertions: false,
  encryptionCert: '',
  attributes: ['email', 'firstName', 'lastName'],
  attributeNameFormat: 'Basic',
});

const str = (v) => (typeof v === 'string' ? v.trim() : '');

export function parseAppForm(body) {
  return {
    name: str(body.name),
    clientId: str(body.clientId),
    acsUrl: str(body.acsUrl),
    sloUrl: str(body.sloUrl),
    homeUrl: str(body.homeUrl),
    nameIdFormat: str(body.nameIdFormat),
    signDocuments: body.signDocuments === 'on',
    signAssertions: body.signAssertions === 'on',
    clientSignature: body.clientSignature === 'on',
    signingCert: str(body.signingCert),
    encryptAssertions: body.encryptAssertions === 'on',
    encryptionCert: str(body.encryptionCert),
    attributes: [].concat(body.attributes ?? []).filter((a) => a in USER_ATTRIBUTES),
    attributeNameFormat: str(body.attributeNameFormat),
  };
}

function checkUrl(value, label, { required = false } = {}) {
  if (!value) return required ? `${label} is required.` : null;
  let url;
  try { url = new URL(value); } catch { return `${label} must be a full URL, e.g. https://myapp.example.com/saml/acs`; }
  if (!['http:', 'https:'].includes(url.protocol)) return `${label} must start with http:// or https://`;
  if (value.includes('*')) return `${label} cannot contain wildcards.`;
  if (url.hash) return `${label} cannot contain a # fragment.`;
  return null;
}

// Accepts PEM or bare base64 and returns bare base64 (what Keycloak stores), or null if invalid.
export function normalizeCert(value) {
  const body = value.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
  if (!body) return null;
  try {
    new crypto.X509Certificate(`-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`);
    return body;
  } catch {
    return null;
  }
}

// Validates and normalizes in place. Returns an error message or null.
export function validateApp(values, { isNew }) {
  if (!values.name || values.name.length > 80) return 'Application name is required (max 80 characters).';
  if (isNew) {
    if (!values.clientId || values.clientId.length > 255 || !/^[\x21-\x7e]+$/.test(values.clientId)) {
      return 'Entity ID is required: up to 255 printable characters, no spaces (often a URL like https://myapp.example.com/saml).';
    }
  }
  const urlError = checkUrl(values.acsUrl, 'ACS URL', { required: true })
    || checkUrl(values.sloUrl, 'Logout URL') || checkUrl(values.homeUrl, 'Home URL');
  if (urlError) return urlError;
  if (!(values.nameIdFormat in NAME_ID_FORMATS)) return 'Choose a Name ID format.';
  if (!ATTRIBUTE_NAME_FORMATS.includes(values.attributeNameFormat)) return 'Choose an attribute name format.';
  if (!values.signDocuments && !values.signAssertions) {
    return 'Keycloak must sign the response, the assertion, or both; otherwise your app cannot trust it.';
  }
  if (values.clientSignature) {
    const cert = normalizeCert(values.signingCert);
    if (!cert) return 'Paste a valid X.509 signing certificate (PEM) for your app, or turn off "Require signed requests".';
    values.signingCert = cert;
  }
  if (values.encryptAssertions) {
    const cert = normalizeCert(values.encryptionCert);
    if (!cert) return 'Paste a valid X.509 encryption certificate (PEM) for your app, or turn off encryption.';
    values.encryptionCert = cert;
  }
  return null;
}

function mapperFor(attribute, nameFormat) {
  return {
    name: MAPPER_PREFIX + attribute,
    protocol: 'saml',
    protocolMapper: 'saml-user-property-mapper',
    config: {
      'user.attribute': attribute,
      'attribute.name': attribute,
      'friendly.name': attribute,
      'attribute.nameformat': nameFormat,
    },
  };
}

function toClientRep(values, owner) {
  // Valid redirect URIs gate which ACS/logout URLs Keycloak will post to. The portal's test ACS
  // is always included, on every domain, so "Test connection" works.
  const redirectUris = [...new Set([values.acsUrl, values.sloUrl, ...config.sandbox.testAcsUrls].filter(Boolean))];
  return {
    name: values.name,
    description: `Developer portal application owned by ${owner}`,
    protocol: 'saml',
    enabled: true,
    frontchannelLogout: true,
    baseUrl: values.homeUrl || '',
    redirectUris,
    attributes: {
      saml_assertion_consumer_url_post: values.acsUrl,
      saml_single_logout_service_url_post: values.sloUrl,
      saml_single_logout_service_url_redirect: values.sloUrl,
      saml_name_id_format: values.nameIdFormat,
      saml_force_name_id_format: 'true',
      'saml.server.signature': String(values.signDocuments),
      'saml.assertion.signature': String(values.signAssertions),
      'saml.signature.algorithm': 'RSA_SHA256',
      saml_signature_canonicalization_method: 'http://www.w3.org/2001/10/xml-exc-c14n#',
      'saml.client.signature': String(values.clientSignature),
      'saml.signing.certificate': values.clientSignature ? values.signingCert : '',
      'saml.encrypt': String(values.encryptAssertions),
      'saml.encryption.certificate': values.encryptAssertions ? values.encryptionCert : '',
      'saml.force.post.binding': 'true',
      'saml.authnstatement': 'true',
    },
  };
}

export function idpInitiatedUrl(rep) {
  const name = rep.attributes?.saml_idp_initiated_sso_url_name;
  return name ? `${config.sandbox.samlEndpoint}/clients/${name}` : null;
}

export function fromClientRep(rep, mappers = []) {
  const a = rep.attributes || {};
  const ours = mappers.filter((m) => m.name.startsWith(MAPPER_PREFIX));
  return {
    name: rep.name || rep.clientId,
    clientId: rep.clientId,
    acsUrl: a.saml_assertion_consumer_url_post || a.saml_assertion_consumer_url_redirect || rep.adminUrl || '',
    sloUrl: a.saml_single_logout_service_url_post || a.saml_single_logout_service_url_redirect || '',
    homeUrl: rep.baseUrl || '',
    nameIdFormat: a.saml_name_id_format in NAME_ID_FORMATS ? a.saml_name_id_format : 'username',
    signDocuments: a['saml.server.signature'] !== 'false',
    signAssertions: a['saml.assertion.signature'] === 'true',
    clientSignature: a['saml.client.signature'] === 'true',
    signingCert: a['saml.signing.certificate'] || '',
    encryptAssertions: a['saml.encrypt'] === 'true',
    encryptionCert: a['saml.encryption.certificate'] || '',
    attributes: ours.map((m) => m.config['user.attribute']).filter((x) => x in USER_ATTRIBUTES),
    attributeNameFormat: ours[0]?.config['attribute.nameformat'] || 'Basic',
  };
}

// SP metadata XML -> form values, using Keycloak's own converter.
export async function valuesFromMetadata(xml) {
  const rep = await sandboxAdmin.convertClientDescription(xml);
  if (rep.protocol && rep.protocol !== 'saml') throw new KeycloakError('That is not SAML SP metadata.', 400);
  const values = { ...defaultAppValues(), ...fromClientRep(rep) };
  values.attributes = defaultAppValues().attributes;
  // Keycloak's converter leaves signing on only when the metadata asks for it; keep the portal's safe default.
  if (!values.signDocuments && !values.signAssertions) values.signDocuments = true;
  if (!values.name || values.name === values.clientId) values.name = '';
  return values;
}

// ---------- Keycloak operations ----------

export async function createSamlClient(values, owner) {
  const rep = toClientRep(values, owner);
  rep.clientId = values.clientId;
  // Unique, URL-safe name for Keycloak's IdP-initiated SSO link.
  const slug = values.clientId.toLowerCase().replace(/^https?:\/\//, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
  rep.attributes.saml_idp_initiated_sso_url_name = `${slug || 'app'}-${crypto.randomBytes(3).toString('hex')}`;
  rep.protocolMappers = values.attributes.map((attr) => mapperFor(attr, values.attributeNameFormat));
  return sandboxAdmin.createClient(rep);
}

export async function updateSamlClient(kcId, values, owner) {
  await sandboxAdmin.updateClient(kcId, toClientRep(values, owner));
  // Replace the portal-managed attribute mappers; leave any others alone.
  const existing = (await sandboxAdmin.listProtocolMappers(kcId)).filter((m) => m.name.startsWith(MAPPER_PREFIX));
  for (const m of existing) await sandboxAdmin.deleteProtocolMapper(kcId, m.id);
  for (const attr of values.attributes) await sandboxAdmin.addProtocolMapper(kcId, mapperFor(attr, values.attributeNameFormat));
}

export async function loadSamlClient(kcId) {
  const [rep, mappers] = await Promise.all([sandboxAdmin.getClient(kcId), sandboxAdmin.listProtocolMappers(kcId)]);
  return { rep, mappers, values: fromClientRep(rep, mappers) };
}

const ignoreNotFound = (err) => { if (!(err instanceof KeycloakError && err.status === 404)) throw err; };

export async function deleteSamlClient(kcId) {
  await sandboxAdmin.deleteClient(kcId).catch(ignoreNotFound);
}

// Removes a developer's sandbox clients and test users (used when their account is deleted).
export async function deleteOwnerResources(owner) {
  for (const app of await listApps({ owner })) {
    await deleteSamlClient(app.kc_id);
    await deleteApp(app.id);
  }
  for (const tu of await listTestUsers(owner)) {
    await sandboxAdmin.deleteUser(tu.kc_id).catch(ignoreNotFound);
    await deleteTestUser(tu.id);
  }
}
