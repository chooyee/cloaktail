import crypto from 'node:crypto';
import { DOMParser } from '@xmldom/xmldom';
import { SAML, ValidateInResponseTo } from '@node-saml/passport-saml';
import { config, currentProfileId } from '../config.js';
import { idpCertCallback } from './idpCerts.js';

// "Test connection": the portal plays the developer's SP for one login. It sends an AuthnRequest
// with the developer's entity ID and the portal's own ACS, then validates and explains the response.

const TEST_TTL_MS = 10 * 60 * 1000;
const NS = {
  samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
};

// Pending tests keyed by RelayState. Keycloak's POST to the ACS is cross-site, so the session
// cookie is not sent; RelayState is how the response finds its test.
const pending = new Map();

// Shared InResponseTo cache (node-saml's default cache lives inside each SAML instance).
const requestIds = new Map();
const cacheProvider = {
  async saveAsync(key, value) {
    requestIds.set(key, { value, createdAt: Date.now() });
    return { value, createdAt: Date.now() };
  },
  async getAsync(key) {
    const item = requestIds.get(key);
    return item && Date.now() - item.createdAt < TEST_TTL_MS ? item.value : null;
  },
  async removeAsync(key) {
    const item = requestIds.get(key);
    requestIds.delete(key);
    return item?.value ?? null;
  },
};

function prune() {
  const now = Date.now();
  for (const [k, v] of pending) if (v.expiresAt < now) pending.delete(k);
  for (const [k, v] of requestIds) if (now - v.createdAt > TEST_TTL_MS) requestIds.delete(k);
}

function samlFor(test) {
  return new SAML({
    entryPoint: config.sandbox.samlEndpoint,
    issuer: test.clientId,
    callbackUrl: test.acsUrl,
    idpCert: idpCertCallback(config.sandbox.descriptorUrl),
    idpIssuer: config.sandbox.realmUrl,
    audience: test.clientId,
    wantAuthnResponseSigned: test.signDocuments,
    wantAssertionsSigned: test.signAssertions,
    identifierFormat: null, // let the client's configured Name ID format apply
    disableRequestedAuthnContext: true,
    forceAuthn: true, // always show the login form so any test user can be chosen
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: TEST_TTL_MS,
    cacheProvider,
    acceptedClockSkewMs: 5000,
  });
}

// Returns the Keycloak URL to send the developer's browser to.
export async function startTest({ app, values, startedBy, acsUrl }) {
  prune();
  const relayState = crypto.randomBytes(16).toString('hex');
  const test = {
    appId: app.id,
    clientId: app.client_id,
    profileId: currentProfileId(),
    acsUrl,
    signDocuments: values.signDocuments,
    signAssertions: values.signAssertions,
    expectedAttributes: values.attributes,
    startedBy,
    expiresAt: Date.now() + TEST_TTL_MS,
  };
  pending.set(relayState, test);
  return samlFor(test).getAuthorizeUrlAsync(relayState, undefined, {});
}

// Validates a SAML Response posted to the test ACS. Returns { appId, ok, summary, result } or null
// if the RelayState doesn't belong to a pending test.
export async function finishTest(body) {
  const test = pending.get(body.RelayState);
  // A response is only checked by the profile (sandbox realm) whose test it answers.
  if (!test || test.expiresAt < Date.now() || test.profileId !== currentProfileId()) return null;
  pending.delete(body.RelayState);

  let xml = '';
  try { xml = Buffer.from(body.SAMLResponse || '', 'base64').toString('utf8'); } catch { /* reported below */ }
  const details = analyzeResponse(xml);

  let validation;
  try {
    const { profile } = await samlFor(test).validatePostResponseAsync({ SAMLResponse: body.SAMLResponse });
    validation = { ok: true, nameID: profile?.nameID };
  } catch (err) {
    validation = { ok: false, error: err.message };
  }

  const checks = buildChecks(test, details, validation);
  const ok = checks.every((c) => c.ok !== false);
  const failed = checks.filter((c) => c.ok === false).map((c) => c.label);
  return {
    appId: test.appId,
    ok,
    summary: ok ? `Signed in as ${details.nameId?.value ?? '(no Name ID)'}` : `Failed: ${failed.join(', ')}`,
    result: { startedBy: test.startedBy, checks, details, validation, xml: prettyXml(xml) },
  };
}

function buildChecks(test, d, validation) {
  const checks = [];
  const add = (label, ok, detail) => checks.push({ label, ok, detail });

  add('Keycloak returned Success', d.status?.code?.endsWith(':Success') ?? false,
    d.status ? [d.status.code, d.status.subCode, d.status.message].filter(Boolean).join(' · ') : 'No status in response');
  if (d.encrypted) {
    add('Assertion readable', false, 'The assertion is encrypted with your app\'s certificate. The portal can\'t decrypt it; test encrypted responses in your app, or turn encryption off while testing.');
  }
  add('Issuer is the sandbox realm', d.issuer === config.sandbox.realmUrl, d.issuer || 'missing');
  add('Destination is the test ACS', d.destination === test.acsUrl, d.destination || 'missing');
  if (!d.encrypted) {
    add('Audience is your entity ID', d.audiences.includes(test.clientId), d.audiences.join(', ') || 'missing');
  }
  add('Response signed', test.signDocuments ? d.responseSigned : null,
    d.responseSigned ? 'Signature present' : (test.signDocuments ? 'Expected but missing' : 'Not signed (not required by your settings)'));
  if (!d.encrypted) {
    add('Assertion signed', test.signAssertions ? d.assertionSigned : null,
      d.assertionSigned ? 'Signature present' : (test.signAssertions ? 'Expected but missing' : 'Not signed (not required by your settings)'));
  }
  add('Signature and conditions valid', validation.ok, validation.ok ? 'Validated with the realm\'s signing certificate' : validation.error);
  if (!d.encrypted) {
    const received = new Set(d.attributes.map((a) => a.name));
    const missing = test.expectedAttributes.filter((a) => !received.has(a));
    add('Expected attributes received', missing.length === 0,
      missing.length ? `Missing: ${missing.join(', ')} (is the test user's profile filled in?)` : (test.expectedAttributes.join(', ') || 'None configured'));
  }
  return checks;
}

// ---------- XML inspection ----------

const children = (el, ns, name) =>
  el ? Array.from(el.childNodes).filter((n) => n.nodeType === 1 && n.namespaceURI === ns && n.localName === name) : [];
const child = (el, ns, name) => children(el, ns, name)[0] || null;
const text = (el) => el?.textContent?.trim() || null;

export function analyzeResponse(xml) {
  const d = { parsed: false, audiences: [], attributes: [] };
  if (!xml) return d;
  let doc;
  try {
    doc = new DOMParser({ onError: () => {} }).parseFromString(xml, 'text/xml');
  } catch {
    return d;
  }
  const res = doc?.documentElement;
  if (!res || res.localName !== 'Response') return d;
  d.parsed = true;
  d.id = res.getAttribute('ID');
  d.issueInstant = res.getAttribute('IssueInstant');
  d.destination = res.getAttribute('Destination');
  d.inResponseTo = res.getAttribute('InResponseTo');
  d.issuer = text(child(res, NS.saml, 'Issuer'));
  d.responseSigned = Boolean(child(res, NS.ds, 'Signature'));

  const status = child(res, NS.samlp, 'Status');
  const code = child(status, NS.samlp, 'StatusCode');
  d.status = {
    code: code?.getAttribute('Value'),
    subCode: child(code, NS.samlp, 'StatusCode')?.getAttribute('Value') || null,
    message: text(child(status, NS.samlp, 'StatusMessage')),
  };

  d.encrypted = Boolean(child(res, NS.saml, 'EncryptedAssertion'));
  const assertion = child(res, NS.saml, 'Assertion');
  if (!assertion) return d;
  d.assertionSigned = Boolean(child(assertion, NS.ds, 'Signature'));

  const subject = child(assertion, NS.saml, 'Subject');
  const nameId = child(subject, NS.saml, 'NameID');
  if (nameId) d.nameId = { value: text(nameId), format: nameId.getAttribute('Format') };
  const scd = child(child(subject, NS.saml, 'SubjectConfirmation'), NS.saml, 'SubjectConfirmationData');
  if (scd) d.subjectConfirmation = { recipient: scd.getAttribute('Recipient'), notOnOrAfter: scd.getAttribute('NotOnOrAfter') };

  const conditions = child(assertion, NS.saml, 'Conditions');
  if (conditions) {
    d.conditions = { notBefore: conditions.getAttribute('NotBefore'), notOnOrAfter: conditions.getAttribute('NotOnOrAfter') };
    d.audiences = children(conditions, NS.saml, 'AudienceRestriction')
      .flatMap((ar) => children(ar, NS.saml, 'Audience').map(text));
  }

  const authn = child(assertion, NS.saml, 'AuthnStatement');
  if (authn) d.authn = { instant: authn.getAttribute('AuthnInstant'), sessionIndex: authn.getAttribute('SessionIndex') };

  d.attributes = children(child(assertion, NS.saml, 'AttributeStatement'), NS.saml, 'Attribute').map((a) => ({
    name: a.getAttribute('Name'),
    nameFormat: a.getAttribute('NameFormat') || null,
    friendlyName: a.getAttribute('FriendlyName') || null,
    values: children(a, NS.saml, 'AttributeValue').map(text),
  }));
  return d;
}

// Simple indenter for display; Keycloak emits the response on one line.
function prettyXml(xml) {
  if (!xml) return '';
  let depth = 0;
  return xml
    .replace(/>\s*</g, '>\n<')
    .split('\n')
    .map((line) => {
      if (/^<\//.test(line)) depth = Math.max(depth - 1, 0);
      const out = '  '.repeat(depth) + line;
      if (/^<[^!?/][^>]*[^/]>$/.test(line) && !/<\/[^>]+>$/.test(line)) depth += 1;
      return out;
    })
    .join('\n');
}
