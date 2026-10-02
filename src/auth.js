import express from 'express';
import passport from 'passport';
import { Strategy as SamlStrategy, ValidateInResponseTo } from '@node-saml/passport-saml';
import { config, samlUrlsFor, currentProfileId } from './config.js';
import { upsertUser, getUserRoles, addUserRoleByName } from './db.js';
import { destroySessions } from './session.js';
import { idpCertCallback, loadIdpCerts } from './lib/idpCerts.js';
import { onKeycloakSettingsChange, listTenants } from './keycloakProfiles.js';
import { getActiveSpKey, onSpKeyChange } from './spKeys.js';
import { sendError } from './middleware.js';

// A pinned signing certificate must be the realm's, not a client's; warn early if not.
function checkPinnedCert(tenant) {
  const pinned = tenant.saml.idpCert;
  if (!pinned) return;
  loadIdpCerts(tenant.saml.descriptorUrl).then(
    (certs) => {
      if (!certs.includes(pinned)) {
        console.warn(`The pinned signing certificate of Keycloak profile "${tenant.profileName}" is not a signing certificate of realm`,
          tenant.keycloak.realm, '- every sign-in will fail signature checks. Leave it empty to use the realm certificate automatically.');
      }
    },
    () => { /* Keycloak unreachable; nothing to compare against */ },
  );
}

// ---------- strategy ----------

function attr(profile, name) {
  const value = profile.attributes?.[name] ?? profile[name];
  return Array.isArray(value) ? value[0] : value;
}

// One per domain, built from the Keycloak profile serving it and the signing key; rebuilt when an
// administrator changes either. Built outside any request, so it reads the tenant passed in, not
// config. The callbacks run inside the request, so the database calls there use its profile.
// The portal signs AuthnRequests and LogoutRequests with its own key pair, so Keycloak can keep
// "Client signature required" on; the certificate is imported into the Keycloak client.
const createSamlStrategy = (spKey, tenant) => new SamlStrategy(
  {
    entryPoint: tenant.saml.entryPoint,
    logoutUrl: tenant.saml.entryPoint,
    issuer: tenant.saml.issuer,
    ...samlUrlsFor(tenant.siteUrl),
    idpCert: tenant.saml.idpCert || idpCertCallback(tenant.saml.descriptorUrl),
    idpIssuer: tenant.keycloak.realmUrl,
    audience: tenant.saml.issuer,
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    privateKey: spKey.privateKey,
    publicCert: spKey.certificate,
    signatureAlgorithm: 'sha256',
    // Checks InResponseTo for SP-initiated logins but still allows IdP-initiated SSO.
    validateInResponseTo: ValidateInResponseTo.ifPresent,
    acceptedClockSkewMs: 5000,
  },
  // Sign-on: Keycloak authenticated the user; record them locally and apply bootstrap roles.
  async (profile, done) => {
    try {
      const username = await upsertUser(
        {
          username: profile.nameID,
          email: attr(profile, 'email'),
          firstName: attr(profile, 'firstName'),
          lastName: attr(profile, 'lastName'),
        },
        { login: true },
      );
      if (config.adminUsers.includes(username)) await addUserRoleByName(username, 'admin');
      if ((await getUserRoles(username)).length === 0) await addUserRoleByName(username, config.defaultRole);

      done(null, {
        // Sessions only count on the domains of the profile that signed the user in (userContext).
        profileId: currentProfileId(),
        username,
        email: attr(profile, 'email') || null,
        firstName: attr(profile, 'firstName') || null,
        lastName: attr(profile, 'lastName') || null,
        // Needed to build the SAML LogoutRequest later.
        nameID: profile.nameID,
        nameIDFormat: profile.nameIDFormat,
        sessionIndex: profile.sessionIndex,
      });
    } catch (err) {
      done(err);
    }
  },
  // Logout requested by Keycloak (e.g. user signed out of another app in the realm).
  // The browser's cross-site POST carries no session cookie, so find the sessions in the store.
  (profile, done) => {
    const profileId = currentProfileId();
    destroySessions((user) => user.profileId === profileId && user.nameID === profile.nameID
      && (!profile.sessionIndex || user.sessionIndex === profile.sessionIndex)).then(() => done(null, profile), done);
  },
);

// Strategies by domain. Empty until there is a signing key (fresh install): Keycloak sign-in is
// unavailable meanwhile.
let samlStrategies = new Map();
let spCertificate = null;
const strategyName = (siteUrl) => `saml:${siteUrl}`;
// req.siteUrl is the request's domain when a profile serves it (app.js).
const samlStrategyFor = (req) => samlStrategies.get(req.siteUrl) || null;
const authenticateSaml = (req, ...args) => passport.authenticate(strategyName(req.siteUrl), ...args);

async function useActiveSettings() {
  const spKey = await getActiveSpKey();
  for (const siteUrl of samlStrategies.keys()) passport.unuse(strategyName(siteUrl));
  samlStrategies = new Map();
  spCertificate = null;
  if (!spKey) return;
  const checked = new Set();
  for (const tenant of listTenants()) {
    const strategy = createSamlStrategy(spKey, tenant);
    samlStrategies.set(tenant.siteUrl, strategy);
    passport.use(strategyName(tenant.siteUrl), strategy);
    if (!checked.has(tenant.profileId)) checkPinnedCert(tenant);
    checked.add(tenant.profileId);
  }
  spCertificate = spKey.certificate;
}
await useActiveSettings();
onKeycloakSettingsChange(useActiveSettings);
onSpKeyChange(useActiveSettings);

function requireSaml(req, res, next) {
  if (samlStrategyFor(req)) return next();
  const missing = config.keycloak.configured ? 'a SAML signing certificate' : 'a Keycloak profile for this domain';
  sendError(req, res, 503, `Keycloak sign-in is not set up yet. An administrator must add ${missing} in the admin console.`);
}

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ---------- routes ----------

function safeReturnTo(value) {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') && !value.startsWith('/\\')
    ? value
    : '/';
}

export const authRouter = express.Router();

authRouter.get('/login', (req, res) => {
  if (req.user) return res.redirect('/');
  res.render('pages/login', {
    title: 'Sign in',
    description: 'Sign in to CloakTail with your developer account to manage your Keycloak SAML clients and test users.',
    returnTo: safeReturnTo(req.query.returnTo),
    loggedOut: 'loggedOut' in req.query,
    registered: 'registered' in req.query,
    error: req.query.error,
    // Shown so users know where they are being sent before they type a password.
    keycloakHost: samlStrategyFor(req) ? new URL(config.keycloak.url).host : null,
  });
});

// Starts SP-initiated SSO. RelayState carries the page to return to after login
// (passport-saml forwards req.query.RelayState to Keycloak).
authRouter.get('/auth/login', requireSaml, (req, res, next) => {
  const relayState = safeReturnTo(req.query.RelayState);
  if (relayState !== req.query.RelayState) {
    return res.redirect(`/auth/login?RelayState=${encodeURIComponent(relayState)}`);
  }
  authenticateSaml(req, { failureRedirect: '/login?error=1' })(req, res, next);
});

// Assertion Consumer Service: Keycloak POSTs the signed SAML Response here.
authRouter.post('/saml/acs', requireSaml, express.urlencoded({ extended: false }), (req, res, next) => {
  authenticateSaml(req, (err, user) => {
    if (err || !user) {
      console.error('SAML login failed:', err?.message || 'no user');
      return res.redirect('/login?error=1');
    }
    // Fresh session on login (prevents session fixation).
    req.session.regenerate((regenErr) => {
      if (regenErr) return next(regenErr);
      req.login(user, { keepSessionInfo: false }, (loginErr) => {
        if (loginErr) return next(loginErr);
        res.redirect(safeReturnTo(req.body.RelayState));
      });
    });
  })(req, res, next);
});

// SP-initiated logout: build the SAML LogoutRequest, end the local session, then go to Keycloak.
authRouter.post('/logout', (req, res, next) => {
  if (!req.user) return res.redirect('/login');
  const endSession = (url) => req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie('sid');
      res.redirect(url || '/login?loggedOut');
    });
  });
  // No Keycloak sign-in on this domain: there is no IdP session to end, so sign out locally only.
  const samlStrategy = samlStrategyFor(req);
  if (!samlStrategy) return endSession(null);
  samlStrategy.logout(req, (err, url) => {
    if (err) return next(err);
    endSession(url);
  });
});

// Keycloak sends either a LogoutResponse (after our logout) or a LogoutRequest (IdP-initiated).
authRouter.all('/saml/logout/callback', express.urlencoded({ extended: false }), (req, res, next) => {
  const isLogoutRequest = req.body?.SAMLRequest || req.query?.SAMLRequest;
  if (!isLogoutRequest || !samlStrategyFor(req)) return res.redirect('/login?loggedOut');
  authenticateSaml(req, (err) => {
    if (err) return next(err);
    res.redirect('/login?loggedOut');
  })(req, res, next);
});

// SP metadata, handy for importing the client into Keycloak.
authRouter.get('/saml/metadata', requireSaml, (req, res) => {
  res.type('application/xml').send(samlStrategyFor(req).generateServiceProviderMetadata(null, spCertificate));
});
