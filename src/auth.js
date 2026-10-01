import express from 'express';
import passport from 'passport';
import { Strategy as SamlStrategy, ValidateInResponseTo } from '@node-saml/passport-saml';
import { config } from './config.js';
import { upsertUser, getUserRoles, addUserRoleByName } from './db.js';
import { destroySessions } from './session.js';
import { idpCertCallback, loadIdpCerts } from './lib/idpCerts.js';
import { onKeycloakSettingsChange } from './keycloakProfiles.js';
import { getActiveSpKey, onSpKeyChange } from './spKeys.js';
import { sendError } from './middleware.js';

// A pinned SAML_IDP_CERT must be the realm's signing certificate, not a client's; warn early if not.
function checkPinnedCert() {
  const pinned = config.saml.idpCert;
  if (!pinned) return;
  loadIdpCerts(config.saml.descriptorUrl).then(
    (certs) => {
      if (!certs.includes(pinned)) {
        console.warn('The pinned signing certificate of the active Keycloak profile is not a signing certificate of realm',
          config.keycloak.realm, '- every sign-in will fail signature checks. Leave it empty to use the realm certificate automatically.');
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

// Built from the active Keycloak profile and signing key; rebuilt when an administrator changes either.
// The portal signs AuthnRequests and LogoutRequests with its own key pair, so Keycloak can keep
// "Client signature required" on; the certificate is imported into the Keycloak client.
const createSamlStrategy = (spKey) => new SamlStrategy(
  {
    entryPoint: config.saml.entryPoint,
    logoutUrl: config.saml.entryPoint,
    issuer: config.saml.issuer,
    callbackUrl: config.saml.callbackUrl,
    logoutCallbackUrl: config.saml.logoutCallbackUrl,
    idpCert: config.saml.idpCert || idpCertCallback(config.saml.descriptorUrl),
    idpIssuer: config.keycloak.realmUrl,
    audience: config.saml.issuer,
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
  (profile, done) => {
    try {
      const username = upsertUser(
        {
          username: profile.nameID,
          email: attr(profile, 'email'),
          firstName: attr(profile, 'firstName'),
          lastName: attr(profile, 'lastName'),
        },
        { login: true },
      );
      if (config.adminUsers.includes(username)) addUserRoleByName(username, 'admin');
      if (getUserRoles(username).length === 0) addUserRoleByName(username, config.defaultRole);

      done(null, {
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
    destroySessions(
      (user) => user.nameID === profile.nameID && (!profile.sessionIndex || user.sessionIndex === profile.sessionIndex),
    ).then(() => done(null, profile), done);
  },
);

// null until there is both an active Keycloak profile and a signing key (fresh install):
// Keycloak sign-in is unavailable meanwhile.
let samlStrategy = null;
let spCertificate = null;

function useActiveSettings() {
  const spKey = getActiveSpKey();
  if (config.keycloak.configured && spKey) {
    samlStrategy = createSamlStrategy(spKey);
    spCertificate = spKey.certificate;
    passport.use('saml', samlStrategy);
    checkPinnedCert();
  } else {
    samlStrategy = null;
    spCertificate = null;
    passport.unuse('saml');
  }
}
useActiveSettings();
onKeycloakSettingsChange(useActiveSettings);
onSpKeyChange(useActiveSettings);

function requireSaml(req, res, next) {
  if (samlStrategy) return next();
  const missing = config.keycloak.configured ? 'a SAML signing certificate' : 'a Keycloak profile';
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
    returnTo: safeReturnTo(req.query.returnTo),
    loggedOut: 'loggedOut' in req.query,
    registered: 'registered' in req.query,
    error: req.query.error,
    // Shown so users know where they are being sent before they type a password.
    keycloakHost: samlStrategy ? new URL(config.keycloak.url).host : null,
  });
});

// Starts SP-initiated SSO. RelayState carries the page to return to after login
// (passport-saml forwards req.query.RelayState to Keycloak).
authRouter.get('/auth/login', requireSaml, (req, res, next) => {
  const relayState = safeReturnTo(req.query.RelayState);
  if (relayState !== req.query.RelayState) {
    return res.redirect(`/auth/login?RelayState=${encodeURIComponent(relayState)}`);
  }
  passport.authenticate('saml', { failureRedirect: '/login?error=1' })(req, res, next);
});

// Assertion Consumer Service: Keycloak POSTs the signed SAML Response here.
authRouter.post('/saml/acs', requireSaml, express.urlencoded({ extended: false }), (req, res, next) => {
  passport.authenticate('saml', (err, user) => {
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
  // No active Keycloak profile: there is no IdP session to end, so sign out locally only.
  if (!samlStrategy) return endSession(null);
  samlStrategy.logout(req, (err, url) => {
    if (err) return next(err);
    endSession(url);
  });
});

// Keycloak sends either a LogoutResponse (after our logout) or a LogoutRequest (IdP-initiated).
authRouter.all('/saml/logout/callback', express.urlencoded({ extended: false }), (req, res, next) => {
  const isLogoutRequest = req.body?.SAMLRequest || req.query?.SAMLRequest;
  if (!isLogoutRequest || !samlStrategy) return res.redirect('/login?loggedOut');
  passport.authenticate('saml', (err) => {
    if (err) return next(err);
    res.redirect('/login?loggedOut');
  })(req, res, next);
});

// SP metadata, handy for importing the client into Keycloak.
authRouter.get('/saml/metadata', requireSaml, (req, res) => {
  res.type('application/xml').send(samlStrategy.generateServiceProviderMetadata(null, spCertificate));
});
