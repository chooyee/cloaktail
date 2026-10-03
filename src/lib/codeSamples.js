// Example integration code for the app detail pages, filled in from each client's settings.
// Each function returns samples for views/fragments/code-samples.ejs: one tab per language.
import { NAME_ID_FORMAT_URNS } from './samlClients.js';

const pathOf = (url, fallback) => {
  try { return new URL(url).pathname; } catch { return fallback; }
};
const indent = (lines, by) => lines.map((l) => (l ? `${by}${l}` : l)).join('\n');
const py = (b) => (b ? 'True' : 'False');

const POM_DEPENDENCIES = (starters, extra = []) => `<!-- Spring Boot, with spring-boot-starter-parent -->
<dependencies>
${[...starters.map((s) => `  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>${s}</artifactId>
  </dependency>`), ...extra].join('\n')}
</dependencies>`;

// ---------- SAML ----------

export function samlSamples({ values, idp }) {
  const acsPath = pathOf(values.acsUrl, '/saml/acs');
  const nameIdFormat = NAME_ID_FORMAT_URNS[values.nameIdFormat];
  const idpCertFile = `keycloak-${idp.realm}-idp.pem`;
  const wrongEncryptionAlgorithm = values.encryptAssertions && values.encryptionKeyAlgorithm !== 'rsa-oaep-mgf1p';

  // Node.js: @node-saml/passport-saml
  const nodeLines = [
    `entryPoint: '${idp.ssoUrl}',`,
    `issuer: '${values.clientId}',`,
    `callbackUrl: '${values.acsUrl}',`,
    `idpIssuer: '${idp.entityId}',`,
    `idpCert: fs.readFileSync('${idpCertFile}', 'utf8'), // the IdP signing certificate (PEM) above`,
    `identifierFormat: '${nameIdFormat}',`,
    `wantAuthnResponseSigned: ${values.signDocuments},`,
    `wantAssertionsSigned: ${values.signAssertions},`,
    ...(values.clientSignature ? [
      `// Required: Keycloak rejects unsigned requests for this client.`,
      `privateKey: fs.readFileSync('sp-signing-key.pem', 'utf8'), // key of the signing certificate you uploaded`,
      `signatureAlgorithm: 'sha256', // the default is SHA-1`,
      `digestAlgorithm: 'sha256',`,
    ] : []),
    ...(values.encryptAssertions ? [
      `decryptionPvk: fs.readFileSync('sp-encryption-key.pem', 'utf8'), // key of the encryption certificate you uploaded`,
      ...(wrongEncryptionAlgorithm ? [`// Won't decrypt: set the encryption key algorithm to "RSA-OAEP, SHA-1" in the application settings.`] : []),
    ] : []),
    ...(values.sloUrl ? [`logoutUrl: '${idp.sloUrl}',`, `logoutCallbackUrl: '${values.sloUrl}',`] : []),
  ];
  const node = `import fs from 'node:fs';
import express from 'express';
import passport from 'passport';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml';

passport.use('saml', new SamlStrategy({
${indent(nodeLines, '  ')}
}, (profile, done) => done(null, profile), (profile, done) => done(null, profile)));

// Sign-in: redirects the browser to Keycloak.
app.get('/login', passport.authenticate('saml'));

// ACS: Keycloak POSTs the SAML response here.
app.post('${acsPath}', express.urlencoded({ extended: false }),
  passport.authenticate('saml', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/'));`;

  // Python: python3-saml holds a single SP key pair, used both to sign requests and to decrypt assertions.
  const spKey = values.clientSignature ? 'signing' : 'encryption';
  const pySpKeys = values.clientSignature || values.encryptAssertions ? [
    ...(values.clientSignature && values.encryptAssertions
      ? ['# python3-saml signs and decrypts with one key pair: upload the same certificate for signing and encryption.']
      : []),
    `"x509cert": read("sp-${spKey}-cert.pem"),  # the ${spKey} certificate you uploaded`,
    `"privateKey": read("sp-${spKey}-key.pem"),`,
  ] : [];
  const redirectBinding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
  const python = `import os

from flask import Flask, redirect, request, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]


def read(path):
    with open(path) as f:
        return f.read()


SAML_SETTINGS = {
    "strict": True,
    "sp": {
        "entityId": "${values.clientId}",
        "assertionConsumerService": {
            "url": "${values.acsUrl}",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },${values.sloUrl ? `
        "singleLogoutService": {"url": "${values.sloUrl}", "binding": "${redirectBinding}"},` : ''}
        "NameIDFormat": "${nameIdFormat}",${pySpKeys.length ? `\n${indent(pySpKeys, '        ')}` : ''}
    },
    "idp": {
        "entityId": "${idp.entityId}",
        "singleSignOnService": {"url": "${idp.ssoUrl}", "binding": "${redirectBinding}"},
        "singleLogoutService": {"url": "${idp.sloUrl}", "binding": "${redirectBinding}"},
        "x509cert": read("${idpCertFile}"),  # the IdP signing certificate (PEM) above
    },
    "security": {
        "authnRequestsSigned": ${py(values.clientSignature)},
        "logoutRequestSigned": ${py(values.clientSignature)},
        "logoutResponseSigned": ${py(values.clientSignature)},
        "wantMessagesSigned": ${py(values.signDocuments)},
        "wantAssertionsSigned": ${py(values.signAssertions)},
        "wantAssertionsEncrypted": ${py(values.encryptAssertions)},
        "requestedAuthnContext": False,  # let Keycloak decide how the user signs in
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
    },
}


def saml_auth():
    # Behind a TLS-terminating proxy, use the original scheme and host (e.g. werkzeug's ProxyFix).
    return OneLogin_Saml2_Auth({
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }, SAML_SETTINGS)


# Sign-in: redirects the browser to Keycloak.
@app.get("/login")
def login():
    return redirect(saml_auth().login())


# ACS: Keycloak POSTs the SAML response here.
@app.post("${acsPath}")
def acs():
    auth = saml_auth()
    auth.process_response()
    if auth.get_errors():
        return f"SAML sign-in failed: {auth.get_last_error_reason()}", 400
    session["user"] = {"name_id": auth.get_nameid(), "attributes": auth.get_attributes()}
    return redirect("/")`;

  // Java: Spring Security SAML 2.0 Login, configured from the IdP metadata.
  const credential = (property, cert) => [
    `${property}:`,
    `  credentials:`,
    `    - private-key-location: "file:sp-${cert}-key.pem"   # key of the ${cert} certificate you uploaded (PKCS#8)`,
    `      certificate-location: "file:sp-${cert}-cert.pem"`,
  ];
  const credentials = [
    ...(values.clientSignature ? credential('signing', 'signing') : []),
    ...(values.encryptAssertions ? credential('decryption', 'encryption') : []),
  ];
  const yml = `spring:
  security:
    saml2:
      relyingparty:
        registration:
          keycloak:
            entity-id: "${values.clientId}"
            acs:
              location: "${values.acsUrl}"
            assertingparty:
              metadata-uri: "${idp.metadataUrl}"
              singlesignon:
                sign-request: ${values.clientSignature}${values.clientSignature ? '   # required: Keycloak rejects unsigned requests' : ''}${credentials.length ? `\n${indent(credentials, '            ')}` : ''}

# Keycloak POSTs the response from its own site; the session cookie must come along,
# since it holds the AuthnRequest ID Spring checks InResponseTo against. Needs HTTPS (or localhost).
server:
  servlet:
    session:
      cookie:
        same-site: none
        secure: true`;
  const java = `import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            // ACS: Keycloak POSTs the SAML response here. Spring Security 6.1+ finds the
            // registration from the response's issuer, so the path needs no {registrationId}.
            .saml2Login((saml2) -> saml2.loginProcessingUrl("${acsPath}"));${values.sloUrl ? `
        // Single logout: add .saml2Logout(...); Spring signs logout messages, so it needs a signing key.` : ''}
        return http.build();
    }
}`;

  return [
    { lang: 'node', label: 'Node.js', language: 'javascript', filename: 'auth.js · @node-saml/passport-saml',
      install: 'npm install @node-saml/passport-saml passport express', code: node },
    { lang: 'python', label: 'Python', language: 'python', filename: 'app.py · python3-saml + Flask',
      install: 'pip install python3-saml flask   # python3-saml needs the xmlsec1 system libraries', code: python },
    { lang: 'java', label: 'Java', files: [
      { filename: 'pom.xml · Spring Security SAML 2.0', language: 'xml', code: `${POM_DEPENDENCIES(['spring-boot-starter-web', 'spring-boot-starter-security'], [`  <dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-saml2-service-provider</artifactId>
  </dependency>`])}

<!-- OpenSAML, which Spring Security uses, is published in Shibboleth's repository. -->
<repositories>
  <repository>
    <id>shibboleth</id>
    <url>https://build.shibboleth.net/maven/releases/</url>
  </repository>
</repositories>` },
      { filename: 'src/main/resources/application.yml', language: 'yaml', code: yml },
      { filename: 'SecurityConfig.java', language: 'java', code: java },
    ] },
  ];
}

// ---------- OpenID Connect ----------

export function oidcSamples({ clientId, values, op }) {
  const isPublic = values.clientType === 'public';
  const insecure = op.issuer.startsWith('http:');
  const redirectUri = values.redirectUris.find((u) => !u.endsWith('*')) || 'https://myapp.example.com/auth/callback';
  const callbackPath = pathOf(redirectUri, '/auth/callback');

  // Node.js: openid-client v6
  const discoveryArgs = isPublic
    ? `,\n  undefined,\n  client.None(), // public client${insecure ? ',\n  { execute: [client.allowInsecureRequests] }, // Keycloak on http://, development only' : ''}`
    : `,\n  process.env.OIDC_CLIENT_SECRET,${insecure ? '\n  undefined,\n  { execute: [client.allowInsecureRequests] }, // Keycloak on http://, development only' : ''}`;
  const node = `import * as client from 'openid-client';

const config = await client.discovery(
  new URL('${op.issuer}'),
  '${clientId}'${discoveryArgs}
);

// Sign-in: keep codeVerifier (and state) in the session, then redirect the browser.
const codeVerifier = client.randomPKCECodeVerifier();
const url = client.buildAuthorizationUrl(config, {
  redirect_uri: '${redirectUri}',
  scope: 'openid profile email',
  code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
  code_challenge_method: 'S256',
});

// Callback: exchange the code; the ID token is verified for you.
const tokens = await client.authorizationCodeGrant(config, currentUrl, { pkceCodeVerifier: codeVerifier });
const claims = tokens.claims();`;

  // Python: Authlib's Flask client
  const python = `import os

from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, session

${insecure ? 'os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"  # Keycloak on http://, development only\n\n' : ''}app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

oauth = OAuth(app)
oauth.register(
    "keycloak",
    client_id="${clientId}",${isPublic ? '' : `
    client_secret=os.environ["OIDC_CLIENT_SECRET"],`}
    server_metadata_url="${op.discoveryUrl}",
    client_kwargs={
        "scope": "openid profile email",
        "code_challenge_method": "S256",  # PKCE${isPublic ? `
        "token_endpoint_auth_method": "none",  # public client` : ''}
    },
)


# Sign-in: redirects the browser to Keycloak.
@app.get("/login")
def login():
    return oauth.keycloak.authorize_redirect("${redirectUri}")


# Callback: exchange the code; the ID token is verified for you.
@app.get("${callbackPath}")
def callback():
    token = oauth.keycloak.authorize_access_token()
    session["user"] = token["userinfo"]  # the ID token's claims
    return redirect("/")`;

  // Java: Spring Security OAuth 2.0 Login
  const yml = `spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            client-id: "${clientId}"
            ${isPublic ? 'client-authentication-method: none   # public client; Spring adds PKCE' : 'client-secret: "${OIDC_CLIENT_SECRET}"'}
            authorization-grant-type: authorization_code
            redirect-uri: "${redirectUri}"
            scope: openid, profile, email
        provider:
          keycloak:
            issuer-uri: "${op.issuer}"`;
  const java = `import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;${isPublic ? '' : `
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;`}
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http${isPublic ? '' : ', ClientRegistrationRepository registrations'}) throws Exception {${isPublic ? '' : `
        // PKCE: Spring adds it for public clients only.
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(registrations, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
`}
        http
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            .oauth2Login((oauth2) -> oauth2${isPublic ? '' : `
                .authorizationEndpoint((endpoint) -> endpoint.authorizationRequestResolver(resolver))`}
                // Callback: Spring exchanges the code and verifies the ID token here.
                .redirectionEndpoint((endpoint) -> endpoint.baseUri("${callbackPath}")));
        return http.build();
    }
}`;

  return [
    { lang: 'node', label: 'Node.js', language: 'javascript', filename: 'auth.js · openid-client v6',
      install: 'npm install openid-client', code: node },
    { lang: 'python', label: 'Python', language: 'python', filename: 'app.py · Authlib + Flask',
      install: 'pip install authlib flask requests', code: python },
    { lang: 'java', label: 'Java', files: [
      { filename: 'pom.xml · Spring Security OAuth 2.0 Client', language: 'xml',
        code: POM_DEPENDENCIES(['spring-boot-starter-web', 'spring-boot-starter-oauth2-client']) },
      { filename: 'src/main/resources/application.yml', language: 'yaml', code: yml },
      { filename: 'SecurityConfig.java', language: 'java', code: java },
    ] },
  ];
}

// ---------- user migration (the application's side of /migrate) ----------

// migrateUrl: <domain>/migrate (the request's aud; /start is where users are sent).
// requestKey: how requests are signed ('secret' = HS256 with the migration secret; otherwise RS256
// with the application's own private key). Results are always HS256 with the migration secret.
export function migrationSamples({ clientId, migrateUrl, returnUrl, requestKey, requireOtp }) {
  const hs = requestKey === 'secret';
  const returnPath = pathOf(returnUrl, '/migrated');
  const kid = requestKey === 'jwks' ? ", kid: 'my-key-1'" : '';
  const otpNote = requireOtp ? ' Keycloak asks for a code from the authenticator app they added on CloakTail.' : '';

  const node = `import crypto from 'node:crypto';

const MIGRATE_URL = '${migrateUrl}';
const CLIENT_ID = '${clientId}';
const RETURN_URL = '${returnUrl}';
const MIGRATION_SECRET = process.env.CLOAKTAIL_MIGRATION_SECRET; // from the migration page
${hs ? '' : `const PRIVATE_KEY = crypto.createPrivateKey(process.env.MIGRATION_PRIVATE_KEY); // pairs with the ${requestKey === 'jwks' ? 'key in your JWKS' : 'public key you registered'}\n`}
const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const hmac = (input) => crypto.createHmac('sha256', MIGRATION_SECRET).update(input).digest();

function signRequest(claims) {
  const input = \`\${b64({ alg: '${hs ? 'HS256' : 'RS256'}', typ: 'JWT'${hs ? '' : kid} })}.\${b64(claims)}\`;
  const signature = ${hs ? 'hmac(input)' : "crypto.sign('sha256', Buffer.from(input), PRIVATE_KEY)"};
  return \`\${input}.\${signature.toString('base64url')}\`;
}

// Checks a result from CloakTail; returns its claims, or null.
function verifyResult(token) {
  const [header, payload, signature] = String(token).split('.');
  if (!signature) return null;
  const expected = hmac(\`\${header}.\${payload}\`);
  const given = Buffer.from(signature, 'base64url');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  if (JSON.parse(Buffer.from(header, 'base64url')).alg !== 'HS256') return null;
  const claims = JSON.parse(Buffer.from(payload, 'base64url'));
  if (claims.aud !== CLIENT_ID || claims.exp < Date.now() / 1000) return null;
  return claims;
}

// Step 1: your existing login. Once the old password checks out, a user who isn't migrated yet
// goes to CloakTail instead of getting a session.
app.post('/login', async (req, res) => {
  const user = await checkLegacyPassword(req.body.username, req.body.password);
  if (!user) return res.status(401).render('login', { error: 'Wrong username or password.' });
  if (user.migratedAt) return res.redirect(\`/auth/keycloak?login_hint=\${encodeURIComponent(user.username)}\`);

  const now = Math.floor(Date.now() / 1000);
  req.session.migration = { state: crypto.randomUUID(), userId: user.id };
  const request = signRequest({
    iss: CLIENT_ID,
    aud: MIGRATE_URL,
    iat: now,
    exp: now + 300,                     // at most 10 minutes
    jti: crypto.randomUUID(),           // new for every request
    sub: String(user.id),               // your id; Keycloak keeps it as legacy_id
    preferred_username: user.username,  // their Keycloak username
    email: user.email,                  // optional
    given_name: user.firstName,         // optional
    family_name: user.lastName,         // optional
    return_url: RETURN_URL,
    state: req.session.migration.state,
  });
  res.redirect(\`\${MIGRATE_URL}/start?request=\${request}\`);
});

// Step 2: CloakTail sends the user back here with ?result=…
app.get('${returnPath}', async (req, res) => {
  const result = verifyResult(req.query.result);
  const pending = req.session.migration;
  delete req.session.migration;
  if (!result || !pending || result.state !== pending.state) return res.status(400).send('Invalid migration result.');

  switch (result.status) {
    case 'created':
      // They signed in with their old password moments ago: let them in now, no second sign-in.
      await markMigrated(result.sub, result.keycloak_id);
      req.session.userId = pending.userId;
      return res.redirect('/');
    case 'already_migrated':
      await markMigrated(result.sub, result.keycloak_id);
      // Step 3: migrated users sign in with Keycloak, never with the old password.${otpNote}
      return res.redirect(\`/auth/keycloak?login_hint=\${encodeURIComponent(result.preferred_username)}\`);
    case 'conflict':
      // Another Keycloak account has this username or email: needs a person to sort out.
      return res.render('migration-conflict');
    default: // cancelled, expired, error: let them in the old way this time, and ask again next time.
      req.session.userId = pending.userId;
      return res.redirect('/');
  }
});`;

  const python = `import base64, hashlib, hmac, json, os, secrets, time, uuid
from urllib.parse import urlencode
from flask import abort, redirect, render_template, request, session
${hs ? '' : 'import jwt  # pip install "pyjwt[crypto]", to sign with your private key\n'}
MIGRATE_URL = '${migrateUrl}'
CLIENT_ID = '${clientId}'
RETURN_URL = '${returnUrl}'
MIGRATION_SECRET = os.environ['CLOAKTAIL_MIGRATION_SECRET'].encode()  # from the migration page
${hs ? '' : `PRIVATE_KEY = os.environ['MIGRATION_PRIVATE_KEY']  # pairs with the ${requestKey === 'jwks' ? 'key in your JWKS' : 'public key you registered'}\n`}

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def sign_request(claims: dict) -> str:
${hs ? `    signing_input = b64(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()) + '.' + b64(json.dumps(claims).encode())
    signature = hmac.new(MIGRATION_SECRET, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + '.' + b64(signature)` : `    return jwt.encode(claims, PRIVATE_KEY, algorithm='RS256'${requestKey === 'jwks' ? ", headers={'kid': 'my-key-1'}" : ''})`}


def verify_result(token: str):
    """Checks a result from CloakTail; returns its claims, or None."""
    try:
        header, payload, signature = token.split('.')
        expected = hmac.new(MIGRATION_SECRET, f'{header}.{payload}'.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(unb64(signature), expected):
            return None
        if json.loads(unb64(header)).get('alg') != 'HS256':
            return None
        claims = json.loads(unb64(payload))
    except ValueError:
        return None
    if claims.get('aud') != CLIENT_ID or claims.get('exp', 0) < time.time():
        return None
    return claims


# Step 1: your existing login. Once the old password checks out, a user who isn't migrated yet
# goes to CloakTail instead of getting a session.
@app.post('/login')
def login():
    user = check_legacy_password(request.form['username'], request.form['password'])
    if user is None:
        return render_template('login.html', error='Wrong username or password.'), 401
    if user.migrated_at:
        return redirect('/auth/keycloak?' + urlencode({'login_hint': user.username}))

    now = int(time.time())
    session['migration'] = {'state': secrets.token_urlsafe(16), 'user_id': user.id}
    token = sign_request({
        'iss': CLIENT_ID,
        'aud': MIGRATE_URL,
        'iat': now,
        'exp': now + 300,                    # at most 10 minutes
        'jti': str(uuid.uuid4()),            # new for every request
        'sub': str(user.id),                 # your id; Keycloak keeps it as legacy_id
        'preferred_username': user.username,  # their Keycloak username
        'email': user.email,                 # optional
        'given_name': user.first_name,       # optional
        'family_name': user.last_name,       # optional
        'return_url': RETURN_URL,
        'state': session['migration']['state'],
    })
    return redirect(f'{MIGRATE_URL}/start?' + urlencode({'request': token}))


# Step 2: CloakTail sends the user back here with ?result=…
@app.get('${returnPath}')
def migrated():
    result = verify_result(request.args.get('result', ''))
    pending = session.pop('migration', None)
    if result is None or pending is None or result.get('state') != pending['state']:
        abort(400)

    if result['status'] == 'created':
        # They signed in with their old password moments ago: let them in now, no second sign-in.
        mark_migrated(result['sub'], result.get('keycloak_id'))
        session['user_id'] = pending['user_id']
        return redirect('/')
    if result['status'] == 'already_migrated':
        mark_migrated(result['sub'], result.get('keycloak_id'))
        # Step 3: migrated users sign in with Keycloak, never with the old password.${otpNote}
        return redirect('/auth/keycloak?' + urlencode({'login_hint': result['preferred_username']}))
    if result['status'] == 'conflict':
        # Another Keycloak account has this username or email: needs a person to sort out.
        return render_template('migration_conflict.html')
    # cancelled, expired, error: let them in the old way this time, and ask again next time.
    session['user_id'] = pending['user_id']
    return redirect('/')`;

  return [
    { lang: 'node', label: 'Node.js', filename: 'migration.js (Express)', language: 'javascript', code: node },
    { lang: 'python', label: 'Python', install: hs ? undefined : 'pip install "pyjwt[crypto]"', filename: 'migration.py (Flask)', language: 'python', code: python },
  ];
}
