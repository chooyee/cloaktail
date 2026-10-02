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
