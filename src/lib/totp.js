import crypto from 'node:crypto';
import QRCode from 'qrcode';

// TOTP enrolment for user migration (RFC 6238), in the form Keycloak stores OTP credentials: the
// secret is a plain string, and authenticator apps get the base32 of its bytes. Keycloak's own
// defaults (HmacSHA1, 6 digits, 30 seconds); the credential carries them, so Keycloak checks codes
// with these whatever the realm's OTP policy says.
export const TOTP = { algorithm: 'HmacSHA1', digits: 6, period: 30 };

const SECRET_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const SECRET_LENGTH = 20; // as Keycloak generates them

// A new secret, as Keycloak generates them: 20 alphanumeric characters.
export function newTotpSecret() {
  const out = [];
  // Rejection sampling, so every character is equally likely.
  while (out.length < SECRET_LENGTH) {
    for (const b of crypto.randomBytes(SECRET_LENGTH)) {
      if (b < 248 && out.length < SECRET_LENGTH) out.push(SECRET_CHARS[b % SECRET_CHARS.length]);
    }
  }
  return out.join('');
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

// The key the user types into an authenticator app instead of scanning, in groups of four.
export const manualKey = (secret) => base32(Buffer.from(secret)).match(/.{1,4}/g).join(' ');

function codeAt(secret, counter) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', Buffer.from(secret)).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 15;
  return String((hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** TOTP.digits).padStart(TOTP.digits, '0');
}

// Whether code is valid now, allowing one period either side for clock drift.
export function verifyTotp(secret, code) {
  if (typeof code !== 'string' || !new RegExp(`^\\d{${TOTP.digits}}$`).test(code)) return false;
  const counter = Math.floor(Date.now() / 1000 / TOTP.period);
  return [-1, 0, 1].some((d) => crypto.timingSafeEqual(Buffer.from(codeAt(secret, counter + d)), Buffer.from(code)));
}

// The QR code authenticator apps scan, as an SVG string.
export function totpQrSvg(secret, { issuer, account }) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: base32(Buffer.from(secret)), issuer, algorithm: 'SHA1', digits: String(TOTP.digits), period: String(TOTP.period),
  });
  return QRCode.toString(`otpauth://totp/${label}?${params}`, { type: 'svg', margin: 1, width: 160, errorCorrectionLevel: 'M' });
}

// The Keycloak credential for a secret, for the admin API's user representation.
export const totpCredential = (secret) => ({
  type: 'otp',
  userLabel: 'Authenticator app',
  secretData: JSON.stringify({ value: secret }),
  credentialData: JSON.stringify({ subType: 'totp', digits: TOTP.digits, period: TOTP.period, algorithm: TOTP.algorithm, counter: 0 }),
});
