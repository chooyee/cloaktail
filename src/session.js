import session from 'express-session';
import { config } from './config.js';

// In-memory store: fine for a single dev instance. For production use a shared store
// (Redis, a database) that still implements all() so destroySessions() keeps working.
export const sessionStore = new session.MemoryStore();

export const sessionMiddleware = session({
  name: 'sid',
  secret: config.sessionSecret,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    // Lax: the session cookie is not sent on Keycloak's cross-site POSTs, which is why
    // the ACS handler starts a fresh session and IdP logout looks sessions up in the store.
    sameSite: 'lax',
    secure: config.secureCookies,
    maxAge: 8 * 60 * 60 * 1000,
  },
});

// Destroys every session whose logged-in user matches the predicate.
// Used for IdP-initiated logout and when an admin disables/deletes a user.
export function destroySessions(predicate) {
  return new Promise((resolve, reject) => {
    sessionStore.all((err, sessions) => {
      if (err) return reject(err);
      const ids = Object.entries(sessions || {})
        .filter(([, s]) => s?.passport?.user && predicate(s.passport.user))
        .map(([id]) => id);
      let pending = ids.length;
      if (!pending) return resolve(0);
      for (const id of ids) {
        sessionStore.destroy(id, () => {
          if (--pending === 0) resolve(ids.length);
        });
      }
    });
  });
}
