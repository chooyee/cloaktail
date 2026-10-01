import session from 'express-session';
import { config } from './config.js';
import { getSession, saveSession, deleteSession, listSessions, deleteExpiredSessions } from './db.js';

const MAX_AGE = 8 * 60 * 60 * 1000;

// Sessions live in PostgreSQL, so they survive restarts and are shared by every app instance.
// all() is implemented because destroySessions() needs it.
class PgSessionStore extends session.Store {
  get(sid, cb) {
    getSession(sid).then((sess) => cb(null, sess), cb);
  }

  set(sid, sess, cb) {
    const expires = sess.cookie?.expires ? new Date(sess.cookie.expires) : new Date(Date.now() + MAX_AGE);
    saveSession(sid, sess, expires).then(() => cb?.(), (err) => cb?.(err));
  }

  destroy(sid, cb) {
    deleteSession(sid).then(() => cb?.(), (err) => cb?.(err));
  }

  all(cb) {
    listSessions().then((rows) => cb(null, Object.fromEntries(rows.map((r) => [r.sid, r.sess]))), cb);
  }
}

export const sessionStore = new PgSessionStore();

// Expired rows are ignored on read; clear them out now and then.
setInterval(() => {
  deleteExpiredSessions().catch((err) => console.error('Removing expired sessions failed:', err));
}, 15 * 60 * 1000).unref();

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
    maxAge: MAX_AGE,
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
