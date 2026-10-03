import { config } from '../config.js';
import { sandboxAdmin, KeycloakError } from '../lib/keycloakAdmin.js';
import { listTestUsers, countTestUsers, getTestUser, insertTestUser, deleteTestUser } from '../db.js';
import { ServiceError, invalid } from './errors.js';

// Developers' own test accounts in the sandbox realm, used to sign in during "Test connection".
// Used by the HTML page (routes/testUsers.js) and the REST API (routes/api.js).

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,39}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// The owner's test users, each with `kc`: its Keycloak user, or null when Keycloak lost it.
export async function listTestUsersWithDetails(owner) {
  return Promise.all((await listTestUsers(owner)).map(async (row) => {
    try {
      return { ...row, kc: await sandboxAdmin.getUser(row.kc_id) };
    } catch (err) {
      if (err instanceof KeycloakError && err.status === 404) return { ...row, kc: null };
      throw err;
    }
  }));
}

// Rows are only ever looked up for their owner.
export async function findOwnTestUser(owner, id) {
  const row = await getTestUser(Number(id));
  return row && row.owner === owner ? row : null;
}

const passwordProblem = (password) => (typeof password !== 'string' || password.length < 8 ? 'Password must be at least 8 characters.' : null);

// values: { username, email, firstName, lastName }, already trimmed. Returns the new row's id.
export async function createTestUser(owner, values, password) {
  const max = config.sandbox.maxTestUsersPerDeveloper;
  if (await countTestUsers(owner) >= max) {
    throw new ServiceError(422, 'quota_exceeded', `You have reached the limit of ${max} test users. Delete one first.`);
  }
  if (!USERNAME_RE.test(values.username)) throw invalid('Username must be 3-40 characters: lowercase letters, digits, . _ -', { field: 'username' });
  if (!EMAIL_RE.test(values.email)) throw invalid('Enter a valid email address.', { field: 'email' });
  if (!values.firstName || !values.lastName) throw invalid('First and last name are required.', { field: values.firstName ? 'lastName' : 'firstName' });
  const problem = passwordProblem(password);
  if (problem) throw invalid(problem, { field: 'password' });

  let kcId;
  try {
    kcId = await sandboxAdmin.createUser({ ...values, emailVerified: true, password, temporary: false });
  } catch (err) {
    if (err instanceof KeycloakError && err.status === 409) {
      throw new ServiceError(409, 'duplicate_username', 'That username or email is already used in the sandbox. Try another.');
    }
    if (err instanceof KeycloakError && err.status < 500) throw new ServiceError(422, 'keycloak_rejected', err.message);
    throw err;
  }
  return insertTestUser({ owner, kcId, username: values.username });
}

export async function setTestUserPassword(row, password) {
  const problem = passwordProblem(password);
  if (problem) throw invalid(problem, { field: 'password' });
  try {
    await sandboxAdmin.resetPassword(row.kc_id, password, false);
  } catch (err) {
    if (err instanceof KeycloakError && err.status < 500) throw new ServiceError(422, 'keycloak_rejected', err.message);
    throw err;
  }
}

export async function removeTestUser(row) {
  await sandboxAdmin.deleteUser(row.kc_id).catch((err) => {
    if (!(err instanceof KeycloakError && err.status === 404)) throw err;
  });
  await deleteTestUser(row.id);
}
