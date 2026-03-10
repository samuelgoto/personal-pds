import { randomBytes } from 'crypto';
import { db } from './db.js';
import { parseCookies } from './util.js';

export const SESSION_COOKIE = 'pds_session';
export const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;

const makeSessionCookie = (value, maxAgeSeconds) => (
  `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAgeSeconds}`
);

const clearSessionCookie = () => (
  `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`
);

async function getSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const sessionId = cookies[SESSION_COOKIE];
  if (!sessionId) return null;

  const result = await db.execute({
    sql: 'SELECT * FROM sessions WHERE id = ? AND expires_at > ?',
    args: [sessionId, Math.floor(Date.now() / 1000)],
  });

  if (result.rows.length === 0) return null;
  return result.rows[0];
}

export async function attachSession(req, res, next) {
  try {
    req.session = await getSessionFromRequest(req);
    next();
  } catch (err) {
    next(err);
  }
}

export async function createSession(user) {
  const sessionId = randomBytes(32).toString('hex');
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  await db.execute({
    sql: 'INSERT OR REPLACE INTO sessions (id, handle, did, expires_at) VALUES (?, ?, ?, ?)',
    args: [sessionId, user.handle, user.did, expiresAt],
  });
  return { sessionId, expiresAt };
}

export async function destroySession(req) {
  const sessionId = parseCookies(req.headers.cookie || '')[SESSION_COOKIE];
  if (!sessionId) return;
  await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [sessionId] });
}

export function setSessionCookie(res, sessionId, maxAgeSeconds = SESSION_TTL_SECONDS) {
  res.setHeader('Set-Cookie', makeSessionCookie(sessionId, maxAgeSeconds));
}

export function clearSessionCookieHeader(res) {
  res.setHeader('Set-Cookie', clearSessionCookie());
}

export function getLoginUrl(returnTo = '/', { autoReturn = false } = {}) {
  const params = new URLSearchParams();
  if (returnTo) params.set('return_to', returnTo);
  if (autoReturn) params.set('auto_return', '1');
  const query = params.toString();
  return query ? `/login?${query}` : '/login';
}
