import { createHash, randomBytes } from 'node:crypto';
import type { Database } from 'better-sqlite3';
import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { COOKIE_SECURE, SESSION_COOKIE, SESSION_TTL_SECONDS } from '../config.ts';
import { HttpError } from '../http/errors.ts';
import type { SessionUser } from '../types/index.ts';

function nowIso(): string {
	return new Date().toISOString();
}

function expiryIso(): string {
	return new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
}

export function hashSessionToken(token: string): string {
	return createHash('sha256').update(token).digest('hex');
}

export function createSession(db: Database, userId: string): string {
	const token = randomBytes(32).toString('base64url');
	db.prepare(
		'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'
	).run(hashSessionToken(token), userId, nowIso(), expiryIso());
	return token;
}

export function destroySession(db: Database, token: string): void {
	db.prepare('DELETE FROM sessions WHERE token = ?').run(hashSessionToken(token));
}

export function purgeExpiredSessions(db: Database): void {
	db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(nowIso());
}

export function readSessionUser(db: Database, token: string): SessionUser | undefined {
	const row = db
		.prepare(
			`SELECT u.id, u.name, u.email, u.role, u.room, u.created_at, s.expires_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = ?`
		)
		.get(hashSessionToken(token)) as (SessionUser & { expires_at: string }) | undefined;
	if (!row) return undefined;
	if (Date.parse(row.expires_at) <= Date.now()) {
		db.prepare('DELETE FROM sessions WHERE token = ?').run(hashSessionToken(token));
		return undefined;
	}
	return {
		id: row.id,
		name: row.name,
		email: row.email,
		role: row.role,
		room: row.room,
		created_at: row.created_at
	};
}

export function setSessionCookie(c: Context, token: string): void {
	const isProd = process.env.NODE_ENV === 'production';
	const isHttps = c.req.header('x-forwarded-proto') === 'https' || c.req.raw.url.startsWith('https:');
	setCookie(c, SESSION_COOKIE, token, {
		path: '/',
		httpOnly: true,
		secure: COOKIE_SECURE || isProd || isHttps,
		sameSite: 'Lax',
		maxAge: SESSION_TTL_SECONDS
	});
}

export function clearSessionCookie(c: Context): void {
	deleteCookie(c, SESSION_COOKIE, { path: '/' });
}

export function readSessionToken(c: Context): string | undefined {
	return getCookie(c, SESSION_COOKIE);
}

export function requireUser(c: Context, db: Database): SessionUser {
	const token = readSessionToken(c);
	if (!token) {
		throw new HttpError(401, 'unauthenticated', 'Authentication required.');
	}
	const user = readSessionUser(db, token);
	if (!user) {
		throw new HttpError(401, 'unauthenticated', 'Authentication required.');
	}
	return user;
}
