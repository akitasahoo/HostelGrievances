import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import {
	clearSessionCookie,
	createSession,
	destroySession,
	purgeExpiredSessions,
	readSessionToken,
	requireUser,
	setSessionCookie
} from '../auth/session.ts';
import { verifyPassword } from '../auth/passwords.ts';
import { findUserByEmail } from '../db/queries.ts';
import { toPublicUser } from '../db/map.ts';
import { HttpError } from '../http/errors.ts';
import { clientIp, writeAudit } from '../security/audit.ts';
import { LIMITS } from '../security/limits.ts';

export const authRoutes = new Hono<AppEnv>();

authRoutes.post('/login', async (c) => {
	const db = c.get('db');
	const limiter = c.get('loginLimiter');
	const ip = clientIp(c);
	let body: unknown;
	try {
		body = await c.req.json();
	} catch {
		throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
	}
	if (!body || typeof body !== 'object') {
		throw new HttpError(400, 'bad_request', 'Request body must be JSON.');
	}
	const email =
		'email' in body && typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
	const password = 'password' in body && typeof body.password === 'string' ? body.password : '';
	if (!email || !password) {
		throw new HttpError(400, 'bad_request', 'Email and password are required.');
	}
	if (email.length > LIMITS.emailMax || password.length > LIMITS.passwordMax) {
		throw new HttpError(400, 'bad_request', 'Email and password are required.');
	}

	const rateKey = `${ip}|${email}`;
	const limited = limiter.consume(rateKey);
	if (!limited.ok) {
		writeAudit(db, {
			actorEmail: email,
			action: 'login',
			outcome: 'denied',
			ip,
			details: 'rate_limited'
		});
		c.header('Retry-After', String(limited.retryAfterSeconds));
		throw new HttpError(429, 'rate_limited', 'Too many sign-in attempts. Try again later.');
	}

	const user = findUserByEmail(db, email);
	const passwordOk = verifyPassword(password, user?.password_hash);
	if (!user || !passwordOk) {
		writeAudit(db, {
			actorEmail: email,
			action: 'login',
			outcome: 'failure',
			ip
		});
		throw new HttpError(401, 'unauthenticated', 'Invalid email or password.');
	}

	purgeExpiredSessions(db);
	limiter.reset(rateKey);
	const token = createSession(db, user.id);
	setSessionCookie(c, token);
	writeAudit(db, {
		actorId: user.id,
		actorEmail: user.email,
		action: 'login',
		outcome: 'success',
		ip
	});
	return c.json({ user: toPublicUser(user) });
});

authRoutes.post('/logout', (c) => {
	const db = c.get('db');
	const token = readSessionToken(c);
	if (token) {
		destroySession(db, token);
	}
	clearSessionCookie(c);
	writeAudit(db, {
		action: 'logout',
		outcome: 'success',
		ip: clientIp(c)
	});
	return c.json({ ok: true });
});

authRoutes.get('/me', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	return c.json({ user: toPublicUser(user) });
});
