import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import type { Database } from 'better-sqlite3';
import type { AppEnv } from './env.ts';
import { handleError, HttpError } from './http/errors.ts';
import { authRoutes } from './routes/auth.ts';
import { grievanceRoutes } from './routes/grievances.ts';
import { attachmentRoutes } from './routes/attachments.ts';
import { auditRoutes } from './routes/audit.ts';
import { csrfOriginCheck } from './security/csrf.ts';
import { createRateLimiter } from './security/rate-limit.ts';
import { reflectAllowedOrigin } from './security/origins.ts';
import { LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_MS } from './config.ts';
import { MAX_REQUEST_BYTES } from './security/limits.ts';
import { clientIp } from './security/audit.ts';

export type CreateAppOptions = {
	db: Database;
	uploadsDir: string;
};

export function createApp(options: CreateAppOptions) {
	const app = new Hono<AppEnv>();
	const loginLimiter = createRateLimiter({ windowMs: LOGIN_WINDOW_MS, max: LOGIN_MAX_ATTEMPTS });
	const apiLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 200 });

	app.use('*', async (c, next) => {
		c.set('db', options.db);
		c.set('uploadsDir', options.uploadsDir);
		c.set('loginLimiter', loginLimiter);
		await next();
	});

	app.use('/api/*', async (c, next) => {
		const ip = clientIp(c);
		const limited = apiLimiter.consume(ip);
		if (!limited.ok) {
			c.header('Retry-After', String(limited.retryAfterSeconds));
			throw new HttpError(429, 'rate_limited', 'Too many requests. Try again later.');
		}
		await next();
	});

	app.use(
		'*',
		secureHeaders({
			xFrameOptions: 'DENY',
			xContentTypeOptions: 'nosniff',
			referrerPolicy: 'no-referrer',
			crossOriginResourcePolicy: 'same-site',
			strictTransportSecurity: 'max-age=31536000; includeSubDomains; preload'
		})
	);

	app.use('*', async (c, next) => {
		await next();
		c.header('Cache-Control', c.res.headers.get('Cache-Control') ?? 'no-store');
		c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
	});

	app.use(
		'/api/*',
		cors({
			origin: (origin) => reflectAllowedOrigin(origin) ?? '',
			credentials: true,
			allowMethods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
			allowHeaders: ['Content-Type']
		})
	);

	app.use(
		'/api/*',
		bodyLimit({
			maxSize: MAX_REQUEST_BYTES,
			onError: (c) => c.json({ error: 'Request is too large.', code: 'bad_request' }, 413)
		})
	);

	app.use('/api/*', csrfOriginCheck);

	app.onError((err, c) => handleError(err, c));

	app.notFound((c) => c.json({ error: 'Not found.', code: 'not_found' }, 404));

	app.get('/api/health', (c) => c.json({ ok: true }));
	app.route('/api', authRoutes);
	app.route('/api/grievances', grievanceRoutes);
	app.route('/api/attachments', attachmentRoutes);
	app.route('/api/audit', auditRoutes);

	app.all('/api/*', () => {
		throw new HttpError(404, 'not_found', 'Not found.');
	});

	return app;
}
