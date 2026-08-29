import type { Context, Next } from 'hono';
import { HttpError } from '../http/errors.ts';
import { isAllowedOrigin } from './origins.ts';

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

export async function csrfOriginCheck(c: Context, next: Next) {
	if (SAFE.has(c.req.method.toUpperCase())) {
		await next();
		return;
	}
	const origin = c.req.header('origin');
	const referer = c.req.header('referer');
	if (!isAllowedOrigin(origin, referer)) {
		throw new HttpError(403, 'unauthorized', 'Request origin is not allowed.');
	}
	await next();
}
