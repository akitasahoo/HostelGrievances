import { dev } from '$app/environment';
import type { Handle } from '@sveltejs/kit';

const CSP = [
	"default-src 'self'",
	"img-src 'self' data: blob:",
	"style-src 'self' 'unsafe-inline'",
	"script-src 'self'" + (dev ? " 'unsafe-eval'" : ''),
	"connect-src 'self'" + (dev ? ' ws: wss:' : ''),
	"font-src 'self'",
	"object-src 'none'",
	"base-uri 'self'",
	"form-action 'self'",
	"frame-ancestors 'none'"
].join('; ');

export const handle: Handle = async ({ event, resolve }) => {
	const response = await resolve(event);
	response.headers.set('Content-Security-Policy', CSP);
	response.headers.set('X-Content-Type-Options', 'nosniff');
	response.headers.set('X-Frame-Options', 'DENY');
	response.headers.set('Referrer-Policy', 'no-referrer');
	response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
	response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
	response.headers.set('X-DNS-Prefetch-Control', 'off');
	return response;
};
