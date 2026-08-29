import { ALLOWED_ORIGINS } from '../config.ts';

export function isAllowedOrigin(origin: string | undefined, referer?: string): boolean {
	if (origin) {
		return ALLOWED_ORIGINS.has(origin);
	}
	if (referer) {
		try {
			const refUrl = new URL(referer);
			return ALLOWED_ORIGINS.has(refUrl.origin);
		} catch {
			return false;
		}
	}
	if (process.env.NODE_ENV === 'test') {
		return true;
	}
	return false;
}

export function reflectAllowedOrigin(origin: string | undefined): string | undefined {
	if (origin && ALLOWED_ORIGINS.has(origin)) return origin;
	return undefined;
}
