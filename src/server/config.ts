import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SERVER_DIR = path.dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = path.resolve(SERVER_DIR, '../..');

export const DEFAULT_DB_PATH =
	process.env.HOSTEL_DB_PATH ?? path.join(REPO_ROOT, 'data', 'hostel.db');

export const DEFAULT_UPLOADS_DIR =
	process.env.HOSTEL_UPLOADS_DIR ?? path.join(REPO_ROOT, 'uploads');

export const API_PORT = Number(process.env.HOSTEL_API_PORT ?? 3001);

export const API_HOST = process.env.HOSTEL_API_HOST ?? '0.0.0.0';

export const SESSION_COOKIE = 'hg_session';

export const SESSION_TTL_SECONDS = Number(process.env.HOSTEL_SESSION_TTL ?? 60 * 60 * 8);

export const COOKIE_SECURE = process.env.HOSTEL_COOKIE_SECURE === 'true';

export const MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024;

export const ALLOWED_ATTACHMENT_TYPES = new Set([
	'image/jpeg',
	'image/png',
	'image/gif',
	'image/webp'
]);

export const LOGIN_WINDOW_MS = 15 * 60 * 1000;
export const LOGIN_MAX_ATTEMPTS = 5;

export const COMMENT_WINDOW_MS = 2 * 60 * 1000;  // 2 minutes
export const COMMENT_MAX_ATTEMPTS = 5;  // 5 comments per 2 minutes

function parseOrigins(raw: string | undefined): Set<string> {
	const defaults = [
		'http://localhost:5173',
		'http://127.0.0.1:5173',
		'http://localhost:5174',
		'http://127.0.0.1:5174',
		'http://localhost:4173',
		'http://127.0.0.1:4173',
		'http://localhost:4174',
		'http://127.0.0.1:4174'
	];
	const extra = (raw ?? '')
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
	return new Set([...defaults, ...extra]);
}

export const ALLOWED_ORIGINS = parseOrigins(process.env.HOSTEL_CORS_ORIGINS);
