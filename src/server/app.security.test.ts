import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from './app.ts';
import { openDatabase } from './db/connection.ts';
import { seedDatabase } from './db/seed.ts';
import { hashSessionToken } from './auth/session.ts';
import type { Database } from 'better-sqlite3';
import { createRateLimiter } from './security/rate-limit.ts';

const PNG = Buffer.from(
	'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
	'base64'
);

function cookieHeader(res: Response): string {
	const anyHeaders = res.headers as Headers & { getSetCookie?: () => string[] };
	const list = anyHeaders.getSetCookie?.() ?? [];
	if (list.length > 0) {
		return list.map((v) => v.split(';')[0]).join('; ');
	}
	const raw = res.headers.get('set-cookie');
	return raw ? raw.split(';')[0] : '';
}

function rawSetCookie(res: Response): string {
	const anyHeaders = res.headers as Headers & { getSetCookie?: () => string[] };
	const list = anyHeaders.getSetCookie?.() ?? [];
	if (list.length > 0) return list.join('; ');
	return res.headers.get('set-cookie') ?? '';
}

async function login(app: ReturnType<typeof createApp>, email: string, password: string) {
	const res = await app.request('/api/login', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password })
	});
	const json = await res.json();
	return { res, json, cookie: cookieHeader(res) };
}

describe('HostelGrievance security controls', () => {
	let dir: string;
	let db: Database;
	let app: ReturnType<typeof createApp>;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'hg-sec-'));
		db = openDatabase(join(dir, 'hostel.db'));
		const uploadDir = join(dir, 'uploads');
		seedDatabase(db, uploadDir);
		app = createApp({ db, uploadsDir: uploadDir });
	});

	afterEach(() => {
		try {
			db.close();
		} catch {
			/* already closed */
		}
		rmSync(dir, { recursive: true, force: true });
	});

	it('sets HttpOnly SameSite session cookies and stores hashed tokens', async () => {
		const student = await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const setCookie = rawSetCookie(student.res).toLowerCase();
		expect(setCookie).toContain('httponly');
		expect(setCookie).toContain('samesite=strict');
		expect(setCookie).not.toContain('secure');

		const rawToken = student.cookie.replace('hg_session=', '');
		const rows = db.prepare('SELECT token FROM sessions').all() as { token: string }[];
		expect(rows.length).toBe(1);
		expect(rows[0].token).toBe(hashSessionToken(rawToken));
		expect(rows[0].token).not.toBe(rawToken);
	});

	it('blocks IDOR on grievance comments and attachments', async () => {
		const owner = await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const other = await login(app, 'priya.nair@giet.edu', 'GIET_Student_2026!');

		const comments = await app.request('/api/grievances/GRV-0001/comments', {
			headers: { Cookie: other.cookie }
		});
		expect(comments.status).toBe(403);

		const post = await app.request('/api/grievances/GRV-0001/comments', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: other.cookie },
			body: JSON.stringify({ body: 'I should not be able to comment here.' })
		});
		expect(post.status).toBe(403);

		const stolen = await app.request('/api/attachments/att-1', { headers: { Cookie: other.cookie } });
		expect(stolen.status).toBe(403);

		const allowed = await app.request('/api/attachments/att-1', { headers: { Cookie: owner.cookie } });
		expect(allowed.status).toBe(200);
		expect(allowed.headers.get('x-content-type-options')).toBe('nosniff');
	});

	it('rejects stored XSS payloads as HTML in comments while still storing text', async () => {
		const { cookie } = await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const payload = '<img src=x onerror=alert(1)>';
		const res = await app.request('/api/grievances/GRV-0001/comments', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Cookie: cookie },
			body: JSON.stringify({ body: payload })
		});
		expect(res.status).toBe(201);
		const json = await res.json();
		// After sanitization, HTML tags should be escaped
		expect(json.data.body).not.toBe(payload);
		expect(json.data.body).toContain('&lt;');
	});

	it('does not use the original filename as the on-disk stored name', async () => {
		const { cookie } = await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const form = new FormData();
		form.append('file', new File([PNG], '../../evil.png', { type: 'image/png' }));
		const uploaded = await app.request('/api/grievances/GRV-0008/attachments', {
			method: 'POST',
			headers: { Cookie: cookie },
			body: form
		});
		expect(uploaded.status).toBe(201);
		const meta = await uploaded.json();
		expect(meta.data.filename).toBe('evil.png');
		const row = db.prepare('SELECT stored_filename FROM attachments WHERE id = ?').get(meta.data.id) as {
			stored_filename: string;
		};
		expect(row.stored_filename).not.toContain('..');
		expect(row.stored_filename).toMatch(/^[a-f0-9]{32}\.png$/);
	});

	it('rejects HTML uploaded as a fake image/png', async () => {
		const { cookie } = await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const form = new FormData();
		form.append('file', new File(['<html><script>alert(1)</script></html>'], 'note.png', { type: 'image/png' }));
		const res = await app.request('/api/grievances/GRV-0008/attachments', {
			method: 'POST',
			headers: { Cookie: cookie },
			body: form
		});
		expect(res.status).toBe(400);
	});

	it('rejects cross-site mutating requests with a disallowed Origin', async () => {
		const { cookie } = await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const res = await app.request('/api/grievances/GRV-0001/comments', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Cookie: cookie,
				Origin: 'https://evil.example'
			},
			body: JSON.stringify({ body: 'cross site comment' })
		});
		expect(res.status).toBe(403);
	});

	it('does not reflect arbitrary CORS origins', async () => {
		const res = await app.request('/api/login', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Origin: 'https://evil.example'
			},
			body: JSON.stringify({ email: 'student.portal@giet.edu', password: 'GIET_Student_2026!' })
		});
		expect(res.headers.get('access-control-allow-origin')).not.toBe('https://evil.example');
	});

	it('hides unknown errors from clients', async () => {
		const broken = createApp({
			db: {
				prepare() {
					throw new Error('SQLITE_ERROR: secret schema dump');
				}
			} as unknown as Database,
			uploadsDir: join(dir, 'uploads')
		});
		const res = await broken.request('/api/login', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email: 'student.portal@giet.edu', password: 'GIET_Student_2026!' })
		});
		expect(res.status).toBe(500);
		const json = await res.json();
		expect(json.code).toBe('internal');
		expect(JSON.stringify(json)).not.toMatch(/SQLITE|secret schema/i);
	});

	it('exposes audit events to wardens only', async () => {
		await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const student = await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const denied = await app.request('/api/audit', { headers: { Cookie: student.cookie } });
		expect(denied.status).toBe(403);

		const warden = await login(app, 'warden.portal@giet.edu', 'GIET_Warden_2026!');
		const allowed = await app.request('/api/audit', { headers: { Cookie: warden.cookie } });
		expect(allowed.status).toBe(200);
		const json = await allowed.json();
		expect(Array.isArray(json.data)).toBe(true);
		expect(json.data.some((row: { action: string }) => row.action === 'login')).toBe(true);
	});

	it('rate-limits repeated failed logins', async () => {
		let last = 401;
		for (let i = 0; i < 6; i += 1) {
			const res = await app.request('/api/login', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email: 'student.portal@giet.edu', password: 'wrong-password' })
			});
			last = res.status;
		}
		expect(last).toBe(429);
	});

	it('sets Strict-Transport-Security (HSTS) headers', async () => {
		const res = await app.request('/api/health');
		expect(res.headers.get('strict-transport-security')).toBe(
			'max-age=31536000; includeSubDomains; preload'
		);
	});

	it('allows mutating requests with a valid Referer when Origin is missing', async () => {
		const { cookie } = await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const res = await app.request('/api/grievances/GRV-0001/comments', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Cookie: cookie,
				Referer: 'http://localhost:5173/student/grievances/GRV-0001'
			},
			body: JSON.stringify({ body: 'referer comment' })
		});
		expect(res.status).toBe(201);
	});

	it('blocks mutating requests with an invalid Referer when Origin is missing', async () => {
		const { cookie } = await login(app, 'student.portal@giet.edu', 'GIET_Student_2026!');
		const res = await app.request('/api/grievances/GRV-0001/comments', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Cookie: cookie,
				Referer: 'https://evil.example/malicious'
			},
			body: JSON.stringify({ body: 'invalid referer comment' })
		});
		expect(res.status).toBe(403);
	});

	it('evicts oldest entries when rate limiter Map size exceeds 10,000', () => {
		const limiter = createRateLimiter({ windowMs: 60 * 1000, max: 1 });
		for (let i = 0; i < 10000; i += 1) {
			limiter.consume(`key-${i}`);
		}
		const res = limiter.consume('key-10000');
		expect(res.ok).toBe(true);

		const oldestRes = limiter.consume('key-0');
		expect(oldestRes.ok).toBe(true);
	});
});
