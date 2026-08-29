import type { Database } from 'better-sqlite3';
import type { Context } from 'hono';
import { getConnInfo } from '@hono/node-server/conninfo';

export type AuditOutcome = 'success' | 'failure' | 'denied';

export function clientIp(c: Context): string {
	const forwarded = c.req.header('x-forwarded-for');
	if (forwarded) {
		return forwarded.split(',')[0]?.trim().slice(0, 128) || 'unknown';
	}
	const realIp = c.req.header('x-real-ip');
	if (realIp) {
		return realIp.slice(0, 128);
	}
	try {
		const info = getConnInfo(c);
		if (info?.remote?.address) {
			return info.remote.address;
		}
	} catch {
		// ignore
	}
	return 'unknown';
}

export function writeAudit(
	db: Database,
	event: {
		actorId?: string | null;
		actorEmail?: string | null;
		action: string;
		resource?: string | null;
		outcome: AuditOutcome;
		ip?: string | null;
		details?: string | null;
	}
): void {
	try {
		db.prepare(
			`INSERT INTO audit_events (at, actor_id, actor_email, action, resource, outcome, ip, details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		).run(
			new Date().toISOString(),
			event.actorId ?? null,
			event.actorEmail ?? null,
			event.action.slice(0, 80),
			event.resource?.slice(0, 200) ?? null,
			event.outcome,
			event.ip?.slice(0, 128) ?? null,
			event.details?.slice(0, 500) ?? null
		);
	} catch (err) {
		console.error('audit_write_failed', err);
	}
}

export function listRecentAudit(db: Database, limit = 100) {
	return db
		.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT ?')
		.all(Math.min(Math.max(limit, 1), 500));
}
