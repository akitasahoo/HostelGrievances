import type { Database } from 'better-sqlite3';
import type { Context } from 'hono';
import { getConnInfo } from '@hono/node-server/conninfo';
import { computeRecordHash } from './merkle-audit.ts';

export type AuditOutcome = 'success' | 'failure' | 'denied' | 'blocked';

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
	const timestamp = new Date().toISOString();

	// Structured JSON stdout log for SIEM / Log aggregation
	console.log(
		JSON.stringify({
			log_type: 'audit',
			timestamp,
			actor_id: event.actorId ?? null,
			actor_email: event.actorEmail ?? null,
			action: event.action,
			resource: event.resource ?? null,
			outcome: event.outcome,
			ip: event.ip ?? null,
			details: event.details ?? null
		})
	);

	try {
		// Fetch last audit event entry_hash to build continuous hash chain
		const lastRow = db.prepare('SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1').get() as
			| { entry_hash: string | null }
			| undefined;

		const prevHash = lastRow?.entry_hash || 'GENESIS_HASH';

		const recordData = {
			at: timestamp,
			actor_id: event.actorId ?? null,
			actor_email: event.actorEmail ?? null,
			action: event.action.slice(0, 80),
			resource: event.resource?.slice(0, 200) ?? null,
			outcome: event.outcome,
			ip: event.ip?.slice(0, 128) ?? null,
			details: event.details?.slice(0, 500) ?? null
		};

		const entryHash = computeRecordHash(recordData, prevHash);

		db.prepare(
			`INSERT INTO audit_events (at, actor_id, actor_email, action, resource, outcome, ip, details, prev_hash, entry_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		).run(
			recordData.at,
			recordData.actor_id,
			recordData.actor_email,
			recordData.action,
			recordData.resource,
			recordData.outcome,
			recordData.ip,
			recordData.details,
			prevHash,
			entryHash
		);
	} catch (err) {
		console.error('audit_write_failed', err);
	}
}

export const logAuditEvent = writeAudit;

export function listRecentAudit(db: Database, limit = 100) {
	return db
		.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT ?')
		.all(Math.min(Math.max(limit, 1), 500));
}
