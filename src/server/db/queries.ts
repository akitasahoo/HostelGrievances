import type { Database } from 'better-sqlite3';
import { randomBytes } from 'node:crypto';
import { HttpError } from '../http/errors.ts';
import type {
	AttachmentRow,
	CommentRow,
	GrievanceRow,
	PublicGrievance,
	SessionUser,
	UserRow
} from '../types/index.ts';
import { toPublicAttachment, toPublicComment, toPublicGrievance, toPublicUser } from './map.ts';

export interface UserMfaRow {
	id: string;
	user_id: string;
	totp_secret: string | null;
	mfa_level: number;
	hardware_pin_hash: string | null;
	created_at: string;
	updated_at: string;
}

export interface ThreatLogRow {
	id: number;
	at: string;
	ip: string | null;
	user_id: string | null;
	risk_score: number;
	anomaly_factors: string | null;
	payload_threat: number;
	mfa_level: number;
}

export function findUserByEmail(db: Database, email: string): UserRow | undefined {
	return db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined;
}

export function findUserById(db: Database, id: string): UserRow | undefined {
	return db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
}

export function userCount(db: Database): number {
	const row = db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number };
	return row.n;
}

// User MFA queries
export function getUserMfa(db: Database, userId: string): UserMfaRow | undefined {
	return db.prepare('SELECT * FROM user_mfa WHERE user_id = ?').get(userId) as UserMfaRow | undefined;
}

export function upsertUserMfa(
	db: Database,
	userId: string,
	data: { totpSecret?: string | null; mfaLevel?: number; hardwarePinHash?: string | null }
): UserMfaRow {
	const now = new Date().toISOString();
	const existing = getUserMfa(db, userId);

	if (existing) {
		const newTotpSecret = data.totpSecret !== undefined ? data.totpSecret : existing.totp_secret;
		const newMfaLevel = data.mfaLevel !== undefined ? data.mfaLevel : existing.mfa_level;
		const newPinHash = data.hardwarePinHash !== undefined ? data.hardwarePinHash : existing.hardware_pin_hash;

		db.prepare(
			'UPDATE user_mfa SET totp_secret = ?, mfa_level = ?, hardware_pin_hash = ?, updated_at = ? WHERE user_id = ?'
		).run(newTotpSecret, newMfaLevel, newPinHash, now, userId);
	} else {
		const mfaId = `mfa-${randomBytes(6).toString('hex')}`;
		db.prepare(
			'INSERT INTO user_mfa (id, user_id, totp_secret, mfa_level, hardware_pin_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
		).run(mfaId, userId, data.totpSecret || null, data.mfaLevel || 1, data.hardwarePinHash || null, now, now);
	}

	return getUserMfa(db, userId)!;
}

// Threat Logs queries
export function recordThreatLog(
	db: Database,
	event: { ip?: string; userId?: string; riskScore: number; anomalyFactors?: string[]; payloadThreat?: number; mfaLevel: number }
): void {
	const now = new Date().toISOString();
	db.prepare(
		`INSERT INTO threat_logs (at, ip, user_id, risk_score, anomaly_factors, payload_threat, mfa_level)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
	).run(
		now,
		event.ip || '127.0.0.1',
		event.userId || null,
		event.riskScore,
		JSON.stringify(event.anomalyFactors || []),
		event.payloadThreat || 0,
		event.mfaLevel
	);
}

export function listRecentThreatLogs(db: Database, limit = 100): ThreatLogRow[] {
	return db.prepare('SELECT * FROM threat_logs ORDER BY id DESC LIMIT ?').all(limit) as ThreatLogRow[];
}

export function findGrievanceRow(db: Database, id: string): GrievanceRow | undefined {
	return db.prepare('SELECT * FROM grievances WHERE id = ?').get(id) as GrievanceRow | undefined;
}

export function listGrievanceRowsForStudent(db: Database, studentId: string): GrievanceRow[] {
	return db
		.prepare('SELECT * FROM grievances WHERE student_id = ? ORDER BY created_at DESC')
		.all(studentId) as GrievanceRow[];
}

export function listAllGrievanceRows(db: Database): GrievanceRow[] {
	return db.prepare('SELECT * FROM grievances ORDER BY created_at DESC').all() as GrievanceRow[];
}

export function listCommentRows(db: Database, grievanceId: string): CommentRow[] {
	return db
		.prepare('SELECT * FROM comments WHERE grievance_id = ? ORDER BY created_at ASC')
		.all(grievanceId) as CommentRow[];
}

export function listAttachmentRows(db: Database, grievanceId: string): AttachmentRow[] {
	return db
		.prepare('SELECT * FROM attachments WHERE grievance_id = ? ORDER BY created_at ASC')
		.all(grievanceId) as AttachmentRow[];
}

export function findAttachmentRow(db: Database, id: string): AttachmentRow | undefined {
	return db.prepare('SELECT * FROM attachments WHERE id = ?').get(id) as AttachmentRow | undefined;
}

export function assembleGrievance(db: Database, row: GrievanceRow): PublicGrievance {
	const studentRow = findUserById(db, row.student_id);
	if (!studentRow) {
		throw new HttpError(500, 'internal', 'Internal server error.');
	}
	const student = toPublicUser(studentRow);
	const attachments = listAttachmentRows(db, row.id).map(toPublicAttachment);
	const comments = listCommentRows(db, row.id).map((comment) => {
		const authorRow = findUserById(db, comment.author_id);
		if (!authorRow) {
			throw new HttpError(500, 'internal', 'Internal server error.');
		}
		return toPublicComment(comment, toPublicUser(authorRow));
	});
	return toPublicGrievance(row, student, attachments, comments);
}

export function requireGrievance(db: Database, id: string): GrievanceRow {
	const row = findGrievanceRow(db, id);
	if (!row) {
		throw new HttpError(404, 'not_found', 'Grievance was not found.');
	}
	return row;
}

export function assertCanViewGrievance(user: SessionUser, row: GrievanceRow): void {
	switch (user.role) {
		case 'warden':
			return;
		case 'student':
			if (row.student_id !== user.id) {
				throw new HttpError(403, 'unauthorized', 'You cannot access this grievance.');
			}
			return;
		default: {
			const _exhaustive: never = user.role;
			throw new HttpError(500, 'internal', 'Internal server error.');
			void _exhaustive;
		}
	}
}

export function nextGrievanceId(db: Database): string {
	return `GRV-${randomBytes(4).toString('hex').toUpperCase()}`;
}

export function nextCommentId(db: Database): string {
	return `cmt-${randomBytes(8).toString('hex')}`;
}

export function nextAttachmentId(db: Database): string {
	return `att-${randomBytes(8).toString('hex')}`;
}

export function touchGrievance(db: Database, id: string, updatedAt: string): void {
	db.prepare('UPDATE grievances SET updated_at = ? WHERE id = ?').run(updatedAt, id);
}
