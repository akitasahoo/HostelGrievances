import type { Database } from 'better-sqlite3';
import type { Context } from 'hono';
import { requireUser } from '../auth/session.ts';
import { assertCanViewGrievance, requireGrievance } from '../db/queries.ts';
import { HttpError } from '../http/errors.ts';
import type { GrievanceRow, SessionUser } from '../types/index.ts';

export function requireAccessibleGrievance(
	c: Context,
	db: Database,
	id: string
): { user: SessionUser; row: GrievanceRow } {
	const user = requireUser(c, db);
	const row = requireGrievance(db, id);
	assertCanViewGrievance(user, row);
	return { user, row };
}

export function assertStudentOwnsGrievance(user: SessionUser, row: GrievanceRow): void {
	if (user.role !== 'student' || row.student_id !== user.id) {
		throw new HttpError(403, 'unauthorized', 'Only the student owner can perform this action.');
	}
}
