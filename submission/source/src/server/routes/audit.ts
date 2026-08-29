import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import { requireUser } from '../auth/session.ts';
import { listRecentAudit } from '../security/audit.ts';
import { HttpError } from '../http/errors.ts';

export const auditRoutes = new Hono<AppEnv>();

auditRoutes.get('/', (c) => {
	const db = c.get('db');
	const user = requireUser(c, db);
	if (user.role !== 'warden') {
		throw new HttpError(403, 'unauthorized', 'Only wardens can view the audit log.');
	}
	const limitRaw = Number(c.req.query('limit') ?? 100);
	const limit = Number.isFinite(limitRaw) ? limitRaw : 100;
	return c.json({ data: listRecentAudit(db, limit) });
});
