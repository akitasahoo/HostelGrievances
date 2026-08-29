import { Hono } from 'hono';
import type { AppEnv } from '../env.ts';
import { findAttachmentRow } from '../db/queries.ts';
import { contentDispositionAttachment, readStoredFile } from '../storage/attachments.ts';
import { HttpError } from '../http/errors.ts';
import { requireAccessibleGrievance } from '../security/access.ts';
import { clientIp, writeAudit } from '../security/audit.ts';

export const attachmentRoutes = new Hono<AppEnv>();

attachmentRoutes.get('/:id', (c) => {
	const db = c.get('db');
	const row = findAttachmentRow(db, c.req.param('id'));
	if (!row) {
		throw new HttpError(404, 'not_found', 'Attachment was not found.');
	}
	const { user } = requireAccessibleGrievance(c, db, row.grievance_id);
	const bytes = readStoredFile(c.get('uploadsDir'), row.stored_filename);
	c.header('Content-Type', row.mime_type);
	c.header('Content-Length', String(bytes.length));
	c.header('X-Content-Type-Options', 'nosniff');
	c.header('Content-Security-Policy', "default-src 'none'; sandbox");
	c.header('Cache-Control', 'private, no-store');
	c.header('Content-Disposition', contentDispositionAttachment(row.original_filename));
	writeAudit(db, {
		actorId: user.id,
		actorEmail: user.email,
		action: 'attachment.read',
		resource: row.id,
		outcome: 'success',
		ip: clientIp(c)
	});
	return c.body(new Uint8Array(bytes));
});
