import type { Context, MiddlewareHandler } from 'hono';
import type { AppEnv } from '../env.ts';
import { clientIp, logAuditEvent } from './audit.ts';

export const HONEYPOT_PATHS = [
	'/api/v1/system/debug',
	'/admin/db-backup.sql',
	'/api/config/keys',
	'/admin.php',
	'/wp-login.php',
	'/.env',
	'/api/internal/dump'
];

/**
 * Middleware for active honeypot deception traps.
 * Any bot or attacker probing decoy paths is immediately flagged, logged, and trapped with fake/blocked responses.
 */
export function honeypotTrapMiddleware(): MiddlewareHandler<AppEnv> {
	return async (c: Context<AppEnv>, next) => {
		const path = c.req.path.toLowerCase();
		
		if (HONEYPOT_PATHS.some((trap) => path === trap || path.startsWith(trap))) {
			const ip = clientIp(c);
			const db = c.get('db');
			
			// Log critical security audit event
			logAuditEvent(db, {
				action: 'HONEYPOT_TRAP_TRIGGERED',
				actorId: null,
				actorEmail: null,
				resource: path,
				outcome: 'blocked',
				ip,
				details: JSON.stringify({
					userAgent: c.req.header('user-agent'),
					severity: 'CRITICAL',
					message: 'Attacker or automated scanner hit deceptive honeypot trap path.'
				})
			});

			// Return deceptive 403 Forbidden with delay to slow down scanner threads
			await new Promise((resolve) => setTimeout(resolve, 500));

			return c.json(
				{
					error: 'Security Breach Protocol Triggered: Immediate Access Denied.',
					code: 'honeypot_trap_activated',
					incidentId: `INC-${Date.now()}`
				},
				403
			);
		}

		await next();
	};
}
