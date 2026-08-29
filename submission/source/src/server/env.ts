import type { Database } from 'better-sqlite3';
import type { RateLimiter } from './security/rate-limit.ts';

export type AppEnv = {
	Variables: {
		db: Database;
		uploadsDir: string;
		loginLimiter: RateLimiter;
	};
};
