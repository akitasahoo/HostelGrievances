export type RateLimitResult = { ok: true } | { ok: false; retryAfterSeconds: number };

type Bucket = { count: number; resetAt: number };

export type RateLimiter = {
	consume(key: string): RateLimitResult;
	reset(key: string): void;
};

export function createRateLimiter(options: { windowMs: number; max: number }): RateLimiter {
	const buckets = new Map<string, Bucket>();

	function prune(now: number): void {
		for (const [key, bucket] of buckets) {
			if (bucket.resetAt <= now) buckets.delete(key);
		}
	}

	return {
		consume(key: string): RateLimitResult {
			const now = Date.now();
			if (buckets.size >= 10_000) {
				prune(now);
				while (buckets.size >= 10_000) {
					const oldestKey = buckets.keys().next().value;
					if (oldestKey === undefined) break;
					buckets.delete(oldestKey);
				}
			}
			const existing = buckets.get(key);
			if (!existing || existing.resetAt <= now) {
				buckets.set(key, { count: 1, resetAt: now + options.windowMs });
				return { ok: true };
			}
			if (existing.count >= options.max) {
				return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)) };
			}
			existing.count += 1;
			return { ok: true };
		},
		reset(key: string): void {
			buckets.delete(key);
		}
	};
}
