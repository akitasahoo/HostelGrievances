import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEYLEN = 32;

function scryptKey(password: string, salt: Buffer): Buffer {
	return scryptSync(password, salt, KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
}

export function hashPassword(password: string): string {
	const salt = randomBytes(16);
	const key = scryptKey(password, salt);
	return `scrypt:${SCRYPT_N}:${SCRYPT_R}:${SCRYPT_P}:${salt.toString('base64url')}:${key.toString('base64url')}`;
}

function verifyScrypt(password: string, stored: string): boolean {
	const parts = stored.split(':');
	if (parts.length !== 6) return false;
	const [, nRaw, rRaw, pRaw, saltB64, keyB64] = parts;
	const n = Number(nRaw);
	const r = Number(rRaw);
	const p = Number(pRaw);
	if (!Number.isFinite(n) || !Number.isFinite(r) || !Number.isFinite(p) || !saltB64 || !keyB64) {
		return false;
	}
	let salt: Buffer;
	let expected: Buffer;
	try {
		salt = Buffer.from(saltB64, 'base64url');
		expected = Buffer.from(keyB64, 'base64url');
	} catch {
		return false;
	}
	if (expected.length !== KEYLEN) return false;
	const actual = scryptSync(password, salt, KEYLEN, { N: n, r, p });
	if (actual.length !== expected.length) return false;
	return timingSafeEqual(actual, expected);
}

function verifySha256Legacy(password: string, stored: string): boolean {
	const parts = stored.split(':');
	if (parts.length !== 2) return false;
	const [scheme, hash] = parts;
	if (scheme !== 'sha256' || !hash) return false;
	const actual = createHash('sha256').update(password).digest();
	const expected = Buffer.from(hash, 'hex');
	if (actual.length !== expected.length) return false;
	return timingSafeEqual(actual, expected);
}

const TIMING_DUMMY = hashPassword('hostelgrievance-timing-dummy');

export function verifyPassword(password: string, stored: string | undefined): boolean {
	if (!stored) {
		verifyPassword(password, TIMING_DUMMY);
		return false;
	}
	if (stored.startsWith('scrypt:')) return verifyScrypt(password, stored);
	if (stored.startsWith('sha256:')) return verifySha256Legacy(password, stored);
	verifyPassword(password, TIMING_DUMMY);
	return false;
}
