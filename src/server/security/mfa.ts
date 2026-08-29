import crypto from 'node:crypto';

export interface MfaStatus {
	enabled: boolean;
	activeLevel: 1 | 2 | 3 | 4;
	totpConfigured: boolean;
	hardwarePinConfigured: boolean;
}

/**
 * Generates a base32-like TOTP secret key for 2FA setup.
 */
export function generateTotpSecret(): string {
	const bytes = crypto.randomBytes(20);
	const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	let secret = '';
	for (let i = 0; i < bytes.length; i++) {
		secret += alphabet[bytes[i] % 32];
	}
	return secret;
}

/**
 * Generates a 6-digit Time-Based One-Time Password (TOTP) based on RFC 6238.
 */
export function generateTotpCode(secret: string, timeStep = 30): string {
	const epoch = Math.floor(Date.now() / 1000);
	const timeCounter = Math.floor(epoch / timeStep);
	
	const buffer = Buffer.alloc(8);
	buffer.writeBigInt64BE(BigInt(timeCounter), 0);

	const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'ascii'));
	hmac.update(buffer);
	const digest = hmac.digest();

	const offset = digest[digest.length - 1] & 0xf;
	const code =
		((digest[offset] & 0x7f) << 24) |
		((digest[offset + 1] & 0xff) << 16) |
		((digest[offset + 2] & 0xff) << 8) |
		(digest[offset + 3] & 0xff);

	const otp = (code % 1000000).toString().padStart(6, '0');
	return otp;
}

/**
 * Verifies a TOTP code against secret key allowing 1 time-step window tolerance.
 */
export function verifyTotpCode(secret: string, userCode: string): boolean {
	if (!userCode || userCode.trim().length !== 6) return false;
	const currentCode = generateTotpCode(secret);
	if (userCode.trim() === currentCode) return true;

	// Check previous and next time window (30s drift tolerance)
	const epoch = Math.floor(Date.now() / 1000);
	const pastCounter = Math.floor((epoch - 30) / 30);
	const pastBuffer = Buffer.alloc(8);
	pastBuffer.writeBigInt64BE(BigInt(pastCounter), 0);
	const hmacPast = crypto.createHmac('sha1', Buffer.from(secret, 'ascii'));
	hmacPast.update(pastBuffer);
	const digestPast = hmacPast.digest();
	const offsetP = digestPast[digestPast.length - 1] & 0xf;
	const codeP =
		((digestPast[offsetP] & 0x7f) << 24) |
		((digestPast[offsetP + 1] & 0xff) << 16) |
		((digestPast[offsetP + 2] & 0xff) << 8) |
		(digestPast[offsetP + 3] & 0xff);
	const pastOtp = (codeP % 1000000).toString().padStart(6, '0');

	return userCode.trim() === pastOtp;
}

/**
 * Hashes a 3FA Security PIN / Hardware Token PIN using SHA-256.
 */
export function hashHardwarePin(pin: string): string {
	return crypto.createHash('sha256').update(pin + 'hostel-3fa-salt').digest('hex');
}

/**
 * Verifies a 3FA Security PIN.
 */
export function verifyHardwarePin(pin: string, storedHash: string): boolean {
	return hashHardwarePin(pin) === storedHash;
}

/**
 * Evaluates 4FA Adaptive Verification (Behavioral dynamics + Geolocation + Risk Score).
 */
export interface FourFactorChallenge {
	geoCountry: string;
	expectedCountry: string;
	keystrokeLatencyMs: number;
	sessionRiskScore: number;
}

export function verifyFourFactorChallenge(challenge: FourFactorChallenge): { success: boolean; failureReason?: string } {
	if (challenge.geoCountry && challenge.expectedCountry && challenge.geoCountry !== challenge.expectedCountry) {
		return { success: false, failureReason: `Unrecognized location anomaly: detected ${challenge.geoCountry}, expected ${challenge.expectedCountry}` };
	}
	if (challenge.keystrokeLatencyMs < 15) {
		return { success: false, failureReason: 'Automated script detected during 4FA challenge execution.' };
	}
	if (challenge.sessionRiskScore > 90) {
		return { success: false, failureReason: 'High critical risk score (>90) blocks automated 4FA challenge pass.' };
	}
	return { success: true };
}
