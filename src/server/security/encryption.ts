import crypto from 'node:crypto';

// Master key derived from environment or secure static fallback
const ENCRYPTION_SECRET = process.env.ENCRYPTION_KEY || 'hostel-grievance-master-aes-256-key-32-bytes!';
const ALGORITHM = 'aes-256-gcm';

function getDerivedKey(): Buffer {
	return crypto.scryptSync(ENCRYPTION_SECRET, 'hostel-salt-2026', 32);
}

export interface EncryptedData {
	ciphertext: string; // Base64
	iv: string; // Base64
	authTag: string; // Base64
}

/**
 * Encrypts a plain text string using AES-256-GCM envelope encryption.
 */
export function encryptData(plaintext: string): EncryptedData {
	const key = getDerivedKey();
	const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
	const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
	
	let encrypted = cipher.update(plaintext, 'utf8', 'base64');
	encrypted += cipher.final('base64');
	const authTag = cipher.getAuthTag().toString('base64');

	return {
		ciphertext: encrypted,
		iv: iv.toString('base64'),
		authTag
	};
}

/**
 * Decrypts AES-256-GCM encrypted payload.
 */
export function decryptData(encryptedData: EncryptedData): string {
	const key = getDerivedKey();
	const iv = Buffer.from(encryptedData.iv, 'base64');
	const authTag = Buffer.from(encryptedData.authTag, 'base64');
	const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
	
	decipher.setAuthTag(authTag);
	let decrypted = decipher.update(encryptedData.ciphertext, 'base64', 'utf8');
	decrypted += decipher.final('utf8');
	return decrypted;
}

/**
 * Encrypts a binary Buffer (e.g. file attachments).
 */
export function encryptBuffer(buffer: Buffer): { encryptedBuffer: Buffer; iv: string; authTag: string } {
	const key = getDerivedKey();
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
	
	const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
	const authTag = cipher.getAuthTag().toString('base64');

	return {
		encryptedBuffer: encrypted,
		iv: iv.toString('base64'),
		authTag
	};
}

/**
 * Decrypts a binary Buffer.
 */
export function decryptBuffer(encryptedBuffer: Buffer, ivBase64: string, authTagBase64: string): Buffer {
	const key = getDerivedKey();
	const iv = Buffer.from(ivBase64, 'base64');
	const authTag = Buffer.from(authTagBase64, 'base64');
	const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
	
	decipher.setAuthTag(authTag);
	return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}
