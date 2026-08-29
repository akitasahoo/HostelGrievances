import { describe, expect, it, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { applySchema } from './db/schema.ts';
import { encryptData, decryptData, encryptBuffer, decryptBuffer } from './security/encryption.ts';
import { calculateShannonEntropy, classifyPayloadThreat, evaluateThreatRisk } from './security/ml-engine.ts';
import { generateTotpSecret, generateTotpCode, verifyTotpCode, hashHardwarePin, verifyHardwarePin, verifyFourFactorChallenge } from './security/mfa.ts';
import { computeRecordHash, calculateMerkleRoot, verifyAuditChainIntegrity } from './security/merkle-audit.ts';
import { writeAudit } from './security/audit.ts';

describe('Cybersecurity Architecture Test Suite', () => {
	// 1. AES-256-GCM Envelope Encryption
	describe('AES-256-GCM Encryption Module', () => {
		it('should encrypt and decrypt string data correctly', () => {
			const originalText = 'Confidential Hostel Room 304 Student Details';
			const encrypted = encryptData(originalText);
			expect(encrypted.ciphertext).not.toBe(originalText);
			expect(encrypted.iv).toBeDefined();
			expect(encrypted.authTag).toBeDefined();

			const decrypted = decryptData(encrypted);
			expect(decrypted).toBe(originalText);
		});

		it('should encrypt and decrypt binary buffer data', () => {
			const buffer = Buffer.from('Sample attachment binary data stream');
			const encrypted = encryptBuffer(buffer);
			const decrypted = decryptBuffer(encrypted.encryptedBuffer, encrypted.iv, encrypted.authTag);
			expect(decrypted.toString()).toBe('Sample attachment binary data stream');
		});
	});

	// 2. Machine Learning Anomaly Engine & NLP Threat Classifier
	describe('ML Anomaly Engine & NLP Threat Classifier', () => {
		it('should compute Shannon entropy accurately', () => {
			const lowEntropy = 'aaaaabbbbb';
			const highEntropy = 'qW9#xK2$mZ8@vP4%';
			expect(calculateShannonEntropy(highEntropy)).toBeGreaterThan(calculateShannonEntropy(lowEntropy));
		});

		it('should classify SQL injection and XSS payloads', () => {
			const sqliPayload = "admin' UNION SELECT 1,2,3 FROM users--";
			const xssPayload = "<script>alert('xss')</script>";
			const safeText = 'The fan in room 102 is making a strange noise.';

			const sqliResult = classifyPayloadThreat(sqliPayload);
			expect(sqliResult.score).toBeGreaterThan(40);
			expect(sqliResult.detectedPatterns).toContain('SQL Injection Syntax');

			const xssResult = classifyPayloadThreat(xssPayload);
			expect(xssResult.score).toBeGreaterThan(40);
			expect(xssResult.detectedPatterns).toContain('XSS Attack Vector');

			const safeResult = classifyPayloadThreat(safeText);
			expect(safeResult.score).toBe(0);
		});

		it('should evaluate dynamic threat risk and recommend MFA elevation level', () => {
			const lowRisk = evaluateThreatRisk({
				ip: '192.168.1.1',
				userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
				failedLoginCount: 0
			});
			expect(lowRisk.riskScore).toBeLessThan(30);
			expect(lowRisk.recommendedMfaLevel).toBe(1);

			const highRisk = evaluateThreatRisk({
				ip: '10.0.0.99',
				userAgent: 'python-requests/2.25.1',
				failedLoginCount: 4,
				payload: "UNION SELECT * FROM users"
			});
			expect(highRisk.riskScore).toBeGreaterThan(50);
			expect(highRisk.recommendedMfaLevel).toBeGreaterThanOrEqual(2);
		});
	});

	// 3. Multi-Factor Authentication (2FA / 3FA / 4FA)
	describe('Multi-Factor Authentication Matrix', () => {
		it('should generate and verify RFC 6238 2FA TOTP codes', () => {
			const secret = generateTotpSecret();
			expect(secret.length).toBeGreaterThanOrEqual(16);

			const code = generateTotpCode(secret);
			expect(code).toHaveLength(6);
			expect(verifyTotpCode(secret, code)).toBe(true);
			expect(verifyTotpCode(secret, '000000')).toBe(false);
		});

		it('should hash and verify 3FA Hardware Security PINs', () => {
			const pin = '9876';
			const hash = hashHardwarePin(pin);
			expect(verifyHardwarePin('9876', hash)).toBe(true);
			expect(verifyHardwarePin('1234', hash)).toBe(false);
		});

		it('should evaluate 4FA adaptive contextual challenge', () => {
			const validChallenge = verifyFourFactorChallenge({
				geoCountry: 'US',
				expectedCountry: 'US',
				keystrokeLatencyMs: 120,
				sessionRiskScore: 10
			});
			expect(validChallenge.success).toBe(true);

			const botChallenge = verifyFourFactorChallenge({
				geoCountry: 'US',
				expectedCountry: 'US',
				keystrokeLatencyMs: 5, // Automated bot latency
				sessionRiskScore: 10
			});
			expect(botChallenge.success).toBe(false);
		});
	});

	// 4. Cryptographic Merkle Tree Hash-Chain Audit System
	describe('Cryptographic Merkle Audit Chain', () => {
		let db: Database.Database;

		beforeEach(() => {
			db = new Database(':memory:');
			applySchema(db);
		});

		it('should maintain a valid Merkle root and hash chain for audit events', () => {
			writeAudit(db, { action: 'user_login', actorId: 'u1', actorEmail: 's1@test.com', outcome: 'success', ip: '127.0.0.1' });
			writeAudit(db, { action: 'grievance_create', actorId: 'u1', actorEmail: 's1@test.com', outcome: 'success', ip: '127.0.0.1' });

			const verification = verifyAuditChainIntegrity(db);
			expect(verification.isValid).toBe(true);
			expect(verification.totalRecords).toBe(2);
			expect(verification.merkleRoot).toBeDefined();
			expect(verification.tamperedRecords).toHaveLength(0);
		});

		it('should detect unauthorized tampering of audit log entries', () => {
			writeAudit(db, { action: 'user_login', actorId: 'u1', actorEmail: 's1@test.com', outcome: 'success', ip: '127.0.0.1' });
			writeAudit(db, { action: 'grievance_delete', actorId: 'u1', actorEmail: 's1@test.com', outcome: 'success', ip: '127.0.0.1' });

			// Malicious direct database modification
			db.prepare("UPDATE audit_events SET action = 'tampered_action' WHERE id = 1").run();

			const verification = verifyAuditChainIntegrity(db);
			expect(verification.isValid).toBe(false);
			expect(verification.tamperedRecords).toContain(1);
		});
	});
});
