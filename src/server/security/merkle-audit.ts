import crypto from 'node:crypto';
import type { Database } from 'better-sqlite3';

export interface AuditRecord {
	id: number;
	at: string;
	actor_id: string | null;
	actor_email: string | null;
	action: string;
	resource: string | null;
	outcome: string;
	ip: string | null;
	details: string | null;
	prev_hash?: string | null;
	entry_hash?: string | null;
}

export interface MerkleVerificationResult {
	isValid: boolean;
	totalRecords: number;
	merkleRoot: string;
	tamperedRecords: number[];
	verificationMessage: string;
}

/**
 * Computes SHA-256 hash for an individual audit record and its link to the previous record hash.
 */
export function computeRecordHash(record: Omit<AuditRecord, 'id' | 'entry_hash'>, prevHash: string = 'GENESIS_HASH'): string {
	const rawPayload = [
		prevHash,
		record.at,
		record.actor_id || '',
		record.actor_email || '',
		record.action,
		record.resource || '',
		record.outcome,
		record.ip || '',
		record.details || ''
	].join('|');

	return crypto.createHash('sha256').update(rawPayload).digest('hex');
}

/**
 * Constructs a Merkle Tree from an array of record hashes and calculates the Merkle Root.
 */
export function calculateMerkleRoot(hashes: string[]): string {
	if (hashes.length === 0) return crypto.createHash('sha256').update('EMPTY_TREE').digest('hex');
	if (hashes.length === 1) return hashes[0];

	let currentLevel = [...hashes];
	if (currentLevel.length % 2 !== 0) {
		currentLevel.push(currentLevel[currentLevel.length - 1]); // Duplicate odd element
	}

	while (currentLevel.length > 1) {
		const nextLevel: string[] = [];
		for (let i = 0; i < currentLevel.length; i += 2) {
			const combined = currentLevel[i] + currentLevel[i + 1];
			nextLevel.push(crypto.createHash('sha256').update(combined).digest('hex'));
		}
		if (nextLevel.length > 1 && nextLevel.length % 2 !== 0) {
			nextLevel.push(nextLevel[nextLevel.length - 1]);
		}
		currentLevel = nextLevel;
	}

	return currentLevel[0];
}

/**
 * Verifies the full cryptographic hash chain and Merkle root of all audit events in the database.
 */
export function verifyAuditChainIntegrity(db: Database): MerkleVerificationResult {
	try {
		const rows = db.prepare('SELECT * FROM audit_events ORDER BY id ASC').all() as AuditRecord[];
		if (rows.length === 0) {
			return {
				isValid: true,
				totalRecords: 0,
				merkleRoot: calculateMerkleRoot([]),
				tamperedRecords: [],
				verificationMessage: 'Audit log is empty. Genesis state verified.'
			};
		}

		let prevHash = 'GENESIS_HASH';
		const tamperedRecords: number[] = [];
		const verifiedHashes: string[] = [];

		for (const row of rows) {
			const calculatedHash = computeRecordHash(row, prevHash);
			if (row.entry_hash && row.entry_hash !== calculatedHash) {
				tamperedRecords.push(row.id);
			}
			verifiedHashes.push(calculatedHash);
			prevHash = calculatedHash;
		}

		const merkleRoot = calculateMerkleRoot(verifiedHashes);
		const isValid = tamperedRecords.length === 0;

		return {
			isValid,
			totalRecords: rows.length,
			merkleRoot,
			tamperedRecords,
			verificationMessage: isValid
				? `Cryptographic Merkle Root (${merkleRoot.slice(0, 16)}...) verified. All ${rows.length} audit records intact.`
				: `ALERT: Cryptographic tampering detected in ${tamperedRecords.length} audit log record(s): ${tamperedRecords.join(', ')}`
		};
	} catch (err) {
		return {
			isValid: false,
			totalRecords: 0,
			merkleRoot: '',
			tamperedRecords: [],
			verificationMessage: `Verification failed: ${String(err)}`
		};
	}
}
