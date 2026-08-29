import { mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { randomBytes } from 'node:crypto';
import { MAX_ATTACHMENT_BYTES } from '../config.ts';
import { HttpError } from '../http/errors.ts';
import { LIMITS } from '../security/limits.ts';
import { isAllowedImageMime, sniffImageMime } from '../security/magic.ts';

const MIME_EXTENSION: Record<string, string> = {
	'image/jpeg': '.jpg',
	'image/png': '.png',
	'image/gif': '.gif',
	'image/webp': '.webp'
};

export function ensureUploadsDir(dir: string): void {
	mkdirSync(dir, { recursive: true });
}

export function resetUploadsDir(dir: string): void {
	if (existsSync(dir)) {
		rmSync(dir, { recursive: true, force: true });
	}
	mkdirSync(dir, { recursive: true });
}

export function originalBasename(filename: string): string {
	const base = filename.replace(/\\/g, '/').split('/').pop() ?? 'upload';
	const cleaned = base.replace(/[\0\r\n]/g, '').trim();
	return cleaned.length > 0 ? cleaned.slice(0, LIMITS.filenameMax) : 'upload';
}

export function extensionForMime(mime: string): string {
	return MIME_EXTENSION[mime] ?? '.bin';
}

export function newStoredName(mime: string): string {
	return `${randomBytes(16).toString('hex')}${extensionForMime(mime)}`;
}

export function assertPermittedAttachment(mime: string, size: number): void {
	if (!isAllowedImageMime(mime)) {
		throw new HttpError(400, 'bad_request', 'Attachments must be JPEG, PNG, GIF, or WebP images.');
	}
	if (size <= 0) {
		throw new HttpError(400, 'bad_request', 'Attachment file is empty.');
	}
	if (size > MAX_ATTACHMENT_BYTES) {
		throw new HttpError(400, 'bad_request', 'Attachment must be 2 MB or smaller.');
	}
}

export function scanFileBuffer(bytes: Buffer): void {
	const text = bytes.toString('ascii');
	// Check for embedded PHP headers or script tags (e.g. polyglot upload attacks)
	if (text.includes('<?php') || text.includes('<?=') || /<script\b[^>]*>/i.test(text)) {
		throw new HttpError(400, 'bad_request', 'Malicious script signature detected in attachment.');
	}
}

export async function bufferFromUpload(file: File): Promise<{ bytes: Buffer; mime: string }> {
	const bytes = Buffer.from(await file.arrayBuffer());
	if (bytes.byteLength > MAX_ATTACHMENT_BYTES) {
		throw new HttpError(400, 'bad_request', 'Attachment must be 2 MB or smaller.');
	}
	const mime = sniffImageMime(bytes);
	if (!mime) {
		throw new HttpError(400, 'bad_request', 'Attachments must be JPEG, PNG, GIF, or WebP images.');
	}
	assertPermittedAttachment(mime, bytes.byteLength);
	scanFileBuffer(bytes);
	return { bytes, mime };
}

function assertInsideUploads(uploadsDir: string, storedName: string): string {
	if (
		!storedName ||
		storedName.includes('/') ||
		storedName.includes('\\') ||
		storedName.includes('..') ||
		storedName.includes('\0')
	) {
		throw new HttpError(404, 'not_found', 'Attachment file was not found.');
	}
	if (!/^[a-zA-Z0-9._-]+$/.test(storedName)) {
		throw new HttpError(404, 'not_found', 'Attachment file was not found.');
	}
	const root = resolve(uploadsDir);
	const full = resolve(join(uploadsDir, storedName));
	if (full !== root && !full.startsWith(root + sep)) {
		throw new HttpError(404, 'not_found', 'Attachment file was not found.');
	}
	return full;
}

export function writeStoredFile(uploadsDir: string, storedName: string, bytes: Buffer): void {
	ensureUploadsDir(uploadsDir);
	const full = assertInsideUploads(uploadsDir, storedName);
	writeFileSync(full, bytes);
}

export function readStoredFile(uploadsDir: string, storedName: string): Buffer {
	const full = assertInsideUploads(uploadsDir, storedName);
	if (!existsSync(full)) {
		throw new HttpError(404, 'not_found', 'Attachment file was not found.');
	}
	return readFileSync(full);
}

export function listStoredNames(uploadsDir: string): string[] {
	if (!existsSync(uploadsDir)) return [];
	return readdirSync(uploadsDir).filter((name) => name !== '.gitkeep');
}

export function contentDispositionAttachment(filename: string): string {
	const ascii = originalBasename(filename)
		.replace(/[^\x20-\x7E]/g, '_')
		.replace(/["\\;]/g, '_');
	const encoded = encodeURIComponent(originalBasename(filename));
	return `inline; filename="${ascii.slice(0, 80) || 'attachment'}"; filename*=UTF-8''${encoded}`;
}
