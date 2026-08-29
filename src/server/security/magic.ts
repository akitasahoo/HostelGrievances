import { ALLOWED_ATTACHMENT_TYPES } from '../config.ts';

export function sniffImageMime(bytes: Buffer): string | undefined {
	if (bytes.length < 12) return undefined;
	if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
	if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
		return 'image/png';
	}
	if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
		return 'image/gif';
	}
	if (bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP') {
		return 'image/webp';
	}
	return undefined;
}

export function isAllowedImageMime(mime: string): boolean {
	return ALLOWED_ATTACHMENT_TYPES.has(mime);
}
