export const LIMITS = {
	emailMax: 254,
	passwordMax: 256,
	titleMin: 5,
	titleMax: 200,
	descriptionMin: 20,
	descriptionMax: 8000,
	commentMin: 1,
	commentMax: 4000,
	filenameMax: 255
} as const;

export const MAX_REQUEST_BYTES = 2 * 1024 * 1024 + 256 * 1024;
