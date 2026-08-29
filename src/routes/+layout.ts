import { redirect } from '@sveltejs/kit';
import { getSession, hydrateSession } from '$lib/stores/auth.svelte';
import type { LayoutLoad } from './$types';

/** Session lives in the browser (cookie + localStorage cache). */
export const ssr = false;

/**
 * Route guard: every non-login route requires a session with the matching role.
 * The cookie session from /api/me is authoritative; localStorage is only a cache.
 */
export const load: LayoutLoad = async ({ url }) => {
	await hydrateSession();
	const user = getSession();

	if (url.pathname === '/login') {
		if (user) {
			redirect(307, user.role === 'student' ? '/student' : '/warden');
		}
		return {};
	}

	if (!user) {
		redirect(307, '/login');
	}

	const prefix = user.role === 'student' ? '/student' : '/warden';
	if (!url.pathname.startsWith(prefix)) {
		// Wrong role area — send them to their own dashboard instead of a 404.
		redirect(307, prefix);
	}

	return {};
};
