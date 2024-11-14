export function isValidYouTubeURL(url: string): boolean {
	const youtubeRegex = /^(https?:\/\/)?(www\.)?(youtube\.com|youtu\.be)\/.+$/;

	if (!youtubeRegex.test(url)) {
		return false;
	}

	try {
		const parsedUrl = new URL(url);
		const hostname = parsedUrl.hostname.toLowerCase();

		if (
			hostname !== 'youtube.com' &&
			hostname !== 'www.youtube.com' &&
			hostname !== 'youtu.be'
		) {
			return false;
		}

		if (hostname === 'youtu.be') {
			return parsedUrl.pathname.length > 1;
		}

		const videoId = parsedUrl.searchParams.get('v');
		return !!videoId;
	} catch (error) {
		return false;
	}
}

export function isValidEmail(email: string): boolean {
	const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	return emailRegex.test(email);
}
