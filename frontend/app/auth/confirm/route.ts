import { NextRequest, NextResponse } from 'next/server';
import axios from 'axios';

export async function GET(request: NextRequest) {
	const searchParams = request.nextUrl.searchParams;
	const token = searchParams.get('token');

	if (!token) {
		return NextResponse.redirect(
			new URL('/auth/confirm-email?error=token-missing', request.url)
		);
	}

	try {
		const response = await axios.post(
			`${process.env.NEXT_PUBLIC_API_URL}/auth/confirm`,
			{ token },
			{
				headers: {
					'Content-Type': 'application/json',
				},
				withCredentials: true,
			}
		);

		const setCookie = response.headers['set-cookie'];
		console.log('Set-Cookie:', setCookie);

		if (response.status !== 200) {
			return NextResponse.redirect(
				new URL('/auth/login?error=confirm-email-token-invalid', request.url)
			);
		}

		const redirectResponse = NextResponse.redirect(
			new URL('/dashboard', request.url)
		);

		// Forward the Set-Cookie header from the API response
		if (setCookie) {
			setCookie.forEach((cookie) => {
				redirectResponse.headers.append('Set-Cookie', cookie);
			});
		}

		return redirectResponse;
	} catch (error) {
		console.error('Error confirming email:', error);
		return NextResponse.redirect(
			new URL('/auth/login?error=confirm-email-token-invalid', request.url)
		);
	}
}
