import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
	const searchParams = request.nextUrl.searchParams;
	const token = searchParams.get('token');

	if (!token) {
		return NextResponse.redirect(
			new URL('/auth/confirm-email?error=token-missing', request.url)
		);
	}

	// TODO: Implement token verification logic here

	return NextResponse.json({ message: 'Token received', token });
}
