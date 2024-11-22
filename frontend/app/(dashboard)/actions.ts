'use server';

import axios from 'axios';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

export async function handleLogout() {
	'use server';

	try {
		const response = await axios.post(
			`${process.env.NEXT_PUBLIC_API_URL}/auth/logout`,
			{},
			{
				withCredentials: true,
			}
		);

		const setCookie = response.headers['set-cookie'];
		console.log('Set-Cookie:', setCookie);

		if (setCookie) {
			setCookie.forEach((cookie) => {
				const [name] = cookie.split('=');
				cookies().delete(name);
			});
		}

		redirect('/auth/login');
	} catch {
		redirect('/auth/login');
	}
}
