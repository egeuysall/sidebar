'use client';

import axios from 'axios';

export default function Signup() {
	async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
		e.preventDefault();

		try {
			const formData = new FormData(e.currentTarget);
			const email = formData.get('email') as string;
			const password = formData.get('password') as string;

			const response = await axios.post(
				`${process.env.NEXT_PUBLIC_API_URL}/auth/signup`,
				{ email, password },
				{
					headers: {
						'Content-Type': 'application/json',
					},
					withCredentials: true,
				}
			);

			console.log(response.data);

			if (response.status === 200) {
				window.location.href = response.data.redirect_url;
			}
		} catch (error) {
			console.error(error);
		}
	}

	return (
		<div>
			<h1>Signup</h1>
			<form
				onSubmit={handleSubmit}
				className='flex flex-col gap-4'
			>
				<input
					type='email'
					name='email'
					placeholder='Email'
					required
				/>
				<input
					type='password'
					name='password'
					placeholder='Password'
					required
				/>
				<button type='submit'>Signup</button>
			</form>
		</div>
	);
}
