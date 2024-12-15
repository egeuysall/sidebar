'use client';

import Button from '@/components/ui/button';
import Input from '@/components/ui/input';
import axios from 'axios';
import toast from '@/lib/toast';
import Link from 'next/link';
import { ApiError } from '@/types';
import Divider from '@/components/ui/divider';
import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function SignupPage() {
	const [isLoading, setIsLoading] = useState(false);
	const [email, setEmail] = useState('');
	const [password, setPassword] = useState('');
	const router = useRouter();

	async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
		e.preventDefault();
		setIsLoading(true);

		try {
			const response = await axios.post(
				`${process.env.NEXT_PUBLIC_API_URL}/auth/signup`,
				{ email, password },
				{
					headers: {
						'Content-Type': 'application/json'
					},
					withCredentials: false
				}
			);

			if (response.status === 200) {
				router.push(response.data.redirect_url);
			}
		} catch (error) {
			if (axios.isAxiosError(error) && error.response) {
				const apiError = error.response.data as ApiError;
				toast({
					message: apiError.error,
					mode: 'error'
				});
			} else {
				toast({
					message: 'An unexpected error occurred',
					mode: 'error'
				});
			}
		} finally {
			setIsLoading(false);
		}
	}

	return (
		<div className='flex flex-col gap-6'>
			<div className='flex flex-col gap-2'>
				<h1>Get started with your dashboard</h1>
				<p>Free for 14 days &mdash; no credit card required.</p>
			</div>
			<form
				onSubmit={handleSubmit}
				className='flex flex-col gap-6'
			>
				<Input
					value={email}
					handleChange={(e) => setEmail(e.target.value)}
					label='Work email address'
					type='email'
					name='email'
					placeholder='name@company.com'
					required
				/>
				<Input
					value={password}
					handleChange={(e) => setPassword(e.target.value)}
					label='Password'
					type='password'
					name='password'
					placeholder='Minimum 8 characters, make it strong'
					required
				/>
				<Button
					className='w-full'
					type='submit'
					disabled={isLoading || !email || !password}
				>
					{isLoading ? 'Loading...' : 'Start for free'}
				</Button>

				<div className='text-center'>
					<Link
						className='no-underline'
						href='/auth/login'
					>
						or login instead
					</Link>
				</div>
			</form>
		</div>
	);
}
