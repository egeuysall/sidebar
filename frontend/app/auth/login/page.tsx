'use client';

import Button from '@/components/ui/button';
import Input from '@/components/ui/input';
import axios from 'axios';
import toast from '@/lib/toast';
import Link from 'next/link';
import { ApiError } from '@/types';
import { useRouter } from 'next/navigation';
import { useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';

export default function LoginPage() {
	const searchParams = useSearchParams();
	const router = useRouter();
	const [isLoading, setIsLoading] = useState(false);
	const [email, setEmail] = useState('');
	const [password, setPassword] = useState('');

	useEffect(() => {
		const error = searchParams.get('error');
		if (error === 'confirm-email-token-invalid') {
			toast({
				message:
					'The confirmation link was invalid or has expired. Please login to request a new one.',
				mode: 'error'
			});
		}
	}, [searchParams]);

	async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
		e.preventDefault();

		setIsLoading(true);

		try {
			const response = await axios.post(
				`${process.env.NEXT_PUBLIC_API_URL}/auth/login`,
				{ email, password },
				{
					headers: {
						'Content-Type': 'application/json'
					},
					withCredentials: false
				}
			);

			if (response.status === 200) {
				toast({
					message: 'Logged in successfully',
					mode: 'success'
				});
				router.push('/dashboard');
			}
		} catch (error) {
			if (axios.isAxiosError(error) && error.response) {
				const apiError = error.response.data as ApiError;
				toast({
					message: 'Invalid credentials',
					mode: 'error'
				});
			} else {
				toast({
					message: 'An unexpected error occurred',
					mode: 'error'
				});
			}
		}

		setIsLoading(false);
	}

	return (
		<div className='flex flex-col gap-4'>
			<h1>Log in to your account</h1>
			<form
				onSubmit={handleSubmit}
				className='flex flex-col gap-6'
			>
				<Input
					label='Email address'
					type='email'
					name='email'
					placeholder='name@company.com'
					required
					value={email}
					handleChange={(e) => setEmail(e.target.value)}
				/>
				<Input
					label='Password'
					type='password'
					name='password'
					placeholder='Password'
					required
					value={password}
					handleChange={(e) => setPassword(e.target.value)}
					hint={
						<Link
							className='text-xs text-typography-weak'
							href='/auth/forgot-password'
						>
							Forgot password?
						</Link>
					}
				/>
				<Button
					className='w-full'
					type='submit'
					disabled={isLoading || !email || !password}
					loading={isLoading}
				>
					Continue with email
				</Button>

				<div className='text-center'>
					<Link
						className='no-underline'
						href='/auth/signup'
					>
						or sign up instead
					</Link>
				</div>
			</form>
		</div>
	);
}
