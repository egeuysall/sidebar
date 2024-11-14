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
			const formData = new FormData(e.currentTarget);
			setEmail(formData.get('email') as string);
			setPassword(formData.get('password') as string);

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

			if (response.status === 200) {
				router.push(response.data.redirect_url);
			}
		} catch (error) {
			if (axios.isAxiosError(error) && error.response) {
				const apiError = error.response.data as ApiError;
				toast({
					message: apiError.error,
					mode: 'error',
				});
			} else {
				toast({
					message: 'An unexpected error occurred',
					mode: 'error',
				});
			}
		} finally {
			setIsLoading(false);
		}
	}

	return (
		<div className='flex flex-col gap-4'>
			<h1>Create your account</h1>
			<form
				onSubmit={handleSubmit}
				className='flex flex-col gap-6'
			>
				<Input
					value={email}
					handleChange={(e) => setEmail(e.target.value)}
					label='Email'
					type='email'
					name='email'
					placeholder='Email'
					required
				/>
				<Input
					value={password}
					handleChange={(e) => setPassword(e.target.value)}
					label='Password'
					type='password'
					name='password'
					placeholder='Password'
					required
				/>
				<Button
					className='w-full'
					type='submit'
					disabled={isLoading || !email || !password}
				>
					{isLoading ? 'Loading...' : 'Continue with email'}
				</Button>
				<p>
					By signing up, you agree to our{' '}
					<Link href='/legal/terms'>Terms of Service</Link> and{' '}
					<Link href='/legal/privacy'>Privacy Policy</Link>.
				</p>
				<Divider className='max-w-[20px]' />
				<p>
					Already have an account? <Link href='/auth/login'>Login</Link>
				</p>
			</form>
		</div>
	);
}
