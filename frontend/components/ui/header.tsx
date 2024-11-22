import Link from 'next/link';

export default function Header({ children }: { children: React.ReactNode }) {
	return (
		<header className='w-full'>
			<nav className='flex justify-between items-center'>
				<Link
					className='text-lg font-medium text-typography-strong'
					href='/dashboard'
				>
					Dashboard
				</Link>
				<div>{children}</div>
			</nav>
		</header>
	);
}
