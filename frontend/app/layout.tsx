import type { Metadata } from 'next';
import localFont from 'next/font/local';
import './globals.css';
import { Toaster } from 'sonner';

const geistSans = localFont({
	src: './fonts/GeistVF.woff',
	variable: '--font-geist-sans',
	weight: '100 900',
});
const geistMono = localFont({
	src: './fonts/GeistMonoVF.woff',
	variable: '--font-geist-mono',
	weight: '100 900',
});

export const metadata: Metadata = {
	title: 'Go Dashboard',
	description: 'SaaS boilerplate built with Next.js and Go.',
};

export default function RootLayout({
	children,
}: Readonly<{
	children: React.ReactNode;
}>) {
	return (
		<html lang='en'>
			<body
				className={`${geistSans.variable} ${geistMono.variable} antialiased dark:dark text-typography-weak bg-background`}
			>
				<Toaster
					duration={3000}
					position='bottom-right'
				/>
				<div className='w-full min-h-screen font-sans antialiased flex flex-col justify-center items-center p-6'>
					{children}
				</div>
			</body>
		</html>
	);
}
