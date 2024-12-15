'use client';

import Link from 'next/link';
import {
	PersonIcon,
	ReaderIcon,
	BellIcon,
	ChevronLeftIcon
} from '@radix-ui/react-icons';
import { WebhookIcon, KeyIcon } from 'lucide-react';
import { usePathname } from 'next/navigation';
export default function SettingsLayout({
	children
}: {
	children: React.ReactNode;
}) {
	const links = [
		{
			id: 'account',
			label: 'Account',
			href: '/settings/account',
			icon: <PersonIcon className='w-4 h-4' />
		},
		{
			id: 'billing',
			label: 'Billing',
			href: '/settings/billing',
			icon: <ReaderIcon className='w-4 h-4' />
		},
		{
			id: 'notifications',
			label: 'Notifications',
			href: '/settings/notifications',
			icon: <BellIcon className='w-4 h-4' />
		},
		{
			id: 'integrations',
			label: 'Integrations',
			href: '/settings/integrations',
			icon: <WebhookIcon className='w-4 h-4' />
		},
		{
			id: 'tokens',
			label: 'API Keys',
			href: '/settings/tokens',
			icon: <KeyIcon className='w-4 h-4' />
		}
	];

	const pathname = usePathname();

	const selectedLink = links.find((link) => link.href === pathname);

	return (
		<div className='flex gap-6 w-full h-full flex-grow'>
			<div className='flex flex-col gap-4 justify-start items-start py-8 w-full max-w-[200px]'>
				<Link
					href='/dashboard'
					className='w-full flex gap-2 items-center group cursor-pointer'
				>
					<ChevronLeftIcon className='w-4 h-4 group-hover:-translate-x-1 text-typography-strong transition-transform duration-200' />
					<span className='text-typography-strong font-semibold'>Settings</span>
				</Link>
				<ul className='list-none flex flex-col gap-2 w-full'>
					{links.map((link) => (
						<li key={link.id}>
							<Link
								className={`hover:text-typography-strong group ${
									selectedLink?.id === link.id
										? 'text-typography-strong'
										: 'text-typography-weak'
								}`}
								href={link.href}
							>
								<span
									className={`${
										selectedLink?.id === link.id
											? 'text-typography-strong'
											: 'text-typography-weak'
									} flex gap-4 items-center group-hover:text-typography-strong group-hover:opacity-100`}
								>
									{link.icon}
									{link.label}
								</span>
							</Link>
						</li>
					))}
				</ul>
			</div>
			<div className='flex flex-col flex-grow items-center justify-start w-full gap-8 py-8 h-full'>
				{children}
			</div>
		</div>
	);
}
