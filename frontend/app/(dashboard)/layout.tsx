'use client';

import Header from '@/components/ui/header';
import Dropdown from '@/components/ui/dropdown';
import { ExitIcon, GearIcon } from '@radix-ui/react-icons';
import { handleLogout } from './actions';

export default function Layout({ children }: { children: React.ReactNode }) {
	const menuItems = [
		{
			id: 'settings',
			label: 'Settings',
			icon: <GearIcon />,
			href: '/settings/account',
		},
		{
			id: 'logout',
			label: 'Logout',
			icon: <ExitIcon />,
			handleClick: async () => {
				await handleLogout();
			},
		},
	];

	return (
		<div className='flex flex-col w-full flex-grow justify-center items-center'>
			<Header>
				<Dropdown menuItems={menuItems}>Account</Dropdown>
			</Header>

			<div className='w-full max-w-screen-xl h-full flex-grow flex flex-col justify-center items-center'>
				{children}
			</div>
		</div>
	);
}
