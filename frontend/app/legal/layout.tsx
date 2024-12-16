import Logo from '@/components/ui/logo';

export default function LegalLayout({
	children
}: {
	children: React.ReactNode;
}) {
	return (
		<div className='flex flex-col h-full justify-between items-center flex-grow py-8 gap-6'>
			<Logo />
			<div className='w-full max-w-lg flex flex-col gap-6'>{children}</div>
		</div>
	);
}
