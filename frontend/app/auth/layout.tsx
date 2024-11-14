export default function AuthLayout({
	children,
}: {
	children: React.ReactNode;
}) {
	return <div className='w-full max-w-md'>{children}</div>;
}
