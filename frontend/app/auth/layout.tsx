import {Suspense} from "react";

export default function AuthLayout({
	children,
}: {
	children: React.ReactNode;
}) {
	return <Suspense>
		<div className='w-full max-w-md'>{children}</div>
	</Suspense>
}
