import { Loader2 } from 'lucide-react';

export default function Spinner({ variant = 'light' }) {
	if (variant === 'light') {
		return <Loader2 className='text-typography-strong h-4 w-4 animate-spin' />;
	} else {
		return <Loader2 className='text-background h-4 w-4 animate-spin' />;
	}
}
