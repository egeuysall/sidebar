import { useState } from 'react';
import Button from '@/components/ui/button';

function SettingsBox({
	variant = 'default',
	title = 'Your Name',
	description = 'This will be your display name on Dashboard MVP',
	note,
	disabled = true,
	onSettingSubmit,
	children,
	submitText = 'Save Changes',
}: {
	variant?: string;
	title?: string;
	description?: string;
	note?: string | JSX.Element;
	disabled?: boolean;
	onSettingSubmit: () => any;
	children?: React.ReactNode;
	submitText?: string;
}) {
	// const { isSubmitting } = useLastSubmit();
	const [disableSubmit, setDisableSubmit] = useState(false);

	return (
		<form
			onSubmit={async (e) => {
				e.preventDefault();

				// const submitted = isSubmitting();

				// if (submitted) {
				// 	return;
				// }

				setDisableSubmit(true);

				console.log(onSettingSubmit, typeof onSettingSubmit);

				await onSettingSubmit()
					.then(() => {
						setDisableSubmit(false);
					})
					.catch((err: any) => {
						console.error(err);
						setDisableSubmit(false);
					});
			}}
			className={`flex flex-col border  ${
				variant === 'destructive'
					? 'border-error-stroke-weak'
					: 'border-stroke-weak'
			} rounded-md gap-2 w-full max-w-4xl`}
		>
			<div className='flex flex-col py-6 px-8 gap-4'>
				<div className='flex flex-col gap-4'>
					<h2 className='text-lg font-semibold'>{title}</h2>
					<p className='text-sm text-gray'>{description}</p>
				</div>
				{children}
			</div>

			<div
				className={`flex justify-between gap-8 items-center rounded-b-md px-8 py-6 ${
					variant === 'destructive' ? 'bg-light-red-bg' : 'bg-fill'
				}`}
			>
				<div className='text-sm text-low-contrast-text'>{note}</div>

				<Button
					variant={variant === 'destructive' ? 'destructive' : ''}
					type='submit'
					disabled={disabled || disableSubmit}
					loading={disableSubmit}
				>
					{submitText}
				</Button>
			</div>
		</form>
	);
}

export default SettingsBox;
