'use client'

import Button from "@/components/ui/button";
import Dropdown from "@/components/ui/dropdown";
import SettingsBox from "@/components/ui/settings-box";
import { DotsHorizontalIcon, GearIcon } from "@radix-ui/react-icons";
import Header from "@/components/ui/header";

export default function BillingPage() {
  return (
    <>
			<div className='flex justify-start w-full'>
				<SettingsBox
					title='Subscriptions'
					description=''
					onSettingSubmit={async () => {}}
          submitText='View Plans'
				>
					<div className="flex w-full justify-between items-center">
            <div>
              <span className='font-bold'>Dashboard Pro</span>
            </div>
            <div className="flex test-sm gap-4">
              <span>50,000 tracked conversions</span>
              <span>49.99 / mo</span>
						</div>
						<div className="flex justify-between items-center">
              <Dropdown menuItems={[
                {
                  id: 'cancel',
                  label: 'Cancel subscription',
                  handleClick: () => {},
                },
                {
                  id: 'cancel',
                  label: 'Renew subscription',
                  handleClick: () => {},
                },
              ]} showIcon={false}>
                <DotsHorizontalIcon />
              </Dropdown>
            </div>
					</div>
				</SettingsBox>
			</div>
		</>
  );
}
