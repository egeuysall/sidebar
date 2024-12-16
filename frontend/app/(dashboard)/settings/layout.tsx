"use client";

import Link from "next/link";
import {
  PersonIcon,
  ReaderIcon,
  BellIcon,
  ChevronLeftIcon,
} from "@radix-ui/react-icons";
import { WebhookIcon, KeyIcon } from "lucide-react";
import { usePathname } from "next/navigation";
export default function SettingsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const links = [
    {
      id: "account",
      label: "Account",
      href: "/settings/account",
      icon: <PersonIcon className="h-4 w-4" />,
    },
    {
      id: "billing",
      label: "Billing",
      href: "/settings/billing",
      icon: <ReaderIcon className="h-4 w-4" />,
    },
    {
      id: "notifications",
      label: "Notifications",
      href: "/settings/notifications",
      icon: <BellIcon className="h-4 w-4" />,
    },
    {
      id: "integrations",
      label: "Integrations",
      href: "/settings/integrations",
      icon: <WebhookIcon className="h-4 w-4" />,
    },
    {
      id: "tokens",
      label: "API Keys",
      href: "/settings/tokens",
      icon: <KeyIcon className="h-4 w-4" />,
    },
  ];

  const pathname = usePathname();

  const selectedLink = links.find((link) => link.href === pathname);

  return (
    <div className="flex h-full w-full flex-grow gap-6">
      <div className="flex w-full max-w-[200px] flex-col items-start justify-start gap-4 py-8">
        <Link
          href="/dashboard"
          className="group flex w-full cursor-pointer items-center gap-2 no-underline"
        >
          <ChevronLeftIcon className="h-4 w-4 text-typography-strong transition-transform duration-200 group-hover:-translate-x-1" />
          <span className="font-semibold text-typography-strong">Settings</span>
        </Link>
        <ul className="flex w-full list-none flex-col gap-2">
          {links.map((link) => (
            <li key={link.id}>
              <Link
                className={`group no-underline hover:text-typography-strong ${
                  selectedLink?.id === link.id
                    ? "text-typography-strong"
                    : "text-typography-weak"
                }`}
                href={link.href}
              >
                <span
                  className={`${
                    selectedLink?.id === link.id
                      ? "text-typography-strong"
                      : "text-typography-weak"
                  } flex items-center gap-4 group-hover:text-typography-strong group-hover:opacity-100`}
                >
                  {link.icon}
                  {link.label}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      </div>
      <div className="flex h-full w-full flex-grow flex-col items-center justify-start gap-8 py-8">
        {children}
      </div>
    </div>
  );
}
