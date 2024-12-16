import Link from "next/link";

export default function Header({ children }: { children: React.ReactNode }) {
  return (
    <header className="w-full">
      <nav className="flex items-center justify-between">
        <Link
          className="text-lg font-medium text-typography-strong no-underline"
          href="/dashboard"
        >
          Dashboard
        </Link>
        <div>{children}</div>
      </nav>
    </header>
  );
}
