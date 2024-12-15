"use client";

import toast from "@/lib/toast";
import { getResponseMessage } from "@/messages";
import { useRouter, useSearchParams, usePathname } from "next/navigation";
import { useEffect } from "react";

export default function DashboardPage() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const message = searchParams.get("message") || "";
  const errorMessage = searchParams.get("error") || "";

  useEffect(() => {
    if (message) {
      console.log(message);
      toast({
        message: getResponseMessage(message),
        mode: "success",
      });

      const newSearchParams = new URLSearchParams(searchParams.toString());
      newSearchParams.delete("message");

      router.replace(
        `${pathname}${
          newSearchParams.toString() ? `?${newSearchParams.toString()}` : ""
        }`,
        {
          scroll: false,
        },
      );
    } else if (errorMessage) {
      toast({
        message: getResponseMessage(errorMessage),
        mode: "error",
      });

      const newSearchParams = new URLSearchParams(searchParams.toString());
      newSearchParams.delete("error");

      router.replace(
        `${pathname}${
          newSearchParams.toString() ? `?${newSearchParams.toString()}` : ""
        }`,
        {
          scroll: false,
        },
      );
    }
  }, [errorMessage, message, router, searchParams, pathname]);

  return (
    <div>
      <h1>Dashboard</h1>
    </div>
  );
}
