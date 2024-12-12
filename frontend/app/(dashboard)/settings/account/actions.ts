"use server";

import { User } from "@/types";

import axios from "axios";
import { cookies } from "next/headers";
import { parseNextCookie } from "@/lib/cookie";

const apiUrl = process.env.NEXT_PUBLIC_API_URL;

export async function updateUser({
  user,
  firstName,
  lastName,
  email,
}: {
  user: User | null;
  firstName?: string;
  lastName?: string;
  email?: string;
}) {
  if (!user) return;

  await axios
    .patch(
      `${apiUrl}/users`,
      {
        first_name: firstName,
        last_name: lastName,
        email,
      },
      {
        headers: {
          Cookie: `auth-token=${cookies().get("auth-token")?.value}`,
        },
      },
    )
    .catch(() => {
      return null;
    });
}

export async function updateUserEmail({
  user,
  email,
}: {
  user: User | null;
  email: string;
}) {
  if (!user || !email) return;

  const cookieStore = cookies();

  const response = await axios
    .patch(
      `${apiUrl}/users/email`,
      { email },
      {
        headers: {
          Cookie: cookieStore
            .getAll()
            .map((cookie) => `${cookie.name}=${cookie.value}`)
            .join("; "),
        },
      },
    )
    .then((res) => {
      return res.data;
    })
    .catch((err) => {
      return err.response.data;
    });

  return response;
}

export async function resendUpdateEmailConfirmation({
  user,
}: {
  user: User | null;
}) {
  const response = await axios.post(
    `${apiUrl}/users/resend-email`,
    {},
    {
      headers: { Cookie: `auth-token=${cookies().get("auth-token")?.value}` },
    },
  );
  return response.data;
}

export async function uploadAvatar({
  user,
  formData,
}: {
  user: User | null;
  formData: FormData;
}) {
  if (!user || !formData) return;

  const response = await axios
    .patch(`${apiUrl}/users/avatar`, formData, {
      headers: { Cookie: `auth-token=${cookies().get("auth-token")?.value}` },
    })
    .then((res) => {
      console.log(res.data);
      return res.data;
    })
    .catch((err) => {
      console.error(err);
      return null;
    });

  return response;
}

export async function verifyPassword({ password }: { password: string }) {
  await axios
    .post(
      `${apiUrl}/auth/verify-password`,
      {
        password,
      },
      {
        headers: { Cookie: `auth-token=${cookies().get("auth-token")?.value}` },
      },
    )
    .then(async (res) => {
      const setCookieHeader: string | string[] | undefined =
        res.headers["set-cookie"];
      if (setCookieHeader) {
        const cookieStore = cookies();

        setCookieHeader.forEach((c) => {
          const parsed = parseNextCookie(c);
          cookieStore.set(parsed.name, parsed.value, parsed.options);
        });
      }
      return res.data;
    })
    .catch((err) => {
      return err;
    });
}
