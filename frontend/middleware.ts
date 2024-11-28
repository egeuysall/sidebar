import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import axios from "axios";

export async function middleware(request: NextRequest) {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL;

  if (!apiUrl) {
    console.error("NEXT_PUBLIC_API_URL is not defined");
    return NextResponse.next();
  }

  try {
    // TODO: retain the initial request url to be redirected back to after login
    const response = await axios.get(`${apiUrl}/auth/identity`, {
      headers: {
        Cookie: request.headers.get("Cookie") || "",
      },
      withCredentials: true,
    });

    const pathname = request.nextUrl.pathname;

    const authPath = pathname.startsWith("/auth");

    // attempt to refresh the auth token
    if (response.status === 401) {
      const refreshToken = request.cookies.get("refresh-token")?.value;
      if (refreshToken) {
        const refreshResponse = await axios.post(
          `${apiUrl}/auth/refresh`,
          {},
          {
            headers: {
              Cookie: `refresh-token=${refreshToken}`,
            },
            withCredentials: true,
          },
        );

        if (refreshResponse.status === 200) {
          // Set cookies from the refresh response
          const response = NextResponse.next();
          const cookies = refreshResponse.headers["set-cookie"];
          if (cookies) {
            if (Array.isArray(cookies)) {
              cookies.forEach((cookie) => {
                response.headers.append("Set-Cookie", cookie);
              });
            } else if (typeof cookies === "string") {
              response.headers.append("Set-Cookie", cookies);
            }
          }

          return response;
        } else {
          return NextResponse.redirect(new URL("/auth/login", request.url));
        }
      }

      if (!authPath) {
        return NextResponse.redirect(new URL("/auth/login", request.url));
      }
    } else {
      // User exists and is authenticated
      const userData = response.data;

      console.log("user data", userData);

      const emailConfirmed = userData && userData.email_confirmed_at;
      const updateEmailRequested =
        userData &&
        userData.updated_email &&
        userData.updated_email_at &&
        !userData.updated_email_confirmed_at;

      const nextResponse = NextResponse.next();

      // Add cookies from the original response to all responses
      const cookies = response.headers["set-cookie"];

      if (cookies) {
        if (Array.isArray(cookies)) {
          cookies.forEach((cookie) => {
            nextResponse.headers.append("Set-Cookie", cookie);
          });
        } else {
          nextResponse.headers.append("Set-Cookie", cookies);
        }
      }

      if (
        userData &&
        emailConfirmed &&
        pathname.startsWith("/auth/confirm-email")
      ) {
        return NextResponse.redirect(new URL("/dashboard", request.url));
      }

      if (updateEmailRequested && pathname.startsWith("/auth/confirm")) {
        return nextResponse;
      }

      if (
        !emailConfirmed &&
        userData &&
        !pathname.startsWith("/auth/confirm-email")
      ) {
        const redirectResponse = NextResponse.redirect(
          new URL("/auth/confirm-email", request.url),
        );
        return redirectResponse;
      }

      if (
        !emailConfirmed &&
        userData &&
        pathname.startsWith("/auth/confirm-email")
      ) {
        return nextResponse;
      }

      if (
        !emailConfirmed &&
        userData &&
        !pathname.startsWith("/auth/confirm")
      ) {
        const redirectResponse = NextResponse.redirect(
          new URL("/auth/confirm-email", request.url),
        );
        return redirectResponse;
      }

      if (userData) {
        if ((authPath && pathname !== "/dashboard") || pathname === "/") {
          const redirectResponse = NextResponse.redirect(
            new URL("/dashboard", request.url),
          );

          return redirectResponse;
        }
      }

      return nextResponse;
    }
  } catch (err) {
    const pathname = request.nextUrl.pathname;

    const authPath = pathname.startsWith("/auth");
    const emailConfirmed = pathname.startsWith("/auth/confirm-email");

    if (!authPath || emailConfirmed) {
      return NextResponse.redirect(new URL("/auth/login", request.url));
    } else {
      return NextResponse.next();
    }
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    "/((?!api|_next/static|_next/image|favicon.ico).*)",
  ],
};
