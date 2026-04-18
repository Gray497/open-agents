import { type NextRequest, NextResponse } from "next/server";
import { encrypt } from "@/lib/crypto";
import { upsertUser } from "@/lib/db/users";
import { encryptJWE } from "@/lib/jwe/encrypt";
import { SESSION_COOKIE_NAME } from "@/lib/session/constants";

const isProd = process.env.NODE_ENV === "production";

export async function GET(req: NextRequest): Promise<Response> {
  const token = req.nextUrl.searchParams.get("token");

  if (!token) {
    return new Response("Missing token parameter", { status: 400 });
  }

  try {
    // Verify the token by calling Vercel's user API
    const userRes = await fetch("https://api.vercel.com/v2/user", {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!userRes.ok) {
      return new Response("Invalid Vercel token", { status: 401 });
    }

    const { user: userInfo } = (await userRes.json()) as {
      user: {
        id: string;
        email: string;
        username: string;
        name: string | null;
        avatar: string | null;
      };
    };

    const username = userInfo.username || userInfo.email || userInfo.id;

    // Store the token for later use (e.g., Vercel API calls)
    const userId = await upsertUser({
      provider: "vercel",
      externalId: userInfo.id,
      accessToken: encrypt(token),
      username,
      email: userInfo.email,
      name: userInfo.name ?? username,
      avatarUrl: userInfo.avatar ?? undefined,
    });

    // Create session (same structure as OAuth callback)
    const session = {
      created: Date.now(),
      authProvider: "vercel" as const,
      user: {
        id: userId,
        username,
        email: userInfo.email,
        name: userInfo.name ?? username,
        avatar: userInfo.avatar ?? "",
      },
    };

    const sessionToken = await encryptJWE(session, "1y");
    const expires = new Date(
      Date.now() + 365 * 24 * 60 * 60 * 1000,
    ).toUTCString();

    const redirectTo = req.nextUrl.searchParams.get("next") ?? "/";

    const response = NextResponse.redirect(
      new URL(redirectTo, req.url),
    );

    response.headers.set(
      "Set-Cookie",
      `${SESSION_COOKIE_NAME}=${sessionToken}; Path=/; Max-Age=${365 * 24 * 60 * 60}; Expires=${expires}; HttpOnly; ${isProd ? "Secure; " : ""}SameSite=Lax`,
    );

    return response;
  } catch (error) {
    console.error("Token login error:", error);
    return new Response("Authentication failed", { status: 500 });
  }
}
