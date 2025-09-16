/**
 * jwtService - signs JWTs using a provided private key and kid header.
 * Supports manual expiry for testing expired tokens.
 */

import { SignJWT, jwtVerify as joseJwtVerify } from "jose";
import config from "../config/default.js";

export async function signJwt({
  payload = {},
  privateKey,
  kid,
  expiresInSeconds,
  exp: manualExp, // optional manual expiry in seconds since epoch
}) {
  if (!privateKey) throw new Error("Missing privateKey for signing");
  if (!kid) throw new Error("Missing kid for header");
  if (!payload.sub) throw new Error("payload must have sub");

  const now = Math.floor(Date.now() / 1000);
  const exp =
    manualExp ?? now + (expiresInSeconds ?? config.JWT.DEFAULT_EXP ?? 300);

  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(privateKey);

  return { jwt, iat: now, exp };
}

// aliases for compatibility
export const signToken = signJwt;
export const jwtVerify = joseJwtVerify;
