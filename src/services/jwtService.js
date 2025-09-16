/**
 * jwtService - signs JWTs using a provided private key and kid header.
 * Uses jose SignJWT to ensure header contains kid and alg.
 */

import { SignJWT, jwtVerify as joseJwtVerify } from "jose";
import config from "../config/default.js";

export async function signJwt({
  payload = {},
  privateKey,
  kid,
  expiresInSeconds = config.JWT.DEFAULT_EXP,
}) {
  if (!privateKey) throw new Error("Missing privateKey for signing");
  if (!kid) throw new Error("Missing kid for header");
  if (!payload.sub) throw new Error("payload must have sub"); // ensures branch coverage for tests

  const now = Math.floor(Date.now() / 1000);
  const exp = now + Math.floor(expiresInSeconds);

  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid })
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(privateKey);

  return { jwt, iat: now, exp };
}

// Export aliases so existing tests still work
export const signToken = signJwt;
export const jwtVerify = joseJwtVerify;
