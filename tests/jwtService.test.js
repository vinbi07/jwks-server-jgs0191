// tests/jwtService.test.js
import { signToken, jwtVerify } from "../src/services/jwtService.js";
import { importJWK } from "jose";
import crypto from "crypto";

describe("jwtService edge cases and branch coverage", () => {
  // Generate a real RSA key pair for signing tests
  let keyPair;
  beforeAll(() => {
    keyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 0x10001,
    });
  });

  test("signToken throws if payload missing sub", async () => {
    await expect(
      signToken({
        payload: {}, // missing 'sub'
        privateKey: keyPair.privateKey,
        kid: "abc123",
      })
    ).rejects.toThrow(/payload.*sub/i);
  });

  test("signToken throws if privateKey missing", async () => {
    await expect(
      signToken({
        payload: { sub: "user123" },
        kid: "abc123",
      })
    ).rejects.toThrow(/Missing privateKey/i);
  });

  test("signToken throws if kid missing", async () => {
    await expect(
      signToken({
        payload: { sub: "user123" },
        privateKey: keyPair.privateKey,
      })
    ).rejects.toThrow(/Missing kid/i);
  });

  test("signToken sets manual exp if provided", async () => {
    const now = Math.floor(Date.now() / 1000);
    const manualExp = now - 10; // expired in the past
    const { exp } = await signToken({
      payload: { sub: "user123" },
      privateKey: keyPair.privateKey,
      kid: "manual-exp",
      exp: manualExp, // force manual expiration
    });
    expect(exp).toBe(manualExp);
  });

  test("signToken returns valid JWT with default expiration", async () => {
    const { jwt, exp, iat } = await signToken({
      payload: { sub: "user123" },
      privateKey: keyPair.privateKey,
      kid: "abc123",
    });
    expect(typeof jwt).toBe("string");
    expect(exp).toBeGreaterThan(iat);
  });

  test("verifyToken throws if invalid key", async () => {
    const fakeToken = "fake.jwt.token";
    const fakeKey = { kty: "RSA", n: "fake", e: "AQAB" };
    const keyLike = await importJWK(fakeKey, "RS256");

    await expect(jwtVerify(fakeToken, keyLike)).rejects.toThrow();
  });
});
