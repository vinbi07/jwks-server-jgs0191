import { signToken, jwtVerify } from "../src/services/jwtService.js";
import { importJWK } from "jose";

describe("jwtService edge cases", () => {
  test("signToken throws if payload missing sub", async () => {
    const dummyKey = { privateKey: {}, kid: "abc123" };

    await expect(
      signToken({
        payload: {}, // missing 'sub'
        privateKey: dummyKey.privateKey,
        kid: dummyKey.kid,
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
    const dummyKey = { privateKey: {} };
    await expect(
      signToken({
        payload: { sub: "user123" },
        privateKey: dummyKey.privateKey,
      })
    ).rejects.toThrow(/Missing kid/i);
  });

  test("verifyToken throws if invalid key", async () => {
    const fakeToken = "fake.jwt.token";
    const fakeKey = { kty: "RSA", n: "fake", e: "AQAB" };
    const keyLike = await importJWK(fakeKey, "RS256");

    await expect(jwtVerify(fakeToken, keyLike)).rejects.toThrow();
  });
});
