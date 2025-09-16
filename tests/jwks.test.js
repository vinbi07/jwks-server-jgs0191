// tests/jwks.test.js
import request from "supertest";
import { createTestApp } from "./setupTestApp.js";
import keystore from "../src/keys/keystore.js";

let app;

beforeAll(async () => {
  app = await createTestApp();
});

describe("JWKS endpoint", () => {
  test("GET /.well-known/jwks.json returns only unexpired keys", async () => {
    const res = await request(app).get("/.well-known/jwks.json").expect(200);

    expect(res.body).toHaveProperty("keys");
    expect(Array.isArray(res.body.keys)).toBe(true);

    res.body.keys.forEach((k) => {
      expect(k.kid).toBeDefined();
      expect(k.kty).toBe("RSA");
      expect(k.n).toBeDefined();
      expect(k.e).toBeDefined();
      expect(k.use).toBe("sig");
    });
  });

  test("GET /.well-known/jwks.json triggers 500 on keystore failure", async () => {
    // Mock keystore to throw an error
    const originalFn = keystore.getUnexpiredPublicKeys;
    keystore.getUnexpiredPublicKeys = jest.fn(() => {
      throw new Error("simulated keystore failure");
    });

    const res = await request(app).get("/.well-known/jwks.json");
    expect(res.status).toBe(500);
    expect(res.body.error).toBe("simulated keystore failure");

    // Restore original function
    keystore.getUnexpiredPublicKeys = originalFn;
  });
});
