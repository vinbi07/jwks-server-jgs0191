import request from "supertest";
import keystore from "../src/keys/keystore.js";
import { jwtVerify, importJWK } from "jose";
import { createTestApp } from "./setupTestApp.js";

let app;

beforeAll(async () => {
  app = await createTestApp();
});

describe("Auth endpoint", () => {
  test("POST /auth returns a JWT signed with a valid key", async () => {
    const res = await request(app).post("/auth").expect(200);
    expect(res.body).toHaveProperty("token");
    const token = res.body.token;

    const header = JSON.parse(
      Buffer.from(token.split(".")[0], "base64").toString("utf8")
    );
    expect(header.kid).toBeDefined();

    const key = keystore.getKeyByKid(header.kid);
    expect(key).toBeDefined();
    expect(key.expiresAt > Date.now()).toBe(true);

    const keyLike = await importJWK(key.publicJwk, "RS256");
    const verified = await jwtVerify(token, keyLike);
    expect(verified.payload.sub).toBe("test-user");
  });

  test("POST /auth?expired returns JWT signed with expired key", async () => {
    const res = await request(app).post("/auth?expired=true").expect(200);
    const token = res.body.token;

    const header = JSON.parse(
      Buffer.from(token.split(".")[0], "base64").toString("utf8")
    );
    expect(header.kid).toBeDefined();

    const key = keystore.getKeyByKid(header.kid);
    expect(key).toBeDefined();
    expect(key.expiresAt <= Date.now()).toBe(true);

    const keyLike = await importJWK(key.publicJwk, "RS256");

    await expect(jwtVerify(token, keyLike)).rejects.toThrow(/exp.*failed/i);
  });

  // ===== Edge-case tests for branch coverage =====
  test("POST /auth returns 500 if keystore fails to pick a key", async () => {
    const originalPick = keystore.pickSigningKey;
    keystore.pickSigningKey = () => {
      throw new Error("forced keystore error");
    };

    const res = await request(app).post("/auth").expect(500);
    expect(res.body.error).toBe("forced keystore error");

    keystore.pickSigningKey = originalPick;
  });

  test("POST /auth with unknown query param still returns valid token", async () => {
    const res = await request(app).post("/auth?unknown=true").expect(200);
    expect(res.body).toHaveProperty("token");
  });
});
