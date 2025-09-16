import keystore from "../src/keys/keystore.js";
import crypto from "crypto";

describe("Keystore full branch coverage", () => {
  beforeEach(() => {
    // Reset keys before each test
    keystore.keys.length = 0;
  });

  test("generateKey returns key with correct structure", async () => {
    const key = await keystore.generateKey();
    expect(key).toHaveProperty("kid");
    expect(key).toHaveProperty("privateKey");
    expect(key).toHaveProperty("publicJwk");
    expect(key).toHaveProperty("expiresAt");
    expect(typeof key.kid).toBe("string");
    expect(key.publicJwk.kid).toBe(key.kid);
    expect(key.publicJwk.use).toBe("sig");
    expect(key.publicJwk.alg).toBe("RS256");
  });

  test("initialize creates initialCount keys and an expired key", async () => {
    const keys = await keystore.initialize({
      initialCount: 2,
      defaultTtl: 3600,
    });
    // 2 regular keys + 1 expired key
    expect(keys.length).toBe(3);
    const expiredKeys = keystore.getExpiredKeys();
    expect(expiredKeys.length).toBe(1);
    const unexpiredKeys = keystore.getUnexpiredPublicKeys();
    expect(unexpiredKeys.length).toBe(2);
  });

  test("getUnexpiredPublicKeys filters out expired keys", async () => {
    // expired keys
    await keystore.generateKey(-1);
    await keystore.generateKey(-2);
    const unexpired = keystore.getUnexpiredPublicKeys();
    expect(unexpired.length).toBe(0);

    // mix expired and unexpired
    await keystore.generateKey(1); // unexpired
    await keystore.generateKey(-1); // expired
    const mixed = keystore.getUnexpiredPublicKeys();
    expect(mixed.length).toBe(1);
  });

  test("getKeyByKid returns correct key or undefined", async () => {
    const key = await keystore.generateKey();
    const found = keystore.getKeyByKid(key.kid);
    expect(found).toBe(key);

    const missing = keystore.getKeyByKid("nonexistent");
    expect(missing).toBeUndefined();

    // test duplicate kid scenario (forcefully)
    const duplicateKey = { ...key, kid: key.kid };
    keystore.keys.push(duplicateKey);
    const result = keystore.getKeyByKid(key.kid);
    expect(result).toBe(key); // first occurrence
  });

  test("pickSigningKey returns most recent unexpired key by default", async () => {
    const oldKey = await keystore.generateKey(1); // expires soon
    const newKey = await keystore.generateKey(3600); // longer TTL
    const picked = keystore.pickSigningKey();
    expect(picked.kid).toBe(newKey.kid);

    // tie-breaker: identical expiresAt
    oldKey.expiresAt = newKey.expiresAt;
    const pickedTie = keystore.pickSigningKey();
    expect([oldKey.kid, newKey.kid]).toContain(pickedTie.kid);
  });

  test("pickSigningKey allows expired key if allowExpired=true", async () => {
    const expiredKey = await keystore.generateKey(-1); // expired immediately
    const picked = keystore.pickSigningKey({ allowExpired: true });
    expect(picked.kid).toBe(expiredKey.kid);
  });

  test("pickSigningKey throws if no keys available", () => {
    expect(() => keystore.pickSigningKey()).toThrow(
      /No signing keys available/i
    );
  });

  test("empty keystore returns empty arrays for getUnexpiredPublicKeys and getExpiredKeys", () => {
    expect(keystore.getUnexpiredPublicKeys()).toEqual([]);
    expect(keystore.getExpiredKeys()).toEqual([]);
  });

  test("randomKid fallback branch", async () => {
    // temporarily remove crypto.randomUUID
    const originalUUID = crypto.randomUUID;
    crypto.randomUUID = undefined;

    const key = await keystore.generateKey();
    expect(typeof key.kid).toBe("string");

    crypto.randomUUID = originalUUID; // restore
  });
});
