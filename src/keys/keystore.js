/**
 * Keystore - in-memory RSA key pair store with expiry and kid support.
 *
 * Each key record:
 * {
 *   kid: string,
 *   privateKey: KeyLike (NodePrivateKey),
 *   publicJwk: object, // exported JWK with kid and use:'sig'
 *   expiresAt: number (ms timestamp)
 * }
 *
 * Exposes functions to get unexpired public keys (for JWKS),
 * pick signing key (optionally allowing expired), and initialize at startup.
 */

import crypto from "crypto";
import { exportJWK } from "jose";

const keystore = {
  keys: [],
};

function randomKid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return crypto.randomBytes(16).toString("hex");
}

async function generateKey(ttlSeconds = 3600) {
  // generate RSA 2048 key pair sync
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });

  const publicJwk = await exportJWK(publicKey);
  const kid = randomKid();
  // add mandatory fields used in JWKS
  publicJwk.kid = kid;
  publicJwk.use = "sig";
  // prefer RSA alg RS256
  publicJwk.alg = "RS256";

  const expiresAt = Date.now() + ttlSeconds * 1000;

  const rec = { kid, privateKey, publicJwk, expiresAt };
  keystore.keys.push(rec);
  return rec;
}

async function initialize({
  initialCount = 3,
  defaultTtl = 3600,
  ensureExpired = true,
} = {}) {
  keystore.keys = [];
  // Create initialCount keys with default TTL
  for (let i = 0; i < initialCount; i += 1) {
    // Make last one short lived so tests can treat it as expired if desired
    const ttl =
      i === initialCount - 1 ? Math.floor(defaultTtl / 2) : defaultTtl;
    // But still positive
    // await generateKey...
    // Use generateKey so the exported jwk is available
    // eslint-disable-next-line no-await-in-loop
    await generateKey(ttl);
  }

  if (ensureExpired) {
    // Create one explicitly expired key (expires 2 hours ago)
    const expiredTtl = -60 * 60 * 2; // negative TTL => expired
    // eslint-disable-next-line no-await-in-loop
    await generateKey(expiredTtl);
  }

  return keystore.keys;
}

function getUnexpiredPublicKeys() {
  const now = Date.now();
  return keystore.keys
    .filter((k) => k.expiresAt > now)
    .map((k) => {
      // Do not return private key
      return k.publicJwk;
    });
}

function getExpiredKeys() {
  const now = Date.now();
  return keystore.keys.filter((k) => k.expiresAt <= now);
}

function getKeyByKid(kid) {
  return keystore.keys.find((k) => k.kid === kid);
}

function pickSigningKey({ allowExpired = false } = {}) {
  const now = Date.now();
  const candidates = keystore.keys.filter((k) =>
    allowExpired ? true : k.expiresAt > now
  );
  if (!candidates.length) throw new Error("No signing keys available");
  // simple selection: pick most-recent non-expired by expiresAt
  candidates.sort((a, b) => b.expiresAt - a.expiresAt);
  return candidates[0];
}

export default {
  get keys() {
    return keystore.keys;
  },
  generateKey,
  initialize,
  getUnexpiredPublicKeys,
  getExpiredKeys,
  getKeyByKid,
  pickSigningKey,
};
