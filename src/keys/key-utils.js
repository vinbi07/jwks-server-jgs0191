// src/keys/key-utils.js
import crypto from "crypto";

let keys = [];

/**
 * Generate a new RSA key pair with a given expiry time.
 * @param {number} ttlSeconds - Time to live for the key in seconds.
 * @returns {object} - The generated key object (public/private/kid/expiry).
 */
export function generateKeyPair(ttlSeconds = 300) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });

  const kid = crypto.randomBytes(8).toString("hex");
  const expiry = Date.now() + ttlSeconds * 1000;

  const keyObj = {
    kid,
    expiry,
    publicKey,
    privateKey,
  };

  keys.push(keyObj);
  return keyObj;
}

/**
 * Get all unexpired keys (for JWKS endpoint).
 */
export function getValidKeys() {
  const now = Date.now();
  return keys.filter((k) => k.expiry > now);
}

/**
 * Get all keys, including expired (used for signing expired JWTs).
 */
export function getAllKeys() {
  return keys;
}

/**
 * Convert Node.js public key object to JWK format.
 * @param {object} keyObj - Key object containing publicKey, kid, expiry.
 * @returns {object} - JWK representation.
 */
export function publicKeyToJWK(keyObj) {
  const pub = crypto
    .createPublicKey(keyObj.publicKey)
    .export({ format: "jwk" });

  return {
    kty: pub.kty,
    n: pub.n,
    e: pub.e,
    alg: "RS256",
    use: "sig",
    kid: keyObj.kid,
  };
}
