import express from "express";
import keystore from "../keys/keystore.js";
import { signJwt } from "../services/jwtService.js";

const router = express.Router();

/**
 * Selects a signing key based on whether an expired token is requested.
 */
function selectSigningKey(wantExpired) {
  if (wantExpired) {
    const expiredKeys = keystore.getExpiredKeys();
    return expiredKeys.length
      ? expiredKeys[0]
      : keystore.pickSigningKey({ allowExpired: true });
  }
  return keystore.pickSigningKey({ allowExpired: false });
}

/**
 * POST /auth
 * Issues a JWT. Optional query param 'expired' will use an expired key
 * or force token expiration in the past.
 */
router.post("/", async (req, res) => {
  try {
    const wantExpired = "expired" in req.query;
    const signingKey = selectSigningKey(wantExpired);

    const now = Math.floor(Date.now() / 1000);
    const tokenExp = wantExpired
      ? Math.floor(signingKey.expiresAt / 1000) // expired token
      : now + 300; // 5 min default

    const payload = {
      sub: req.body?.sub || "test-user",
      role: "student",
      iss: "http://localhost:8080",
    };

    const { jwt, exp } = await signJwt({
      payload,
      privateKey: signingKey.privateKey,
      kid: signingKey.kid,
      exp: tokenExp, // manual expiry ensures truly expired JWT
    });

    res.status(200).json({ token: jwt, exp });
  } catch (err) {
    console.error("[AUTH] Error issuing JWT:", err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * Ensure unsupported methods are blocked for RESTful compliance
 */
router.all("/", (req, res) => {
  res.set("Allow", "POST");
  res.status(405).json({ error: "Method Not Allowed" });
});

export default router;
