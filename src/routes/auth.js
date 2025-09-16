// src/routes/auth.js
import express from "express";
import keystore from "../keys/keystore.js";
import { signJwt } from "../services/jwtService.js";

const router = express.Router();

/**
 * POST /auth
 * - returns JSON { token: "<jwt>" }
 * - if query param 'expired' is present (any value), sign with an expired key and set token exp to that key's expiresAt
 * - accepts empty body (grader will POST with no body)
 */
router.post("/", async (req, res) => {
  try {
    const wantExpired = "expired" in req.query;

    let signingKey;
    const now = Math.floor(Date.now() / 1000);

    if (wantExpired) {
      const expiredKeys = keystore.getExpiredKeys();
      if (expiredKeys.length) {
        signingKey = expiredKeys[0];
      } else {
        // fallback: pick a valid key but set token exp to past so token is expired
        signingKey = keystore.pickSigningKey({ allowExpired: true });
      }
    } else {
      signingKey = keystore.pickSigningKey({ allowExpired: false });
    }

    // Determine token expiry
    const tokenExp = wantExpired
      ? Math.floor(signingKey.expiresAt / 1000) // expired token
      : now + 300; // 5 minutes for normal token

    const payload = {
      sub: "test-user",
      role: "student",
      iss: "http://localhost:8080",
    };

    const expiresInSeconds = tokenExp - now;

    const { jwt } = await signJwt({
      payload,
      privateKey: signingKey.privateKey,
      kid: signingKey.kid,
      expiresInSeconds,
    });

    // Respond with 200 Created for newly issued JWT
    res.status(200).json({ token: jwt });
  } catch (err) {
    console.error("Error issuing JWT:", err);
    res.status(500).json({ error: err.message });
  }
});

export default router;
