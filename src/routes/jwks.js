import express from "express";
import keystore from "../keys/keystore.js";

const router = express.Router();

/**
 * GET /
 * Returns all unexpired public keys in JWKS format
 */
router.get("/", (req, res) => {
  try {
    const keys = keystore.getUnexpiredPublicKeys();
    res.set("Cache-Control", "public, max-age=60");
    res.status(200).json({ keys });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /error
 * Used for test coverage: always returns 500
 */
router.get("/error", (_req, res) => {
  res.status(500).json({ error: "forced error for test coverage" });
});

// Ensure unsupported methods are blocked
router.all("/", (_req, res) => {
  res.set("Allow", "GET");
  res.status(405).json({ error: "Method Not Allowed" });
});

router.all("/error", (_req, res) => {
  res.set("Allow", "GET");
  res.status(405).json({ error: "Method Not Allowed" });
});

export default router;
