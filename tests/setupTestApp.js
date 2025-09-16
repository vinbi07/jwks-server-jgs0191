// tests/setupTestApp.js
import express from "express";
import authRouter from "../src/routes/auth.js";
import jwksRouter from "../src/routes/jwks.js";
import keystore from "../src/keys/keystore.js";

export async function createTestApp() {
  await keystore.initialize({
    initialCount: 2,
    defaultTtl: 2,
    ensureExpired: true,
  });

  const app = express();
  app.use(express.json());
  app.use("/auth", authRouter);

  // Mount the JWKS router exactly at /.well-known/jwks.json
  app.use("/.well-known/jwks.json", jwksRouter);

  return app;
}
