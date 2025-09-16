import express from "express";
import jwksRouter from "./routes/jwks.js";
import authRouter from "./routes/auth.js";
import errorHandler from "./middleware/errorhandler.js";
import logger from "./logger.js";
import keystore from "./keys/keystore.js";
import config from "./config/default.js";

// wrap app creation in async function
export async function initializeApp() {
  const app = express();

  app.use(express.json());
  app.use(logger);

  // initialize keystore with some keys (2 valid + 1 expired)
  await keystore.initialize({
    initialCount: config.KEY_ROTATION.INITIAL_KEYS,
    defaultTtl: config.KEY_ROTATION.DEFAULT_TTL,
    ensureExpired: true,
  });

  // Routes
  app.use("/.well-known", jwksRouter);
  app.use("/", authRouter);

  // health endpoint for convenience
  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  // error handler (must be last)
  app.use(errorHandler);

  return app;
}
