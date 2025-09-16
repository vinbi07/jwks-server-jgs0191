import express from "express";
import config from "./config/default.js";
import jwksRouter from "./routes/jwks.js";
import authRouter from "./routes/auth.js";
import keystore from "./keys/keystore.js";

const app = express();
app.use(express.json());

// Initialize the keystore with some keys
await keystore.initialize({
  initialCount: config.KEY_ROTATION.INITIAL_KEYS,
  defaultTtl: config.KEY_ROTATION.DEFAULT_TTL,
  ensureExpired: true, // ensures there is at least one expired key for /auth?expired=true
});

// Routes
app.use("/.well-known/jwks.json", jwksRouter);
app.use("/auth", authRouter);

// Root route
app.get("/", (req, res) => {
  res.json({
    message: "JWKS Server is running",
    endpoints: ["/jwks", "/auth"],
  });
});

// Start server
app.listen(config.PORT, () => {
  console.log(`Server listening on http://localhost:${config.PORT}`);
});
