export default {
  PORT: 8080,
  KEY_ROTATION: {
    DEFAULT_TTL: 60 * 60 * 24, // 24 hours
    INITIAL_KEYS: 3,
  },
  JWT: {
    DEFAULT_EXP: 300, // 5 minutes
    ALGORITHM: "RS256",
  },
};
