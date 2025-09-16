export default function errorHandler(err, _req, res, _next) {
  // basic JSON error response
  console.error(err && err.stack ? err.stack : err);
  const status = err && err.status ? err.status : 500;
  res.status(status).json({ error: err.message || "Internal Server Error" });
}
