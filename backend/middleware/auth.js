const jwt = require('jsonwebtoken');

// ── C1 FIX: No fallback secret. Crash on startup if JWT_SECRET is not set. ──
// Previously: process.env.JWT_SECRET || 'cyberlab_secret_change_in_production'
// That hardcoded fallback is public on GitHub — anyone could forge admin tokens.
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}

// ── H3 FIX: Also export REFRESH_SECRET for refresh token support ─────────────
const REFRESH_SECRET = process.env.REFRESH_SECRET;
if (!REFRESH_SECRET) {
  console.error('FATAL: REFRESH_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      // Distinguish expired vs invalid for better client UX
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
      }
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

module.exports = { authenticateToken, requireRole, JWT_SECRET, REFRESH_SECRET };