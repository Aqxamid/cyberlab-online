/* require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/labs', require('./routes/labs'));
app.use('/api/stats', require('./routes/stats'));
app.use('/api/users', require('./routes/users'));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), service: 'CyberLab API' });
});

// 404
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
  console.log(`🛡️  CyberLab API running on http://localhost:${PORT}`);
});
   uncomment if you want to run the backend server locally using docker */

require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');         // H2 FIX: security headers
const rateLimit = require('express-rate-limit'); // H1 FIX: rate limiting
const app       = express();
const PORT      = process.env.PORT || 4000;

// ── H2 FIX: Hide Express fingerprint ─────────────────────────────────────────
app.disable('x-powered-by');

// ── H2 FIX: Helmet sets 11 security headers in one call ──────────────────────
// Includes: X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
//           Strict-Transport-Security, X-DNS-Prefetch-Control, etc.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"], // Tailwind CDN uses inline styles
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc:    ["'self'"],
      objectSrc:  ["'none'"],
      frameSrc:   ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Allow lab iframes if you embed them
}));

// ── CORS Middleware ───────────────────────────────────────────────────────────
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

app.use(cors({
  origin: FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// ── M1 FIX: Restrict body size to prevent DoS via large payloads ─────────────
// Previously: express.json() with no limit (default 100KB, but not enforced)
// extended: false uses safer querystring parser instead of qs
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ── H1 FIX: Global rate limiter (broad protection for all API routes) ─────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,                  // 200 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' },
});
app.use('/api/', globalLimiter);

// ── H1 FIX: Strict limiter for login (brute-force protection) ─────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                   // Only 10 login attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  skipSuccessfulRequests: true, // Don't count successful logins against the limit
});
app.use('/api/auth/login', loginLimiter);

// ── H1 FIX: Flag submission rate limiter ────────────────────────────────────
const flagLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,             // 20 flag attempts per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many flag submissions. Please slow down.' },
});
app.use('/api/labs/:slug/attempt', flagLimiter);

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/auth',  require('./routes/auth'));
app.use('/api/labs',  require('./routes/labs'));
app.use('/api/stats', require('./routes/stats'));
app.use('/api/users', require('./routes/users'));

// ── Health Check ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), service: 'CyberLab API' });
});

// ── 404 Handler ──────────────────────────────────────────────────────────────
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ── Global Error Handler (never leak stack traces to client) ─────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🛡️  CyberLab API running on port ${PORT}`);
});