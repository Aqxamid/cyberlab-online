require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const app       = express();

const PORT = process.env.PORT || 4000;

// ── 1. Security Headers ───────────────────────────────────────
// Sets X-Content-Type-Options, X-Frame-Options, HSTS,
// X-XSS-Protection, removes X-Powered-By header, and more.
app.use(helmet());

// ── 2. CORS (your original — completely unchanged) ────────────
app.use((req, res, next) => {
  const origin = process.env.FRONTEND_URL || 'https://cyberlab-frontend.onrender.com';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// ── 3. Body Parsing with size limits (prevents memory DoS) ───
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));

// ── 4. Global rate limit on all /api routes ───────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' },
});
app.use('/api', globalLimiter);

// ── 5. Strict auth rate limit: 5 attempts per 15 min ─────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait 15 minutes before trying again.' },
});
app.use('/api/auth/login',    authLimiter);
app.use('/api/auth/register', authLimiter);

// ── 6. Routes ─────────────────────────────────────────────────
app.use('/api/auth',  require('./routes/auth'));
app.use('/api/labs',  require('./routes/labs'));
app.use('/api/stats', require('./routes/stats'));
app.use('/api/users', require('./routes/users'));

// ── 7. Health Check ───────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), service: 'CyberLab API' });
});

// ── 8. 404 Handler ────────────────────────────────────────────
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ── 9. Global Error Handler — never leaks stack traces ────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const status = err.status || err.statusCode || 500;
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);
  if (process.env.NODE_ENV === 'production') {
    return res.status(status).json({
      error: status < 500 ? err.message : 'Something went wrong. Please try again.',
    });
  }
  return res.status(status).json({ error: err.message, stack: err.stack });
});

app.listen(PORT, () => {
  console.log(`🛡️ CyberLab API running on port ${PORT}`);
});