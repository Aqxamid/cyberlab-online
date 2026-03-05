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
const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;

// ── CORS Middleware ──────────────────────────────
// Allow requests from your deployed frontend or localhost for local dev
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
// CORS
app.use((req, res, next) => {
  // set to the actual frontend URL
  const origin = process.env.FRONTEND_URL || 'https://cyberlab-frontend.onrender.com';

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // preflight
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

// ── Body Parsing Middleware ──────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Routes ──────────────────────────────────────
app.use('/api/auth', require('./routes/auth'));
app.use('/api/labs', require('./routes/labs'));
app.use('/api/stats', require('./routes/stats'));
app.use('/api/users', require('./routes/users'));

// ── Health Check ────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'CyberLab API'
  });
});

// ── 404 Handler ─────────────────────────────────
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ── Start Server ───────────────────────────────
app.listen(PORT, () => {
  console.log(`🛡️  CyberLab API running on port ${PORT}`);
});