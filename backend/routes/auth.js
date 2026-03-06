const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');
const { body, validationResult } = require('express-validator');
const supabase = require('../db/supabase');
const { authenticateToken, JWT_SECRET, REFRESH_SECRET } = require('../middleware/auth');

// ── Token helpers ─────────────────────────────────────────────────────────────
// H3 FIX: Short-lived access token (15 minutes instead of 24 hours).
// A stolen token is only valid for a short window.
function issueAccessToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
}

// H3 FIX: Long-lived refresh token stored in DB for revocation support.
async function issueRefreshToken(userId) {
  const token  = crypto.randomBytes(64).toString('hex');
  const expiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  await supabase
    .from('refresh_tokens')
    .insert([{ user_id: userId, token, expires_at: expiry.toISOString() }]);

  return token;
}

// ── POST /api/auth/register ───────────────────────────────────────────────────
router.post('/register', [
  body('username').trim().isLength({ min: 3, max: 50 }).isAlphanumeric(),
  body('email').isEmail().normalizeEmail(),
  // L3 FIX: Raise minimum password length from 6 to 8 characters
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, email, password } = req.body;

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert([{ username, email, password_hash: passwordHash }])
      .select('id, username, email, role')
      .single();

    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Username or email already exists' });
      throw error;
    }

    const accessToken  = issueAccessToken(data);
    const refreshToken = await issueRefreshToken(data.id);

    res.status(201).json({ accessToken, refreshToken, user: data });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ── POST /api/auth/login ───────────────────────────────────────────────────────
router.post('/login', [
  body('username').trim().notEmpty(),
  body('password').notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password } = req.body;

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    // Always run bcrypt.compare even on miss — prevents user enumeration via timing
    const dummyHash = '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012';
    const hashToCompare = user ? user.password_hash : dummyHash;
    const valid = await bcrypt.compare(password, hashToCompare);

    if (error || !user || !valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken  = issueAccessToken(user);
    const refreshToken = await issueRefreshToken(user.id);

    res.json({
      accessToken,
      refreshToken,
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ── POST /api/auth/refresh ─────────────────────────────────────────────────────
// H3 FIX: Exchange a refresh token for a new short-lived access token.
// Refresh tokens can be revoked in the DB (e.g., on logout or compromise).
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

  try {
    const { data: record, error } = await supabase
      .from('refresh_tokens')
      .select('user_id, expires_at, revoked')
      .eq('token', refreshToken)
      .single();

    if (error || !record) return res.status(401).json({ error: 'Invalid refresh token' });
    if (record.revoked)   return res.status(401).json({ error: 'Refresh token has been revoked' });
    if (new Date(record.expires_at) < new Date()) {
      return res.status(401).json({ error: 'Refresh token expired' });
    }

    const { data: user } = await supabase
      .from('users')
      .select('id, username, role')
      .eq('id', record.user_id)
      .single();

    if (!user) return res.status(401).json({ error: 'User not found' });

    const accessToken = issueAccessToken(user);
    res.json({ accessToken });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
// H3 FIX: Revoke the refresh token in the DB so it can't be used again.
router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    await supabase
      .from('refresh_tokens')
      .update({ revoked: true })
      .eq('token', refreshToken);
  }
  res.json({ message: 'Logged out' });
});

// ── GET /api/auth/me ──────────────────────────────────────────────────────────
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, email, role, created_at')
      .eq('id', req.user.id)
      .single();

    if (error || !user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

module.exports = router;