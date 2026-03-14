const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const supabase = require('../db/supabase');
const { authenticateToken, JWT_SECRET } = require('../middleware/auth');

const BCRYPT_ROUNDS = 12; // increased from 10 → harder to brute-force

function handleValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
  return null;
}

// ── POST /api/auth/register ───────────────────────────────────
router.post('/register', [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 }).withMessage('Username must be 3–50 characters')
    .isAlphanumeric().withMessage('Username can only contain letters and numbers'),
  body('email')
    .isEmail().withMessage('Please enter a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number'),
], async (req, res) => {
  if (handleValidation(req, res)) return;

  const { username, email, password } = req.body;

  try {
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const { data, error } = await supabase
      .from('users')
      .insert([{ username, email, password_hash: passwordHash }])
      .select('uuid, username, email, role') // uuid only — integer id never leaves server
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'An account with that username or email already exists.' });
      }
      throw error;
    }

    const token = jwt.sign(
      { uuid: data.uuid, username: data.username, role: data.role },
      JWT_SECRET,
      { expiresIn: '8h', algorithm: 'HS256' }
    );

    res.status(201).json({ token, user: data });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ── POST /api/auth/login ──────────────────────────────────────
router.post('/login', [
  body('username').trim().notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
  if (handleValidation(req, res)) return;

  const { username, password } = req.body;

  // Dummy hash: bcrypt always runs even when user doesn't exist.
  // Prevents username enumeration via timing differences.
  const DUMMY_HASH = '$2b$12$invalidhashpaddingtomakethisLooksLikeARealHashXXXXXXXXX';

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    const hashToCheck = (error || !user) ? DUMMY_HASH : user.password_hash;
    const valid = await bcrypt.compare(password, hashToCheck);

    // Generic message — never reveal whether username or password was wrong
    if (error || !user || !valid) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const token = jwt.sign(
      { uuid: user.uuid, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '8h', algorithm: 'HS256' }
    );

    res.json({
      token,
      user: { uuid: user.uuid, username: user.username, email: user.email, role: user.role },
      // integer id intentionally omitted from response
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ── GET /api/auth/me ──────────────────────────────────────────
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('uuid, username, email, role, created_at')
      .eq('uuid', req.user.uuid) // look up by uuid — never by integer id
      .single();

    if (error || !user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ── POST /api/auth/logout ─────────────────────────────────────
// Blacklists the token so lab re-checks and all other requests immediately fail.
// Client should also clear its own session (handled in app.js logout()).
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const token     = req.headers['authorization'].split(' ')[1];
    const expiresAt = new Date(req.user.exp * 1000); // JWT exp claim → Date

    await supabase
      .from('invalidated_tokens')
      .insert([{ token, expires_at: expiresAt }]);

    res.json({ ok: true });
  } catch (err) {
    // Even if the DB insert fails, still respond OK — client will clear session anyway
    console.error('Logout blacklist error:', err);
    res.json({ ok: true });
  }
});

module.exports = router;