const express = require('express');
const router  = express.Router();
const { param, body, validationResult } = require('express-validator');
const supabase = require('../db/supabase');
const { authenticateToken, requireRole } = require('../middleware/auth');

function handleValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
  return null;
}

// ── GET /api/users — admin only ───────────────────────────────
router.get('/', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('uuid, username, email, role, created_at') // integer id never exposed
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ── PATCH /api/users/:uuid/role — admin only ──────────────────
// UUID in URL — sequential integer id never exposed
router.patch('/:uuid/role',
  authenticateToken,
  requireRole('admin'),
  param('uuid').isUUID().withMessage('Invalid user identifier'),
  body('role')
    .isIn(['student', 'instructor', 'admin'])
    .withMessage('Invalid role. Must be student, instructor, or admin'),
  async (req, res) => {
    if (handleValidation(req, res)) return;

    const targetUuid = req.params.uuid;

    // Prevent admin from accidentally demoting their own account
    if (req.user.uuid === targetUuid) {
      return res.status(400).json({ error: 'You cannot change your own role.' });
    }

    try {
      const { data, error } = await supabase
        .from('users')
        .update({ role: req.body.role })
        .eq('uuid', targetUuid)
        .select('uuid, username, email, role')
        .single();

      if (error) throw error;
      if (!data) return res.status(404).json({ error: 'User not found' });

      res.json(data);
    } catch (err) {
      res.status(500).json({ error: 'Failed to update role' });
    }
  }
);

module.exports = router;