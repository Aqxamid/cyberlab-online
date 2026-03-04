const express = require('express');
const router = express.Router();
const supabase = require('../db/supabase');
const { authenticateToken, requireRole } = require('../middleware/auth');

// GET /api/users — admin only
router.get('/', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id, username, email, role, created_at')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// PATCH /api/users/:id/role — admin only
router.patch('/:id/role', authenticateToken, requireRole('admin'), async (req, res) => {
  const { role } = req.body;
  const validRoles = ['student', 'instructor', 'admin'];
  if (!validRoles.includes(role)) return res.status(400).json({ error: 'Invalid role' });

  try {
    const { data, error } = await supabase
      .from('users')
      .update({ role })
      .eq('id', req.params.id)
      .select('id, username, email, role')
      .single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update role' });
  }
});

module.exports = router;
