const express = require('express');
const router = express.Router();
const supabase = require('../db/supabase');
const { authenticateToken, requireRole } = require('../middleware/auth');

// ── Rate limiter for flag submissions ─────────────────
// 10 attempts per 15 minutes per user per lab
const attemptCounts = new Map();
function flagRateLimit(req, res, next) {
  const key = `${req.user.id}:${req.params.slug}`;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxAttempts = 10;

  if (!attemptCounts.has(key)) {
    attemptCounts.set(key, { count: 1, start: now });
    return next();
  }

  const entry = attemptCounts.get(key);

  if (now - entry.start > windowMs) {
    attemptCounts.set(key, { count: 1, start: now });
    return next();
  }

  if (entry.count >= maxAttempts) {
    const retryAfter = Math.ceil((windowMs - (now - entry.start)) / 1000 / 60);
    return res.status(429).json({
      error: `Too many attempts. Try again in ${retryAfter} minute(s).`
    });
  }

  entry.count++;
  next();
}

// GET /api/labs
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { data: labs, error } = await supabase
      .from('labs')
      .select('id, slug, title, description, category, difficulty, points, enabled')
      .order('id');

    if (error) throw error;

    const { data: completions } = await supabase
      .from('lab_completions')
      .select('lab_id')
      .eq('user_id', req.user.id);

    const completedIds = new Set((completions || []).map(c => c.lab_id));
    const result = labs.map(lab => ({ ...lab, completed: completedIds.has(lab.id) }));

    res.json(result);
  } catch (err) {
    console.error('Labs fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch labs' });
  }
});

// GET /api/labs/:slug
router.get('/:slug', authenticateToken, async (req, res) => {
  try {
    const { data: lab, error } = await supabase
      .from('labs')
      .select('id, slug, title, description, category, difficulty, points, enabled, content')
      .eq('slug', req.params.slug)
      .single();

    if (error || !lab) return res.status(404).json({ error: 'Lab not found' });

    // Block disabled labs for everyone
    if (!lab.enabled) {
      return res.status(403).json({ error: 'This lab is currently disabled.' });
    }

    const { data: completion } = await supabase
      .from('lab_completions')
      .select('completed_at')
      .eq('user_id', req.user.id)
      .eq('lab_id', lab.id)
      .single();

    res.json({ ...lab, completed: !!completion, completedAt: completion?.completed_at });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch lab' });
  }
});

// POST /api/labs/:slug/attempt
router.post('/:slug/attempt', authenticateToken, flagRateLimit, async (req, res) => {
  const { flag } = req.body;
  if (!flag) return res.status(400).json({ error: 'Flag is required' });

  try {
    // flag selected here for comparison only — never sent back in response
    const { data: lab, error } = await supabase
      .from('labs')
      .select('id, flag, enabled')
      .eq('slug', req.params.slug)
      .single();

    if (error || !lab) return res.status(404).json({ error: 'Lab not found' });

    // Block flag submission for disabled labs for everyone
    if (!lab.enabled) {
      return res.status(403).json({ error: 'This lab is currently disabled.' });
    }

    const correct = flag.trim() === lab.flag.trim();

    await supabase.from('lab_attempts').insert([{
      user_id: req.user.id,
      lab_id: lab.id,
      flag_submitted: flag.trim(),
      correct
    }]);

    if (correct) {
      await supabase.from('lab_completions')
        .upsert([{ user_id: req.user.id, lab_id: lab.id }], { onConflict: 'user_id,lab_id' });
    }

    // Flag value never included in response
    res.json({
      correct,
      message: correct ? '🎉 Correct! Flag accepted.' : '❌ Wrong flag. Keep trying!'
    });
  } catch (err) {
    console.error('Attempt error:', err);
    res.status(500).json({ error: 'Failed to submit flag' });
  }
});

// GET /api/labs/:slug/progress
router.get('/:slug/progress', authenticateToken, async (req, res) => {
  try {
    const { data: lab } = await supabase
      .from('labs')
      .select('id')
      .eq('slug', req.params.slug)
      .single();

    if (!lab) return res.status(404).json({ error: 'Lab not found' });

    const { data: attempts } = await supabase
      .from('lab_attempts')
      .select('correct, flag_submitted, attempted_at')
      .eq('user_id', req.user.id)
      .eq('lab_id', lab.id)
      .order('attempted_at', { ascending: false });

    const { data: completion } = await supabase
      .from('lab_completions')
      .select('completed_at')
      .eq('user_id', req.user.id)
      .eq('lab_id', lab.id)
      .single();

    res.json({
      attempts: attempts || [],
      completed: !!completion,
      completedAt: completion?.completed_at
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});

// PATCH /api/labs/:id/toggle — instructor/admin only
router.patch('/:id/toggle', authenticateToken, requireRole('instructor', 'admin'), async (req, res) => {
  try {
    const { data: lab } = await supabase
      .from('labs')
      .select('enabled')
      .eq('id', req.params.id)
      .single();

    if (!lab) return res.status(404).json({ error: 'Lab not found' });

    const { data: updated, error } = await supabase
      .from('labs')
      .update({ enabled: !lab.enabled })
      .eq('id', req.params.id)
      .select('id, slug, title, description, category, difficulty, points, enabled')
      .single();

    if (error) throw error;

    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to toggle lab' });
  }
});

module.exports = router;