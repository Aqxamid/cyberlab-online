const express  = require('express');
const router   = express.Router();
const crypto   = require('crypto');
const supabase = require('../db/supabase');
const { authenticateToken, requireRole } = require('../middleware/auth');

// ── C3 FIX: Hash flags before comparing ───────────────────────────────────────
// Flags are stored as SHA-256 hashes in the DB (flag_hash column).
// We never store or return raw flag strings — only compare hashes.
function hashFlag(rawFlag) {
  return crypto.createHash('sha256').update(rawFlag.trim().toLowerCase()).digest('hex');
}

// ── GET /api/labs ────────────────────────────────────────────────────────────
router.get('/', authenticateToken, async (req, res) => {
  try {
    // C3 FIX: Never select the flag or flag_hash column in list responses
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

// ── GET /api/labs/:slug ───────────────────────────────────────────────────────
router.get('/:slug', authenticateToken, async (req, res) => {
  try {
    // C3 FIX: Explicitly exclude flag_hash from the selected columns
    const { data: lab, error } = await supabase
      .from('labs')
      .select('id, slug, title, description, category, difficulty, points, enabled, content')
      .eq('slug', req.params.slug)
      .single();

    if (error || !lab) return res.status(404).json({ error: 'Lab not found' });

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

// ── POST /api/labs/:slug/attempt ─────────────────────────────────────────────
router.post('/:slug/attempt', authenticateToken, async (req, res) => {
  const { flag } = req.body;

  // M3 FIX: Validate flag input — must be a non-empty string under 200 chars
  if (!flag || typeof flag !== 'string') {
    return res.status(400).json({ error: 'Flag is required' });
  }
  if (flag.length > 200) {
    return res.status(400).json({ error: 'Flag is too long' });
  }

  try {
    // C3 FIX: Retrieve flag_hash (not raw flag) from DB
    const { data: lab, error } = await supabase
      .from('labs')
      .select('id, flag_hash')
      .eq('slug', req.params.slug)
      .single();

    if (error || !lab) return res.status(404).json({ error: 'Lab not found' });

    // C3 FIX: Compare hashes — never compare or expose raw flag strings
    const submittedHash = hashFlag(flag);
    const correct       = submittedHash === lab.flag_hash;

    // Log the attempt — store submitted hash, not raw flag, to avoid leaking it
    await supabase.from('lab_attempts').insert([{
      user_id:        req.user.id,
      lab_id:         lab.id,
      flag_submitted: submittedHash, // store hash only
      correct,
    }]);

    if (correct) {
      await supabase.from('lab_completions')
        .upsert([{ user_id: req.user.id, lab_id: lab.id }], { onConflict: 'user_id,lab_id' });
    }

    res.json({
      correct,
      message: correct ? '🎉 Correct! Flag accepted.' : '❌ Wrong flag. Keep trying!',
    });
  } catch (err) {
    console.error('Attempt error:', err);
    res.status(500).json({ error: 'Failed to submit flag' });
  }
});

// ── GET /api/labs/:slug/progress ─────────────────────────────────────────────
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
      .select('id, correct, attempted_at') // M3 FIX: never return flag_submitted
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
      attempts:    attempts || [],
      completed:   !!completion,
      completedAt: completion?.completed_at,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});

// ── PATCH /api/labs/:id/toggle — instructor/admin ────────────────────────────
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
      .select('id, slug, title, enabled')
      .single();

    if (error) throw error;
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to toggle lab' });
  }
});

module.exports = router;