const express = require('express');
const router  = express.Router();
const { body, param, validationResult } = require('express-validator');
const supabase = require('../db/supabase');
const { authenticateToken, requireRole } = require('../middleware/auth');

const SCORE_FLOOR   = 20;
const ATTEMPT_COST  = 1;
const HINT_COSTS    = [0, 5, 20, 25]; // matches lab frontend HINT_DEDUCTIONS

function handleValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
  return null;
}

// ── GET /api/labs ─────────────────────────────────────────────
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { data: labs, error } = await supabase
      .from('labs')
      .select('uuid, slug, title, description, category, difficulty, points, enabled')
      .order('id');

    if (error) throw error;

    const { data: completions } = await supabase
      .from('lab_completions')
      .select('lab_uuid, points_earned')
      .eq('user_uuid', req.user.uuid);

    const completedMap = Object.fromEntries((completions || []).map(c => [c.lab_uuid, c.points_earned]));
    const result = labs.map(lab => ({
      ...lab,
      completed:    lab.uuid in completedMap,
      pointsEarned: completedMap[lab.uuid] ?? null,
    }));
    res.json(result);
  } catch (err) {
    console.error('Labs fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch labs' });
  }
});

// ── GET /api/labs/:slug ───────────────────────────────────────
router.get('/:slug',
  authenticateToken,
  param('slug').matches(/^[a-z0-9-]{1,80}$/).withMessage('Invalid lab slug'),
  async (req, res) => {
    if (handleValidation(req, res)) return;
    try {
      const { data: lab, error } = await supabase
        .from('labs')
        .select('uuid, slug, title, description, category, difficulty, points, enabled, content')
        .eq('slug', req.params.slug)
        .single();

      if (error || !lab) return res.status(404).json({ error: 'Lab not found' });

      const { data: completion } = await supabase
        .from('lab_completions')
        .select('completed_at, points_earned, hints_used')
        .eq('user_uuid', req.user.uuid)
        .eq('lab_uuid', lab.uuid)
        .single();

      res.json({
        ...lab,
        completed:    !!completion,
        completedAt:  completion?.completed_at  ?? null,
        pointsEarned: completion?.points_earned ?? null,
        hintsUsed:    completion?.hints_used    ?? null,
      });
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch lab' });
    }
  }
);

// ── POST /api/labs/:slug/attempt ──────────────────────────────
// Single entry point for flag submission + score calculation.
// Labs send: flag, hints_used (total pts deducted by hints), attempts_count.
// Backend verifies flag, calculates final score, saves to lab_completions.
router.post('/:slug/attempt',
  authenticateToken,
  param('slug').matches(/^[a-z0-9-]{1,80}$/).withMessage('Invalid lab slug'),
  body('flag')
    .notEmpty().withMessage('Flag is required')
    .isLength({ max: 200 }).withMessage('Flag is too long')
    .trim(),
  body('hints_used')
    .optional()
    .isInt({ min: 0, max: 10000 }).withMessage('Invalid hints_used value'),
  body('attempts_count')
    .optional()
    .isInt({ min: 0, max: 10000 }).withMessage('Invalid attempts_count value'),
  async (req, res) => {
    if (handleValidation(req, res)) return;

    const { flag } = req.body;
    const hintsUsed     = parseInt(req.body.hints_used     ?? 0, 10);
    const attemptsCount = parseInt(req.body.attempts_count ?? 0, 10);

    try {
      const { data: lab, error } = await supabase
        .from('labs')
        .select('uuid, flag, points')
        .eq('slug', req.params.slug)
        .single();

      if (error || !lab) return res.status(404).json({ error: 'Lab not found' });

      const correct = flag.trim() === lab.flag.trim();

      // Always log the attempt
      await supabase.from('lab_attempts').insert([{
        user_uuid:      req.user.uuid,
        lab_uuid:       lab.uuid,
        flag_submitted: flag.trim(),
        correct,
      }]);

      if (!correct) {
        return res.status(400).json({ correct: false, message: 'Wrong flag. Keep trying!' });
      }

      // Calculate score server-side
      // hints_used is the total pts already deducted by hints (trusted but clamped)
      // attempts_count is how many URL submissions were made (1pt each, winning attempt is free)
      const maxHintDeduction = HINT_COSTS.reduce((a, b) => a + b, 0); // 50 max
      const clampedHints     = Math.min(hintsUsed, maxHintDeduction);
      const clampedAttempts  = Math.min(attemptsCount, lab.points - SCORE_FLOOR); // can't cost more than possible
      const totalDeduction   = clampedHints + (clampedAttempts * ATTEMPT_COST);
      const pointsEarned     = Math.max(SCORE_FLOOR, Math.min(lab.points, lab.points - totalDeduction));

      // Check existing completion — only update if new score is higher
      const { data: existing } = await supabase
        .from('lab_completions')
        .select('points_earned')
        .eq('user_uuid', req.user.uuid)
        .eq('lab_uuid', lab.uuid)
        .single();

      if (!existing || existing.points_earned == null || pointsEarned > existing.points_earned) {
        await supabase
          .from('lab_completions')
          .upsert(
            [{ user_uuid: req.user.uuid, lab_uuid: lab.uuid, points_earned: pointsEarned, hints_used: clampedHints }],
            { onConflict: 'user_uuid,lab_uuid' }
          );
      }

      res.json({
        correct:       true,
        points_earned: pointsEarned,
        lab_max:       lab.points,
        message:       pointsEarned === lab.points
          ? 'Full marks! No deductions.'
          : `Completed with ${pointsEarned} / ${lab.points} points.`,
      });
    } catch (err) {
      console.error('Attempt error:', err);
      res.status(500).json({ error: 'Failed to submit flag' });
    }
  }
);

// ── GET /api/labs/:slug/progress ──────────────────────────────
router.get('/:slug/progress',
  authenticateToken,
  param('slug').matches(/^[a-z0-9-]{1,80}$/).withMessage('Invalid lab slug'),
  async (req, res) => {
    if (handleValidation(req, res)) return;
    try {
      const { data: lab } = await supabase
        .from('labs').select('uuid').eq('slug', req.params.slug).single();
      if (!lab) return res.status(404).json({ error: 'Lab not found' });

      const { data: attempts } = await supabase
        .from('lab_attempts')
        .select('flag_submitted, correct, attempted_at')
        .eq('user_uuid', req.user.uuid)
        .eq('lab_uuid', lab.uuid)
        .order('attempted_at', { ascending: false });

      const { data: completion } = await supabase
        .from('lab_completions')
        .select('completed_at, points_earned, hints_used')
        .eq('user_uuid', req.user.uuid)
        .eq('lab_uuid', lab.uuid)
        .single();

      res.json({
        attempts:     attempts || [],
        completed:    !!completion,
        completedAt:  completion?.completed_at  ?? null,
        pointsEarned: completion?.points_earned ?? null,
        hintsUsed:    completion?.hints_used    ?? null,
      });
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch progress' });
    }
  }
);

// ── PATCH /api/labs/:uuid/toggle ──────────────────────────────
router.patch('/:uuid/toggle',
  authenticateToken,
  requireRole('instructor', 'admin'),
  param('uuid').isUUID().withMessage('Invalid lab identifier'),
  async (req, res) => {
    if (handleValidation(req, res)) return;
    try {
      const { data: lab } = await supabase
        .from('labs').select('enabled').eq('uuid', req.params.uuid).single();
      if (!lab) return res.status(404).json({ error: 'Lab not found' });

      const { data: updated, error } = await supabase
        .from('labs')
        .update({ enabled: !lab.enabled })
        .eq('uuid', req.params.uuid)
        .select('uuid, slug, title, enabled')
        .single();

      if (error) throw error;
      res.json(updated);
    } catch (err) {
      res.status(500).json({ error: 'Failed to toggle lab' });
    }
  }
);

module.exports = router;