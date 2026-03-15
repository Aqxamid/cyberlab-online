const express = require('express');
const router  = express.Router();
const { body, param, validationResult } = require('express-validator');
const supabase = require('../db/supabase');
const { authenticateToken, requireRole } = require('../middleware/auth');

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
      .select('lab_uuid')
      .eq('user_uuid', req.user.uuid);

    const completedUuids = new Set((completions || []).map(c => c.lab_uuid));
    const result = labs.map(lab => ({ ...lab, completed: completedUuids.has(lab.uuid) }));
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
        .select('completed_at, points_earned')
        .eq('user_uuid', req.user.uuid)
        .eq('lab_uuid', lab.uuid)
        .single();

      res.json({ ...lab, completed: !!completion, completedAt: completion?.completed_at, pointsEarned: completion?.points_earned ?? null });
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch lab' });
    }
  }
);

// ── POST /api/labs/:slug/attempt ──────────────────────────────
router.post('/:slug/attempt',
  authenticateToken,
  param('slug').matches(/^[a-z0-9-]{1,80}$/).withMessage('Invalid lab slug'),
  body('flag')
    .notEmpty().withMessage('Flag is required')
    .isLength({ max: 200 }).withMessage('Flag is too long')
    .trim(),
  async (req, res) => {
    if (handleValidation(req, res)) return;

    const { flag } = req.body;

    try {
      const { data: lab, error } = await supabase
        .from('labs')
        .select('uuid, flag')
        .eq('slug', req.params.slug)
        .single();

      if (error || !lab) return res.status(404).json({ error: 'Lab not found' });

      const correct = flag.trim() === lab.flag.trim();

      await supabase.from('lab_attempts').insert([{
        user_uuid:      req.user.uuid,
        lab_uuid:       lab.uuid,
        flag_submitted: flag.trim(),
        correct,
      }]);

      if (correct) {
        await supabase.from('lab_completions')
          .upsert(
            [{ user_uuid: req.user.uuid, lab_uuid: lab.uuid }],
            { onConflict: 'user_uuid,lab_uuid' }
          );
      }

      res.json({
        correct,
        message: correct ? '🎉 Correct! Flag accepted.' : '❌ Wrong flag. Keep trying!',
      });
    } catch (err) {
      console.error('Attempt error:', err);
      res.status(500).json({ error: 'Failed to submit flag' });
    }
  }
);

// ── POST /api/labs/:slug/complete ─────────────────────────────
// Called by lab frontends when a student captures the flag(s).
// Saves points_earned after applying hint deductions.
// points_earned is clamped to the lab's max points from the DB —
// the frontend value is never trusted blindly.
// If the student already has a completion, we only update if the
// new score is strictly higher (prevents re-submission from lowering score).
router.post('/:slug/complete',
  authenticateToken,
  param('slug').matches(/^[a-z0-9-]{1,80}$/).withMessage('Invalid lab slug'),
  body('points_earned')
    .isInt({ min: 0, max: 10000 }).withMessage('Invalid points value'),
  body('hints_used')
    .optional()
    .isInt({ min: 0, max: 10000 }).withMessage('Invalid hints_used value'),
  async (req, res) => {
    if (handleValidation(req, res)) return;

    try {
      // Fetch lab to get the authoritative max points from DB
      const { data: lab, error: labErr } = await supabase
        .from('labs')
        .select('uuid, points')
        .eq('slug', req.params.slug)
        .single();

      if (labErr || !lab) return res.status(404).json({ error: 'Lab not found' });

      // Clamp submitted score to lab max — prevents client manipulation
      const submittedPoints = parseInt(req.body.points_earned, 10);
      const hintsUsed       = parseInt(req.body.hints_used ?? 0, 10);
      const pointsEarned    = Math.min(submittedPoints, lab.points);

      // Check for existing completion
      const { data: existing } = await supabase
        .from('lab_completions')
        .select('points_earned')
        .eq('user_uuid', req.user.uuid)
        .eq('lab_uuid', lab.uuid)
        .single();

      // Only update if no existing completion, or new score is higher
      if (!existing || (existing.points_earned == null) || pointsEarned > existing.points_earned) {
        const { error: upsertErr } = await supabase
          .from('lab_completions')
          .upsert(
            [{
              user_uuid:     req.user.uuid,
              lab_uuid:      lab.uuid,
              points_earned: pointsEarned,
              hints_used:    hintsUsed,
            }],
            { onConflict: 'user_uuid,lab_uuid' }
          );

        if (upsertErr) throw upsertErr;
      }

      res.json({
        success:       true,
        points_earned: pointsEarned,
        lab_max:       lab.points,
        message:       pointsEarned === lab.points
          ? 'Full marks! No hints used.'
          : `Completed with ${pointsEarned} / ${lab.points} points.`,
      });
    } catch (err) {
      console.error('Complete error:', err);
      res.status(500).json({ error: 'Failed to record completion' });
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
        completedAt:  completion?.completed_at,
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