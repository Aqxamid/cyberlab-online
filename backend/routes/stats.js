const express = require('express');
const router  = express.Router();
const supabase = require('../db/supabase');
const { authenticateToken, requireRole } = require('../middleware/auth');

// ── GET /api/stats/student — personal stats ───────────────────
router.get('/student', authenticateToken, async (req, res) => {
  try {
    // Fetch completions using uuid only (no implicit FK join — lab_id is NULL on new rows)
    const { data: completions } = await supabase
      .from('lab_completions')
      .select('lab_uuid, completed_at')
      .eq('user_uuid', req.user.uuid);

    const { data: attempts } = await supabase
      .from('lab_attempts')
      .select('correct, attempted_at')
      .eq('user_uuid', req.user.uuid);

    const { data: allLabs } = await supabase
      .from('labs')
      .select('uuid')
      .eq('enabled', true);

    // Manually fetch lab details for completed labs using lab_uuid
    const completedUuids = (completions || []).map(c => c.lab_uuid).filter(Boolean);
    const { data: completedLabDetails } = completedUuids.length
      ? await supabase
          .from('labs')
          .select('uuid, title, category, difficulty, points')
          .in('uuid', completedUuids)
      : { data: [] };

    // Build a lookup map and merge lab details into each completion
    const labMap = Object.fromEntries((completedLabDetails || []).map(l => [l.uuid, l]));
    const completionsWithLabs = (completions || []).map(c => ({
      ...c,
      labs: labMap[c.lab_uuid] || null,
    }));

    const totalLabs       = allLabs?.length || 0;
    const completed       = completionsWithLabs.length;
    const totalAttempts   = attempts?.length || 0;
    const correctAttempts = attempts?.filter(a => a.correct).length || 0;
    const totalPoints     = completionsWithLabs.reduce((sum, c) => sum + (c.labs?.points || 0), 0);

    // Group completions by category
    const byCategory = {};
    completionsWithLabs.forEach(c => {
      const cat = c.labs?.category || 'Unknown';
      byCategory[cat] = (byCategory[cat] || 0) + 1;
    });

    // Recent activity (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentActivity = attempts?.filter(a => new Date(a.attempted_at) > sevenDaysAgo).length || 0;

    res.json({
      totalLabs,
      completed,
      totalPoints,
      totalAttempts,
      correctAttempts,
      accuracy:              totalAttempts ? Math.round((correctAttempts / totalAttempts) * 100) : 0,
      recentActivity,
      completionsByCategory: byCategory,
      recentCompletions:     completionsWithLabs.slice(-5).reverse(),
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ── GET /api/stats/admin — platform-wide (instructor/admin) ───
router.get('/admin', authenticateToken, requireRole('instructor', 'admin'), async (req, res) => {
  try {
    const { data: users }       = await supabase.from('users').select('uuid, role');
    const { data: labs }        = await supabase.from('labs').select('uuid, enabled');
    const { data: completions } = await supabase.from('lab_completions').select('user_uuid, lab_uuid, completed_at');
    const { data: attempts }    = await supabase.from('lab_attempts').select('user_uuid, correct, attempted_at');

    // Active users in the last 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const activeUsers = new Set(
      (attempts || [])
        .filter(a => new Date(a.attempted_at) > sevenDaysAgo)
        .map(a => a.user_uuid)
    ).size;

    res.json({
      totalUsers:       users?.length || 0,
      students:         users?.filter(u => u.role === 'student').length || 0,
      instructors:      users?.filter(u => u.role === 'instructor').length || 0,
      totalLabs:        labs?.length || 0,
      enabledLabs:      labs?.filter(l => l.enabled).length || 0,
      totalCompletions: completions?.length || 0,
      totalAttempts:    attempts?.length || 0,
      activeUsers,
      successRate:      attempts?.length
        ? Math.round((attempts.filter(a => a.correct).length / attempts.length) * 100)
        : 0,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admin stats' });
  }
});

module.exports = router;