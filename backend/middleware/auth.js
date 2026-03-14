const jwt      = require('jsonwebtoken');
const supabase = require('../db/supabase');

const JWT_SECRET = process.env.JWT_SECRET;

// ── Startup guard: crash immediately if secret is missing/default ─
if (!JWT_SECRET || JWT_SECRET === 'cyberlab_secret_change_in_production') {
  throw new Error(
    '[FATAL] JWT_SECRET is not set or is still the default placeholder.\n' +
    'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"'
  );
}

async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token      = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) return res.status(401).json({ error: 'Access token required' });

  // Step 1: verify signature & expiry (alg:none and algorithm confusion blocked)
  let user;
  try {
    user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }

  // Step 2: check token hasn't been blacklisted (logout invalidation)
  try {
    const { data } = await supabase
      .from('invalidated_tokens')
      .select('token')
      .eq('token', token)
      .maybeSingle();

    if (data) {
      return res.status(401).json({ error: 'Token has been invalidated. Please log in again.' });
    }
  } catch (err) {
    // If the blacklist check fails (e.g. table not yet created), fail open
    // so existing functionality keeps working — just log a warning
    console.warn('[auth] Blacklist check failed:', err.message);
  }

  req.user = user;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

module.exports = { authenticateToken, requireRole, JWT_SECRET };