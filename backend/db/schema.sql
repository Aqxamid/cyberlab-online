-- ════════════════════════════════════════════════════════════════════════════
-- CyberLab Supabase Schema  —  Security-Hardened Version
-- Run this in your Supabase SQL editor
-- ════════════════════════════════════════════════════════════════════════════

-- ── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  username      VARCHAR(50)  UNIQUE NOT NULL,
  email         VARCHAR(100) UNIQUE NOT NULL,
  password_hash TEXT         NOT NULL,
  role          VARCHAR(20)  DEFAULT 'student'
                CHECK (role IN ('student', 'instructor', 'admin')),
  created_at    TIMESTAMPTZ  DEFAULT NOW()
);

-- ── H3 FIX: Refresh tokens table for short-lived JWT + revocable refresh ──────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         SERIAL      PRIMARY KEY,
  user_id    INTEGER     REFERENCES users(id) ON DELETE CASCADE,
  token      TEXT        UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked    BOOLEAN     DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
-- Index for fast lookup on token column
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);

-- ── Labs ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS labs (
  id          SERIAL       PRIMARY KEY,
  slug        VARCHAR(100) UNIQUE NOT NULL,
  title       VARCHAR(200) NOT NULL,
  description TEXT,
  category    VARCHAR(100),
  difficulty  VARCHAR(20)  DEFAULT 'beginner'
              CHECK (difficulty IN ('beginner', 'intermediate', 'advanced')),
  flag_hash   TEXT         NOT NULL,  -- SHA-256 hash of the flag (lowercase, trimmed)
  content     TEXT,
  enabled     BOOLEAN      DEFAULT TRUE,
  points      INTEGER      DEFAULT 100,
  created_at  TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Lab Attempts ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lab_attempts (
  id             SERIAL      PRIMARY KEY,
  user_id        INTEGER     REFERENCES users(id) ON DELETE CASCADE,
  lab_id         INTEGER     REFERENCES labs(id)  ON DELETE CASCADE,
  flag_submitted TEXT        NOT NULL, -- SHA-256 hash of what was submitted
  correct        BOOLEAN     NOT NULL,
  attempted_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ── Lab Completions ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lab_completions (
  id           SERIAL      PRIMARY KEY,
  user_id      INTEGER     REFERENCES users(id) ON DELETE CASCADE,
  lab_id       INTEGER     REFERENCES labs(id)  ON DELETE CASCADE,
  completed_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, lab_id)
);

-- ════════════════════════════════════════════════════════════════════════════
-- SEED LABS
-- C3 FIX: flag_hash values are pre-computed SHA-256 hashes.
-- The actual flag values are NEVER stored here.
-- Flags must be set via environment variables or a secure secrets manager.
-- Compute hashes with: node -e "const c=require('crypto'); console.log(c.createHash('sha256').update('FLAG{your_flag}'.trim().toLowerCase()).digest('hex'))"
-- ════════════════════════════════════════════════════════════════════════════
INSERT INTO labs (slug, title, description, category, difficulty, flag_hash, content, points)
VALUES

(
  'idor-basics',
  'IDOR: Insecure Direct Object Reference',
  'Learn how IDOR vulnerabilities allow attackers to access unauthorized resources by manipulating object references.',
  'Web Security', 'beginner',
  '0f04d8bd7bce2b09170012ba26dc98b587d5f8590aaa47f5c9d66ed5b11f7155',
  '<h2>What is IDOR?</h2>
<p>Insecure Direct Object Reference (IDOR) occurs when an application uses user-controllable input to access objects directly without proper authorization checks.</p>
<h3>Example</h3>
<pre><code>GET /api/users/1234/profile ← What if you change 1234 to 1235?</code></pre>
<h3>Your Mission</h3>
<p>The vulnerable API is running on the IDOR lab. Try accessing <code>/api/vulnerable/users/99</code> to find the admin flag.</p>',
  100
),

(
  'sql-injection-101',
  'SQL Injection Fundamentals',
  'Understand classic SQL injection attacks and how they can expose your entire database.',
  'Web Security', 'beginner',
  'c8ec5b8c30de27a0960f9eff1fc4624027c4c76e683732eb32d50dc75dc242da',
  '<h2>SQL Injection</h2>
<p>SQL Injection allows attackers to interfere with queries an application makes to its database.</p>
<h3>Classic Payload</h3>
<pre><code>'' OR ''1''=''1</code></pre>
<h3>Your Mission</h3>
<p>Try submitting <code>'' OR 1=1--</code> as a username to bypass authentication in the SQLi lab.</p>',
  150
),

(
  'xss-reflected',
  'Cross-Site Scripting (Reflected XSS)',
  'Discover how reflected XSS attacks can steal session tokens and hijack user accounts.',
  'Web Security', 'intermediate',
  'addac31fc574d58d571f59535237d8d2aa46ac89104dfce4e4bc303ac1a6e240',
  '<h2>Reflected XSS</h2>
<p>Reflected XSS occurs when malicious scripts are injected via URL parameters and immediately reflected back to the user.</p>
<h3>Example Payload</h3>
<pre><code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></pre>
<h3>Your Mission</h3>
<p>Use the XSS lab to craft a payload that calls <code>/api/flag</code> and reveals the flag.</p>',
  200
),

(
  'jwt-forgery',
  'JWT Token Manipulation',
  'Explore how weak JWT configurations can be exploited to forge authentication tokens.',
  'Authentication', 'intermediate',
  '7eb2b81494a4cf5d72fcaffb8ad107394358536ce05096c849ec0df6bf19b56a',
  '<h2>JWT Security</h2>
<p>JSON Web Tokens can be vulnerable when servers accept the "none" algorithm or use weak secrets.</p>
<h3>Attack: Algorithm Confusion</h3>
<pre><code>{"alg":"none","typ":"JWT"}</code></pre>
<h3>Your Mission</h3>
<p>Use the JWT lab to forge an admin token using the alg:none bypass technique.</p>',
  250
),

(
  'path-traversal',
  'Path Traversal Attack',
  'Learn how directory traversal vulnerabilities can expose sensitive files on the server.',
  'Server Security', 'advanced',
  '22292a445661c5269102b263211dc4e410868eed389b832bd1da05c9392b3c1a',
  '<h2>Path Traversal</h2>
<p>Path traversal allows attackers to read files outside the intended directory.</p>
<h3>Classic Payload</h3>
<pre><code>../../../../etc/passwd</code></pre>
<h3>Your Mission</h3>
<p>Use the path traversal lab to read a protected file and retrieve the flag.</p>',
  300
)

ON CONFLICT (slug) DO NOTHING;