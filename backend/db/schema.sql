-- CyberLab Supabase Schema
-- Run this in your Supabase SQL editor

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(20) DEFAULT 'student' CHECK (role IN ('student', 'instructor', 'admin')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS labs (
  id SERIAL PRIMARY KEY,
  slug VARCHAR(100) UNIQUE NOT NULL,
  title VARCHAR(200) NOT NULL,
  description TEXT,
  category VARCHAR(100),
  difficulty VARCHAR(20) DEFAULT 'beginner' CHECK (difficulty IN ('beginner', 'intermediate', 'advanced')),
  flag TEXT NOT NULL,
  content TEXT,
  enabled BOOLEAN DEFAULT true,
  points INTEGER DEFAULT 100,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS lab_attempts (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  lab_id INTEGER REFERENCES labs(id) ON DELETE CASCADE,
  flag_submitted TEXT NOT NULL,
  correct BOOLEAN NOT NULL,
  attempted_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS lab_completions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  lab_id INTEGER REFERENCES labs(id) ON DELETE CASCADE,
  completed_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, lab_id)
);

-- Demo users are seeded via: cd backend && node db/seed.js
-- (seed.js generates proper bcrypt hashes at runtime)

-- Seed labs
INSERT INTO labs (slug, title, description, category, difficulty, flag, content, points) VALUES
(
  'idor-basics',
  'IDOR: Insecure Direct Object Reference',
  'Learn how IDOR vulnerabilities allow attackers to access unauthorized resources by manipulating object references.',
  'Web Security',
  'beginner',
  'FLAG{idor_is_dangerous_123}',
  '<h2>What is IDOR?</h2>
<p>Insecure Direct Object Reference (IDOR) occurs when an application uses user-controllable input to access objects directly without proper authorization checks.</p>
<h3>Example</h3>
<pre><code>GET /api/users/1234/profile  ← What if you change 1234 to 1235?</code></pre>
<h3>Your Mission</h3>
<p>The vulnerable API is running on port 5000. Try accessing <code>/api/vulnerable/users/99</code> to find the admin flag.</p>
<p>Then explore <code>/api/vulnerable/documents/42</code> for a bonus flag.</p>',
  100
),
(
  'sql-injection-101',
  'SQL Injection Fundamentals',
  'Understand classic SQL injection attacks and how they can expose your entire database.',
  'Web Security',
  'beginner',
  'FLAG{sql_injected_success}',
  '<h2>SQL Injection</h2>
<p>SQL Injection allows attackers to interfere with queries an application makes to its database.</p>
<h3>Classic Payload</h3>
<pre><code>'' OR ''1''=''1</code></pre>
<h3>Your Mission</h3>
<p>Try submitting <code>'' OR 1=1--</code> as a username in a login form to bypass authentication.</p>
<p>Submit the flag once you understand how the attack works: <strong>FLAG{sql_injected_success}</strong></p>',
  150
),
(
  'xss-reflected',
  'Cross-Site Scripting (Reflected XSS)',
  'Discover how reflected XSS attacks can steal session cookies and hijack user accounts.',
  'Web Security',
  'intermediate',
  'FLAG{xss_reflected_pwned}',
  '<h2>Reflected XSS</h2>
<p>Reflected XSS occurs when malicious scripts are injected into a webpage via URL parameters and immediately reflected back to the user.</p>
<h3>Example Payload</h3>
<pre><code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></pre>
<h3>Your Mission</h3>
<p>Craft a URL that would steal a session cookie using a reflected XSS payload. Once you understand the mechanism, submit: <strong>FLAG{xss_reflected_pwned}</strong></p>',
  200
),
(
  'jwt-forgery',
  'JWT Token Manipulation',
  'Explore how weak JWT configurations can be exploited to forge authentication tokens.',
  'Authentication',
  'intermediate',
  'FLAG{jwt_none_algorithm_bypass}',
  '<h2>JWT Security</h2>
<p>JSON Web Tokens can be vulnerable when servers accept the "none" algorithm or use weak secrets.</p>
<h3>Attack: Algorithm Confusion</h3>
<pre><code>{"alg":"none","typ":"JWT"}</code></pre>
<p>By changing the algorithm to "none", some servers will accept tokens without a signature.</p>
<h3>Your Mission</h3>
<p>Decode a JWT, change the role to "admin", and re-encode with alg:none. Submit: <strong>FLAG{jwt_none_algorithm_bypass}</strong></p>',
  250
),
(
  'path-traversal',
  'Path Traversal Attack',
  'Learn how directory traversal vulnerabilities can expose sensitive files on the server.',
  'Server Security',
  'advanced',
  'FLAG{traversed_the_path}',
  '<h2>Path Traversal</h2>
<p>Path traversal (also known as directory traversal) allows attackers to read files outside the intended directory.</p>
<h3>Classic Payload</h3>
<pre><code>../../../../etc/passwd</code></pre>
<h3>Your Mission</h3>
<p>If a file download endpoint is <code>/download?file=report.pdf</code>, try traversing to read <code>/etc/passwd</code>. Submit: <strong>FLAG{traversed_the_path}</strong></p>',
  300
)
ON CONFLICT (slug) DO NOTHING;
