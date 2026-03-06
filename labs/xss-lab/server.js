const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const app      = express();
const PORT     = process.env.PORT || 5003;

// H4 FIX: Secret for signing/verifying lab session tokens issued by the main backend
const LAB_TOKEN_SECRET = process.env.LAB_TOKEN_SECRET;
if (!LAB_TOKEN_SECRET) {
  console.error('FATAL: LAB_TOKEN_SECRET is not set');
  process.exit(1);
}

// L2 FIX: Restrict CORS to the frontend origin — NOT a wildcard
// Previously: app.use(cors())  which allows all origins (*)
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
app.use(cors({ origin: FRONTEND_URL }));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── In-memory comment store (intentionally vulnerable to stored XSS for teaching) ──
let comments = [
  { id: 1, author: 'alice', text: 'Great article! Really helpful content.', timestamp: new Date(Date.now() - 3600000).toISOString() },
  { id: 2, author: 'bob',   text: 'Thanks for sharing this.',               timestamp: new Date(Date.now() - 1800000).toISOString() },
];
let nextId = 3;

// ── H4 FIX: Token-gated flag endpoint ────────────────────────────────────────
// Previously: GET /api/flag with NO authentication — anyone could curl it directly.
// Now:        Requires a valid lab session token issued by the main backend.
//             Students must actually trigger the XSS payload to retrieve the flag.
//
// How it works:
//   1. When a student opens the XSS lab, the main backend issues a signed
//      lab_token via POST /api/labs/xss-reflected/start (see backend/routes/labs.js)
//   2. The frontend passes this token in the X-Lab-Token header for API calls.
//   3. The XSS payload must fetch /api/flag with the valid token to get the flag.
//      (The token is embedded in the page via the frontend — students discover it
//       by inspecting the DOM or network tab, which is part of the learning.)

function verifyLabToken(token) {
  try {
    const [payload64, sig] = token.split('.');
    if (!payload64 || !sig) return null;
    const expected = crypto
      .createHmac('sha256', LAB_TOKEN_SECRET)
      .update(payload64)
      .digest('hex');
    if (expected !== sig) return null;
    const payload = JSON.parse(Buffer.from(payload64, 'base64').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return null; // expired
    return payload;
  } catch {
    return null;
  }
}

app.get('/api/flag', (req, res) => {
  const token = req.headers['x-lab-token'];
  if (!token) {
    return res.status(401).json({ error: 'Lab session token required. Trigger the XSS payload to get it.' });
  }
  const payload = verifyLabToken(token);
  if (!payload) {
    return res.status(403).json({ error: 'Invalid or expired lab token.' });
  }
  // H4 FIX: Return the flag only to users with a valid session token
  res.json({ flag: process.env.XSS_FLAG || 'FLAG{xss_reflected_pwned}' });
});

// ── Vulnerable comment endpoints (intentional for the lab) ───────────────────
app.get('/api/vulnerable/comments', (req, res) => res.json(comments));

app.post('/api/vulnerable/comments', (req, res) => {
  const { author, text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  // Length limit to prevent abuse of the stored XSS storage
  if (text.length > 2000) return res.status(400).json({ error: 'Comment too long' });
  const c = { id: nextId++, author: author || 'anonymous', text, timestamp: new Date().toISOString() };
  comments.push(c);
  res.status(201).json(c);
});

app.post('/api/vulnerable/comments/reset', (req, res) => {
  comments = [
    { id: 1, author: 'alice', text: 'Great article! Really helpful content.', timestamp: new Date(Date.now() - 3600000).toISOString() },
    { id: 2, author: 'bob',   text: 'Thanks for sharing this.',               timestamp: new Date(Date.now() - 1800000).toISOString() },
  ];
  nextId = 3;
  res.json({ ok: true });
});

// ── Patched search endpoint ───────────────────────────────────────────────────
app.get('/api/patched/search', (req, res) => {
  const q = req.query.q || '';
  const safe = q.replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#x27;' }[c]));
  res.json({ reflected: safe });
});

// ── Main lab UI (HTML with intentional XSS for teaching) ─────────────────────
// The lab token is injected into the page so students can discover it via DevTools
// and learn how tokens are passed between the frontend and APIs.
app.get('/', (req, res) => {
  // In production the frontend would pass the lab token via query param after auth
  const labToken = req.query.token || '';

  const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TechBlog - XSS Lab</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
body { font-family: 'IBM Plex Sans', sans-serif; background: #0d1117; color: #e6edf3; }
code, .font-mono, input.font-mono, textarea.font-mono { font-family: 'JetBrains Mono', monospace; }
pre { background: #161b22; color: #8b949e; padding: 0.75rem; border-radius: 8px; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; font-family: 'JetBrains Mono', monospace; border: 1px solid #30363d; }
.flag-box { background: #2d2a00; border: 2px solid #eab308; color: #fef08a; padding: 0.75rem 1rem; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 0.9rem; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; }
input, textarea { background: #0d1117 !important; color: #e6edf3 !important; border-color: #30363d !important; }
</style>
</head>
<body>
<nav class="border-b border-gray-800 px-6 py-3 flex items-center justify-between" style="background:#161b22">
  <div class="flex items-center gap-2">
    <span class="text-2xl">📰</span>
    <span class="font-bold text-white">TechBlog</span>
    <span class="text-xs px-2 py-0.5 rounded ml-2" style="background:#3d1a1a;color:#f85149">XSS Lab</span>
  </div>
  <div class="text-xs" style="color:#484f58">Intentionally Vulnerable Demo</div>
</nav>
<div class="max-w-4xl mx-auto px-4 py-8 space-y-6">

  <div class="rounded-xl p-4 flex gap-3" style="background:#271c00;border:1px solid #9e6a03">
    <span class="text-2xl flex-shrink-0">⚠️</span>
    <div>
      <p class="font-semibold text-sm" style="color:#d29922">XSS Lab — Reflected &amp; Stored XSS</p>
      <p class="text-xs mt-1" style="color:#b08800">
        <strong>To get the flag:</strong> inject a script that calls
        <code class="px-1 rounded" style="background:#3d2e00">fetch('/api/flag', {headers:{'x-lab-token': window.__labToken}})</code>
        and displays the result. The lab token is in <code>window.__labToken</code> — inspect the page source!
      </p>
    </div>
  </div>

  <!-- Reflected XSS -->
  <div class="card p-6 shadow-sm">
    <h2 class="font-bold mb-1 flex items-center gap-2 text-white">
      🔍 Search Articles
      <span class="text-xs px-2 py-0.5 rounded" style="background:#3d1a1a;color:#f85149">REFLECTED XSS</span>
    </h2>
    <p class="text-xs mb-4" style="color:#8b949e">Input is reflected directly into the page as raw HTML — no sanitization.</p>
    <div class="flex gap-2 mb-3">
      <input id="search-q" type="text" placeholder='Try: &lt;img src=x onerror=alert(1)&gt;'
        class="flex-1 border rounded-lg px-3 py-2 text-sm focus:outline-none font-mono">
      <button id="search-btn" class="text-white px-4 py-2 rounded-lg text-sm font-medium" style="background:#238636">Search</button>
    </div>
    <div class="flex gap-2 mb-4 flex-wrap items-center">
      <span class="text-xs" style="color:#8b949e">Hints:</span>
      <button id="hint-alert" class="text-xs px-2 py-1 rounded font-mono" style="background:#2d1c00;color:#d29922">alert(1)</button>
      <button id="hint-flag" class="text-xs px-2 py-1 rounded font-semibold" style="background:#1b3a2a;color:#3fb950">🏁 get flag payload</button>
    </div>
    <div class="p-3 text-sm mb-3" style="background:#0d1117;border:1px solid #30363d;border-radius:8px">
      <p class="text-xs mb-2" style="color:#484f58">Page renders your input here (innerHTML):</p>
      <div id="search-result" class="min-h-8" style="color:#e6edf3"></div>
    </div>
    <div id="flag-display" class="hidden flag-box"></div>
  </div>

  <!-- Stored XSS -->
  <div class="card p-6 shadow-sm">
    <h2 class="font-bold mb-1 flex items-center gap-2 text-white">
      💬 Comments
      <span class="text-xs px-2 py-0.5 rounded" style="background:#3d1a1a;color:#f85149">STORED XSS</span>
    </h2>
    <p class="text-xs mb-4" style="color:#8b949e">Comments are stored and rendered as raw HTML for every visitor.</p>
    <div id="comments-list" class="space-y-3 mb-4"></div>
    <div class="pt-4 space-y-2" style="border-top:1px solid #30363d">
      <input id="c-author" type="text" placeholder="Your name" class="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none">
      <textarea id="c-text" rows="3" placeholder="Try an XSS payload as your comment..." class="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none font-mono resize-none"></textarea>
      <div class="flex gap-2 flex-wrap">
        <button id="cmnt-hint-flag" class="text-xs px-2 py-1 rounded font-semibold" style="background:#1b3a2a;color:#3fb950">🏁 flag payload</button>
        <button id="cmnt-clear" class="text-xs px-2 py-1 rounded" style="background:#3d1a1a;color:#f85149">🗑 clear comments</button>
      </div>
      <button id="post-btn" class="text-white px-4 py-2 rounded-lg text-sm font-medium" style="background:#238636">Post Comment</button>
    </div>
  </div>

  <!-- Patched -->
  <div class="card p-6 shadow-sm">
    <h2 class="font-bold mb-3 flex items-center gap-2 text-white">
      ✅ Patched Search
      <span class="text-xs px-2 py-0.5 rounded" style="background:#1b3a2a;color:#3fb950">HTML Escaped</span>
    </h2>
    <div class="flex gap-2 mb-3">
      <input id="p-search" type="text" placeholder="Try same payloads here..." class="flex-1 border rounded-lg px-3 py-2 text-sm focus:outline-none font-mono">
      <button id="p-search-btn" class="text-white px-4 py-2 rounded-lg text-sm font-medium" style="background:#1f6feb">Search (Safe)</button>
    </div>
    <pre id="p-search-out">// Patched version escapes HTML — scripts won't execute</pre>
  </div>

</div>

<script>
// H4 FIX: Lab token injected server-side — students discover it via page source / DevTools.
// This is intentional: part of the learning is understanding how tokens flow in apps.
window.__labToken = ${JSON.stringify(labToken)};

const flagPayload = '<img src=x onerror="fetch(\\'/api/flag\\',{headers:{\\' x-lab-token\\':\\'' + window.__labToken + '\\'}} ).then(r=>r.json()).then(d=>{ document.getElementById(\\'flag-display\\').textContent=\\'🏁 \\'+d.flag; document.getElementById(\\'flag-display\\').classList.remove(\\'hidden\\'); })">';

document.getElementById('hint-alert').addEventListener('click', () => {
  document.getElementById('search-q').value = '<img src=x onerror=alert(1)>'; doSearch();
});
document.getElementById('hint-flag').addEventListener('click', () => {
  document.getElementById('search-q').value = flagPayload; doSearch();
});
document.getElementById('cmnt-hint-flag').addEventListener('click', () => {
  document.getElementById('c-text').value = flagPayload;
});
document.getElementById('cmnt-clear').addEventListener('click', async () => {
  await fetch('/api/vulnerable/comments/reset', { method: 'POST' });
  loadComments();
});
document.getElementById('search-btn').addEventListener('click', doSearch);
document.getElementById('search-q').addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });
document.getElementById('post-btn').addEventListener('click', postComment);
document.getElementById('p-search-btn').addEventListener('click', doPatchSearch);
document.getElementById('p-search').addEventListener('keydown', e => { if (e.key === 'Enter') doPatchSearch(); });

function doSearch() {
  document.getElementById('search-result').innerHTML = document.getElementById('search-q').value;
}
async function postComment() {
  const author = document.getElementById('c-author').value || 'Anonymous';
  const text   = document.getElementById('c-text').value;
  if (!text) return;
  try {
    await fetch('/api/vulnerable/comments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author, text }),
    });
    document.getElementById('c-text').value = '';
    loadComments();
  } catch(e) { alert('Error: ' + e.message); }
}
async function loadComments() {
  try {
    const list = await fetch('/api/vulnerable/comments').then(r => r.json());
    document.getElementById('comments-list').innerHTML = list.map(c =>
      '<div class="p-3 rounded-lg" style="border:1px solid #30363d">'
      + '<div class="flex items-center gap-2 mb-1">'
      + '<span class="text-xs font-semibold" style="color:#58a6ff">' + c.author + '</span>'
      + '<span class="text-xs" style="color:#484f58">' + new Date(c.timestamp).toLocaleString() + '</span>'
      + '</div><div class="text-sm" style="color:#c9d1d9">' + c.text + '</div></div>'
    ).join('');
  } catch(e) { console.error('Failed to load comments', e); }
}
async function doPatchSearch() {
  const q = document.getElementById('p-search').value;
  try {
    const d = await fetch('/api/patched/search?q=' + encodeURIComponent(q)).then(r => r.json());
    document.getElementById('p-search-out').textContent = 'Sanitized: ' + d.reflected;
  } catch(e) { document.getElementById('p-search-out').textContent = 'Error: ' + e.message; }
}
loadComments();
<\/script>
</body></html>`;

  res.send(HTML);
});

app.listen(PORT, () => console.log(`🕷️  XSS Lab running on port ${PORT}`));