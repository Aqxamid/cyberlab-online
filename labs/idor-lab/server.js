const express   = require('express');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const jwt       = require('jsonwebtoken');
const https     = require('https');
const http      = require('http');

const app  = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── CyberLab Auth Guard ──────────────────────────────────────
const JWT_SECRET   = process.env.JWT_SECRET   || 'cyberlab_secret_change_in_production';
const BACKEND_URL  = process.env.BACKEND_URL  || 'http://localhost:4000';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

function nodeFetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed  = new URL(url);
    const lib     = parsed.protocol === 'https:' ? https : http;
    const req     = lib.request({
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   options.method || 'GET',
      headers:  options.headers || {},
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300 }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function requireLabAuth(req, res, next) {
  if (req.path.startsWith('/api/')) return next();
  const token = req.query.token;
  if (!token) {
    return res.send(`<!DOCTYPE html><html><head><script>
      var t = sessionStorage.getItem('cl_token');
      if (t) window.location.href = window.location.pathname + '?token=' + encodeURIComponent(t);
      else   window.location.href = '${FRONTEND_URL}/login.html';
    <\/script></head><body></body></html>`);
  }
  try { jwt.verify(token, JWT_SECRET); } catch { return res.redirect(`${FRONTEND_URL}/login.html`); }
  try {
    const r = await nodeFetch(`${BACKEND_URL}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) return res.redirect(`${FRONTEND_URL}/login.html`);
  } catch (err) { console.warn('[idor-lab] Backend unreachable for auth check:', err.message); }
  next();
}
app.use(requireLabAuth);

const labLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests to the lab. Slow down and read the theory!' },
});
app.use('/api', labLimiter);

const users = {
  1:  { id:1,  username:'alice',   email:'alice@corp.io',   role:'employee', department:'HR' },
  2:  { id:2,  username:'bob',     email:'bob@corp.io',     role:'employee', department:'Engineering' },
  3:  { id:3,  username:'charlie', email:'charlie@corp.io', role:'employee', department:'Marketing' },
  99: { id:99, username:'admin',   email:'admin@corp.io',   role:'admin',    department:'Executive', secret:'FLAG{idor_is_dangerous_123}' },
};
const documents = {
  1:  { id:1,  owner_id:1,  title:'Q1 Report',        content:"Alice's Q1 review. Rating: 4/5.",           classification:'internal' },
  2:  { id:2,  owner_id:2,  title:'Project Roadmap',   content:"Bob's engineering roadmap for 2025.",        classification:'internal' },
  3:  { id:3,  owner_id:3,  title:'Campaign Brief',    content:"Charlie's marketing campaign brief.",        classification:'internal' },
  42: { id:42, owner_id:99, title:'Admin Credentials', content:'CONFIDENTIAL — FLAG{idor_docs_exposed_42}', classification:'top-secret' },
};

app.get('/api/vulnerable/users/:id',     (req, res) => { const u = users[+req.params.id];     u ? res.json(u) : res.status(404).json({ error: 'Not found' }); });
app.get('/api/vulnerable/documents/:id', (req, res) => { const d = documents[+req.params.id]; d ? res.json(d) : res.status(404).json({ error: 'Not found' }); });

app.get('/api/patched/users/:id', (req, res) => {
  const myId = +req.headers['x-user-id'], tid = +req.params.id;
  if (!myId) return res.status(401).json({ error: 'Missing x-user-id header' });
  if (myId !== tid) return res.status(403).json({ error: 'Access denied: you can only view your own profile' });
  const { secret, ...safe } = users[tid] || {};
  safe.id ? res.json(safe) : res.status(404).json({ error: 'Not found' });
});
app.get('/api/patched/documents/:id', (req, res) => {
  const myId = +req.headers['x-user-id'];
  if (!myId) return res.status(401).json({ error: 'Missing x-user-id header' });
  const d = documents[+req.params.id];
  if (!d) return res.status(404).json({ error: 'Not found' });
  if (d.owner_id !== myId) return res.status(403).json({ error: 'Access denied: not your document' });
  res.json(d);
});

app.get('/', (req, res) => {
  const token       = req.query.token || '';
  const backendUrl  = BACKEND_URL;
  const frontendUrl = FRONTEND_URL;

  // Fixed IDOR favicon: clean lock+magnifier SVG, no emoji
  const favicon = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%231d4ed8'/%3E%3Ccircle cx='13' cy='13' r='5' fill='none' stroke='white' stroke-width='2.5'/%3E%3Cline x1='17' y1='17' x2='23' y2='23' stroke='white' stroke-width='2.5' stroke-linecap='round'/%3E%3Crect x='7' y='20' width='8' height='6' rx='1.5' fill='white' opacity='0.9'/%3E%3Crect x='10' y='18.5' width='2' height='3' rx='1' fill='white'/%3E%3C/svg%3E";

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CorpPortal — IDOR Lab</title>
<link rel="icon" type="image/svg+xml" href="${favicon}">
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
body { font-family: 'Inter', sans-serif; background: #f1f5f9; }
pre  { background: #0f172a; color: #94a3b8; padding: 1rem; border-radius: 8px; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; min-height: 60px; line-height: 1.6; }
.flag-box { background: #fef9c3; border: 2px solid #eab308; color: #713f12; padding: 0.75rem 1rem; border-radius: 8px; font-family: monospace; font-weight: 700; font-size: 0.85rem; display: none; margin: 0 1rem 1rem; word-break: break-all; }

/* ── Fake Browser ── */
.fake-browser { border: 1px solid #cbd5e1; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.08); background: white; }
.browser-chrome { background: #e2e8f0; padding: 8px 12px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #cbd5e1; }
.traffic-lights { display: flex; gap: 5px; flex-shrink: 0; }
.tl { width: 11px; height: 11px; border-radius: 50%; }
.tl-r { background: #ef4444; } .tl-y { background: #f59e0b; } .tl-g { background: #22c55e; }
.nav-area { display: flex; gap: 3px; flex-shrink: 0; }
.nav-btn { background: none; border: none; cursor: default; color: #94a3b8; font-size: 15px; padding: 1px 5px; border-radius: 4px; line-height: 1; }
.nav-btn.clickable { cursor: pointer; }
.nav-btn.clickable:hover { background: #cbd5e1; color: #475569; }
/* URL bar — scrollable on mobile so full path is always reachable */
.url-wrap { flex: 1; display: flex; align-items: center; background: white; border: 1px solid #94a3b8; border-radius: 5px; padding: 0 8px; height: 28px; gap: 5px; transition: border-color 0.15s, box-shadow 0.15s; cursor: text; min-width: 0; overflow: hidden; }
.url-wrap:focus-within { border-color: #3b82f6; box-shadow: 0 0 0 2px rgba(59,130,246,0.2); }
.url-scheme { font-size: 12px; color: #16a34a; font-family: 'Courier New', monospace; flex-shrink: 0; user-select: none; font-weight: 600; }
.url-input { flex: 1; border: none; outline: none; font-size: 12.5px; font-family: 'Courier New', monospace; color: #1e293b; background: transparent; padding: 0; min-width: 0; caret-color: #3b82f6; width: 100%; }
.url-go-btn { background: none; border: none; cursor: pointer; color: #64748b; font-size: 14px; padding: 0 2px; line-height: 1; flex-shrink: 0; transition: color 0.1s; }
.url-go-btn:hover { color: #1d4ed8; }
.browser-status-bar { background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 3px 12px; font-size: 10.5px; color: #94a3b8; font-family: monospace; min-height: 20px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.page-topbar { background: #1d4ed8; color: white; padding: 8px 16px; display: flex; justify-content: space-between; align-items: center; font-size: 11px; flex-wrap: wrap; gap: 4px; }
.response-panel { margin: 12px; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
.response-panel-header { background: #f8fafc; border-bottom: 1px solid #e2e8f0; padding: 6px 12px; display: flex; align-items: center; gap: 8px; font-size: 11px; font-family: monospace; color: #475569; flex-wrap: wrap; }
.http-badge { padding: 1px 7px; border-radius: 3px; font-weight: 700; font-size: 11px; }
.http-200 { background: #dcfce7; color: #166534; }
.http-403 { background: #fee2e2; color: #991b1b; }
.http-404 { background: #fef9c3; color: #713f12; }
.method-tag { background: #dbeafe; color: #1d4ed8; padding: 1px 6px; border-radius: 3px; font-weight: 700; font-size: 11px; flex-shrink: 0; }
.hint-body { display: none; }
.hint-body.open { display: block; }
.hint-trigger { transition: background 0.15s; }
.hint-trigger:hover { background: #fffbeb; }
.pip { width: 10px; height: 10px; border-radius: 50%; background: #e2e8f0; transition: background 0.2s; display: inline-block; }
.pip.used { background: #ef4444; }
.pip.warn { background: #f59e0b; }
.header-field { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 4px; padding: 3px 8px; font-family: monospace; font-size: 12px; color: #166534; }
.header-field:focus { outline: none; border-color: #4ade80; }
/* Score display */
.score-pill { display: inline-flex; align-items: center; gap: 6px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 6px 12px; }
.score-val { font-size: 22px; font-weight: 700; color: #1d4ed8; line-height: 1; }
.score-max { font-size: 12px; color: #64748b; }
.score-deduction { font-size: 11px; color: #ef4444; font-weight: 600; }
/* Completion banner */
.completion-banner { display: none; background: linear-gradient(135deg, #1d4ed8, #1e40af); border-radius: 12px; padding: 20px; color: white; text-align: center; margin-bottom: 16px; }
/* Mobile: browser chrome stacks url bar below dots on very small screens */
@media (max-width: 480px) {
  .browser-chrome { flex-wrap: wrap; }
  .url-wrap { flex-basis: 100%; order: 3; }
  .nav-area { order: 2; }
  .traffic-lights { order: 1; }
  .url-input { font-size: 13px; }
}
</style>
</head>
<body class="min-h-screen">

<nav class="bg-blue-700 text-white px-6 py-3 flex items-center justify-between shadow-lg flex-wrap gap-2">
  <div class="flex items-center gap-3 flex-wrap">
    <div class="w-8 h-8 bg-white rounded flex items-center justify-center flex-shrink-0">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#1d4ed8" class="w-5 h-5">
        <path fill-rule="evenodd" d="M12 1.5a5.25 5.25 0 00-5.25 5.25v3a3 3 0 00-3 3v6.75a3 3 0 003 3h10.5a3 3 0 003-3v-6.75a3 3 0 00-3-3v-3c0-2.9-2.35-5.25-5.25-5.25zm3.75 8.25v-3a3.75 3.75 0 10-7.5 0v3h7.5z" clip-rule="evenodd"/>
      </svg>
    </div>
    <span class="font-bold text-lg">CorpPortal</span>
    <span class="text-blue-300 text-sm hidden sm:inline">Employee Directory</span>
    <span class="text-xs bg-red-500 text-white px-2 py-0.5 rounded font-semibold">IDOR Lab</span>
  </div>
  <div class="text-sm text-blue-200">Logged in as: <strong class="text-white">alice (ID: 1)</strong></div>
</nav>

<div class="max-w-6xl mx-auto px-4 py-6 space-y-5">

  <!-- Completion banner (shown on both flags captured) -->
  <div class="completion-banner" id="completion-banner">
    <div style="font-size:2rem;margin-bottom:8px;">&#127881;</div>
    <p style="font-size:18px;font-weight:700;margin-bottom:4px;">Lab Complete!</p>
    <p style="font-size:13px;opacity:.85;margin-bottom:12px;">You captured both flags and earned:</p>
    <div style="font-size:42px;font-weight:800;letter-spacing:-1px;" id="banner-score">100</div>
    <div style="font-size:13px;opacity:.7;margin-top:2px;">out of 100 points</div>
    <div id="banner-deductions" style="font-size:12px;color:#fca5a5;margin-top:8px;"></div>
  </div>

  <div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">
    <span class="text-2xl flex-shrink-0 mt-0.5">&#127919;</span>
    <div>
      <p class="font-semibold text-amber-800 text-sm">IDOR Lab — Type the URL yourself</p>
      <p class="text-amber-700 text-xs mt-1">You are <strong>Alice (ID: 1)</strong>. Edit the URL in each browser below and press Enter. Find 2 hidden flags by changing object IDs. Revealing hints reduces your score.</p>
    </div>
  </div>

  <div class="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">
    <div class="xl:col-span-2 space-y-5">

      <!-- Challenge 1 -->
      <div>
        <div class="flex items-center gap-2 mb-2 flex-wrap">
          <span class="text-sm font-semibold text-gray-800">Challenge 1 — User Profile Endpoint</span>
          <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-semibold">VULNERABLE</span>
        </div>
        <div class="fake-browser">
          <div class="browser-chrome">
            <div class="traffic-lights"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="nav-area">
              <button class="nav-btn">&#8592;</button>
              <button class="nav-btn">&#8594;</button>
              <button class="nav-btn clickable" id="reload-user">&#8635;</button>
            </div>
            <div class="url-wrap" id="wrap-user">
              <span class="url-scheme">https://</span>
              <input type="text" class="url-input" id="url-user"
                value="corp-portal.internal/api/vulnerable/users/1"
                spellcheck="false" autocomplete="off">
              <button class="url-go-btn" id="go-user">&#10148;</button>
            </div>
          </div>
          <div class="page-topbar">
            <span>corp-portal.internal / Employee Directory API</span>
            <span id="user-status-badge" class="opacity-60">ready</span>
          </div>
          <div>
            <div class="response-panel">
              <div class="response-panel-header">
                <span class="method-tag">GET</span>
                <span id="user-path-display" class="flex-1 truncate">/api/vulnerable/users/1</span>
                <span id="user-http-badge" class="http-badge"></span>
              </div>
              <pre id="user-out">// Edit the URL above and press Enter to send the request
// Try changing the number at the end — you are user ID 1</pre>
            </div>
            <div id="user-flag" class="flag-box">&#127937; </div>
          </div>
          <div class="browser-status-bar" id="user-status-bar">Waiting for navigation...</div>
        </div>
        <p class="text-xs text-gray-400 font-mono mt-1.5 pl-1">&#8593; Change the number at the end of the URL path</p>
      </div>

      <!-- Challenge 2 -->
      <div>
        <div class="flex items-center gap-2 mb-2 flex-wrap">
          <span class="text-sm font-semibold text-gray-800">Challenge 2 — Document Store Endpoint</span>
          <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-semibold">VULNERABLE</span>
        </div>
        <div class="fake-browser">
          <div class="browser-chrome">
            <div class="traffic-lights"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="nav-area">
              <button class="nav-btn">&#8592;</button>
              <button class="nav-btn">&#8594;</button>
              <button class="nav-btn clickable" id="reload-doc">&#8635;</button>
            </div>
            <div class="url-wrap" id="wrap-doc">
              <span class="url-scheme">https://</span>
              <input type="text" class="url-input" id="url-doc"
                value="corp-portal.internal/api/vulnerable/documents/1"
                spellcheck="false" autocomplete="off">
              <button class="url-go-btn" id="go-doc">&#10148;</button>
            </div>
          </div>
          <div class="page-topbar">
            <span>corp-portal.internal / Document Store API</span>
            <span id="doc-status-badge" class="opacity-60">ready</span>
          </div>
          <div>
            <div class="response-panel">
              <div class="response-panel-header">
                <span class="method-tag">GET</span>
                <span id="doc-path-display" class="flex-1 truncate">/api/vulnerable/documents/1</span>
                <span id="doc-http-badge" class="http-badge"></span>
              </div>
              <pre id="doc-out">// Edit the URL above and press Enter to send the request
// Document IDs don't have to be sequential — try other numbers</pre>
            </div>
            <div id="doc-flag" class="flag-box">&#127937; </div>
          </div>
          <div class="browser-status-bar" id="doc-status-bar">Waiting for navigation...</div>
        </div>
        <p class="text-xs text-gray-400 font-mono mt-1.5 pl-1">&#8593; Document IDs aren't always 1, 2, 3...</p>
      </div>

      <!-- Challenge 3 -->
      <div>
        <div class="flex items-center gap-2 mb-2 flex-wrap">
          <span class="text-sm font-semibold text-gray-800">Challenge 3 — Patched Endpoint</span>
          <span class="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded font-semibold">FIXED</span>
        </div>
        <div class="fake-browser">
          <div class="browser-chrome">
            <div class="traffic-lights"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="nav-area">
              <button class="nav-btn">&#8592;</button>
              <button class="nav-btn">&#8594;</button>
              <button class="nav-btn clickable" id="reload-patched">&#8635;</button>
            </div>
            <div class="url-wrap" id="wrap-patched">
              <span class="url-scheme">https://</span>
              <input type="text" class="url-input" id="url-patched"
                value="corp-portal.internal/api/patched/users/1"
                spellcheck="false" autocomplete="off">
              <button class="url-go-btn" id="go-patched">&#10148;</button>
            </div>
          </div>
          <div class="page-topbar" style="background:#166534;">
            <span>corp-portal.internal / Patched API — ownership checks enabled</span>
          </div>
          <div style="background:#f0fdf4;border-bottom:1px solid #bbf7d0;padding:8px 14px;">
            <p class="text-xs font-semibold text-green-800 mb-2">&#128274; Request Headers</p>
            <div class="flex items-center gap-3 flex-wrap">
              <code class="text-xs text-green-700 font-mono">x-user-id:</code>
              <input type="text" id="patch-userid" value="1" class="header-field" style="width:60px;">
              <span class="text-xs text-green-600">← your session identity (Alice = 1)</span>
            </div>
          </div>
          <div>
            <div class="response-panel">
              <div class="response-panel-header">
                <span class="method-tag">GET</span>
                <span id="patch-path-display" class="flex-1 truncate">/api/patched/users/1</span>
                <span id="patch-http-badge" class="http-badge"></span>
              </div>
              <pre id="patch-out">// Try a user ID in the URL above and press Enter.
// Adjust x-user-id and observe what changes.
// What does the server check that the vulnerable endpoint did not?</pre>
            </div>
          </div>
          <div class="browser-status-bar" id="patch-status-bar">Waiting for navigation...</div>
        </div>
      </div>

    </div>

    <!-- Sidebar -->
    <div class="space-y-4">

      <!-- Score card -->
      <div class="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
        <div class="flex items-center justify-between mb-3">
          <span class="text-sm font-semibold text-gray-700">Score</span>
          <span class="text-xs text-gray-400">max 100 pts</span>
        </div>
        <div class="score-pill w-full justify-center mb-3">
          <span class="score-val" id="score-val">100</span>
          <div>
            <div class="score-max">/ 100 pts</div>
            <div class="score-deduction" id="score-deduction" style="display:none;"></div>
          </div>
        </div>
        <div class="mt-2 pt-2 border-t border-gray-100">
          <div class="flex justify-between text-xs mb-1">
            <span class="text-gray-500">Flags captured</span>
            <span id="flags-count" class="font-bold text-green-600">0 / 2</span>
          </div>
          <div class="w-full bg-gray-100 rounded-full h-2">
            <div id="flag-progress" class="bg-green-500 h-2 rounded-full transition-all duration-500" style="width:0%"></div>
          </div>
        </div>
        <p class="text-xs text-gray-400 mt-2 leading-relaxed">Revealing hints reduces your final score. Solve without hints for full points.</p>
      </div>

      <!-- Attempts -->
      <div class="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
        <div class="flex items-center justify-between mb-3">
          <span class="text-sm font-semibold text-gray-700">Attempts</span>
          <span id="tries-text" class="text-xs text-gray-400 font-mono">0 / 10</span>
        </div>
        <div class="flex flex-wrap gap-1 mb-2" id="pip-row"></div>
        <p class="text-xs text-gray-400 leading-relaxed">After <strong>5 attempts</strong> without a flag, a hint auto-unlocks.</p>
      </div>

      <!-- Hints -->
      <div class="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
        <div class="bg-amber-50 border-b border-amber-200 px-4 py-3 flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span>&#128161;</span>
            <span class="text-sm font-semibold text-amber-800">Hints</span>
          </div>
          <span class="text-xs bg-amber-100 text-amber-700 px-2 py-0.5 rounded font-medium" id="hints-used-label">0 of 4 revealed</span>
        </div>
        <!-- Hint 1 free -->
        <div class="border-b border-gray-100">
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" onclick="revealHint(0)">
            <span class="text-xs font-medium text-gray-700" id="hl0">&#128274; What is IDOR?</span>
            <span class="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded font-medium">free</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-0">
            <strong>Insecure Direct Object Reference</strong> — the server uses a user-supplied value (like an ID in the URL) to look up an object, but never checks if <em>you're allowed to access it</em>. Change the ID, get someone else's data.
          </div>
        </div>
        <!-- Hint 2 -5pts -->
        <div class="border-b border-gray-100">
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" onclick="revealHint(1)">
            <span class="text-xs font-medium text-gray-700" id="hl1">&#128274; Where to look</span>
            <span class="text-xs bg-amber-100 text-amber-700 px-2 py-0.5 rounded font-medium">&#8722;5 pts</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-1">
            The number at the end of the URL is the <strong>object ID</strong>. Regular users have IDs 1, 2, 3. Could there be a privileged account with a much higher ID? Try enumerating.
          </div>
        </div>
        <!-- Hint 3 -20pts -->
        <div class="border-b border-gray-100">
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" onclick="revealHint(2)">
            <span class="text-xs font-medium text-gray-700" id="hl2">&#128274; Flag 1 — ID range</span>
            <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-medium">&#8722;20 pts</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-2">
            The admin account has a <strong>non-sequential ID</strong> between <strong>90 and 100</strong>. Try those values in the User Profile URL.
          </div>
        </div>
        <!-- Hint 4 -25pts -->
        <div>
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" onclick="revealHint(3)">
            <span class="text-xs font-medium text-gray-700" id="hl3">&#128274; Flag 2 — Document ID</span>
            <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-medium">&#8722;25 pts</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-3">
            The second flag is in the <strong>Document endpoint</strong>. There's a document with a specific ID that belongs to the admin. Think: what ID would an admin document have?
          </div>
        </div>
      </div>

      <!-- Observe -->
      <div class="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
        <p class="text-xs font-semibold text-gray-700 mb-2">&#128270; Things to observe</p>
        <ul class="text-xs text-gray-500 space-y-1.5 leading-relaxed">
          <li>&#10140; Does the server check <em>who</em> is making the request?</li>
          <li>&#10140; What HTTP status for a valid vs unknown ID?</li>
          <li>&#10140; Try the same URL on Challenge 3 — what's different?</li>
          <li>&#10140; What header does the patched endpoint use?</li>
        </ul>
      </div>

    </div>
  </div>
</div>

<script>
const MAX_TRIES        = 10;
const AUTO_HINT_THRESHOLD = 5;
const MAX_SCORE        = 100;
const LAB_SLUG         = 'idor-basics';
const HINT_DEDUCTIONS  = [0, 5, 20, 25];

let tries         = 0;
let flagsCaptured = 0;
let flagIds       = { user: false, doc: false };
let hintsRevealed = [false, false, false, false];
let totalDeducted = 0;
let labComplete   = false;

function currentScore() { return Math.max(0, MAX_SCORE - totalDeducted); }

function updateScoreUI() {
  document.getElementById('score-val').textContent = currentScore();
  var dedEl = document.getElementById('score-deduction');
  if (totalDeducted > 0) {
    dedEl.style.display = 'block';
    dedEl.textContent   = '\u2212' + totalDeducted + ' pts from hints';
  } else {
    dedEl.style.display = 'none';
  }
}

function renderPips() {
  var row = document.getElementById('pip-row');
  row.innerHTML = '';
  for (var i = 0; i < MAX_TRIES; i++) {
    var d = document.createElement('div');
    var used = i < tries;
    var warn = used && (tries - i <= 2);
    d.className = 'pip' + (used ? (warn ? ' warn' : ' used') : '');
    row.appendChild(d);
  }
  document.getElementById('tries-text').textContent = tries + ' / ' + MAX_TRIES;
}

function recordTry() {
  tries = Math.min(MAX_TRIES, tries + 1);
  renderPips();
  if (tries >= AUTO_HINT_THRESHOLD && !hintsRevealed[1]) revealHint(1, true);
}

renderPips();

function updateFlagProgress() {
  document.getElementById('flags-count').textContent = flagsCaptured + ' / 2';
  document.getElementById('flag-progress').style.width = (flagsCaptured * 50) + '%';
}

function parseFakeUrl(raw) {
  var s = raw.trim().replace(/^https?:\/\//i, '');
  var slash = s.indexOf('/');
  return slash === -1 ? null : s.slice(slash);
}

function hl(json) {
  return json.replace(/("[^"]*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?)/g, function(m) {
    if (/^"/.test(m)) {
      if (/:$/.test(m)) return '<span style="color:#7dd3fc">' + m + '</span>';
      return '<span style="color:#86efac">' + m + '</span>';
    }
    if (/true|false/.test(m)) return '<span style="color:#fdba74">' + m + '</span>';
    if (/null/.test(m))       return '<span style="color:#f87171">' + m + '</span>';
    return '<span style="color:#c4b5fd">' + m + '</span>';
  });
}

function submitScore() {
  var token = new URLSearchParams(window.location.search).get('token');
  if (!token) return;
  var pts = currentScore();
  fetch('${backendUrl}/api/labs/' + LAB_SLUG + '/complete', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body:    JSON.stringify({ points_earned: pts, hints_used: totalDeducted })
  }).catch(function() {});
}

function showCompletionBanner() {
  var pts = currentScore();
  var banner = document.getElementById('completion-banner');
  banner.style.display = 'block';
  document.getElementById('banner-score').textContent = pts;
  var dedEl = document.getElementById('banner-deductions');
  if (totalDeducted > 0) {
    dedEl.textContent = '\u2212' + totalDeducted + ' pts deducted from hints';
    dedEl.style.display = 'block';
  }
  banner.scrollIntoView({ behavior: 'smooth', block: 'start' });
  submitScore();
}

async function doFetch(apiPath, ids, headers) {
  headers = headers || {};
  var out         = document.getElementById(ids.outId);
  var flagEl      = document.getElementById(ids.flagId);
  var pathDisp    = document.getElementById(ids.pathDisplayId);
  var httpBadge   = document.getElementById(ids.httpBadgeId);
  var statusBar   = document.getElementById(ids.statusBarId);
  var statusBadge = document.getElementById(ids.statusBadgeId);

  pathDisp.textContent    = apiPath;
  statusBar.textContent   = 'Connecting\u2026';
  statusBadge.textContent = 'Loading\u2026';
  out.innerHTML           = '// Sending request\u2026';
  httpBadge.className     = 'http-badge';
  httpBadge.textContent   = '';
  flagEl.style.display    = 'none';

  recordTry();

  try {
    var r    = await fetch(apiPath, { headers: headers });
    var data = await r.json();
    var body = JSON.stringify(data, null, 2);

    out.innerHTML           = hl(body);
    httpBadge.textContent   = r.status;
    httpBadge.className     = 'http-badge http-' + r.status;
    statusBar.textContent   = apiPath + '  \u2014  HTTP ' + r.status + (r.ok ? ' OK' : ' Error');
    statusBadge.textContent = r.status + (r.ok ? ' OK' : ' Error');

    var match = body.match(/FLAG\{[^}]+\}/);
    if (match) {
      flagEl.textContent   = '\uD83C\uDFC1 Flag captured: ' + match[0];
      flagEl.style.display = 'block';
      if (!flagIds[ids.flagKey]) {
        flagIds[ids.flagKey] = true;
        flagsCaptured++;
        updateFlagProgress();
        if (flagsCaptured === 2 && !labComplete) {
          labComplete = true;
          showCompletionBanner();
        }
      }
    }
  } catch (e) {
    out.innerHTML         = '// Network error: ' + e.message;
    statusBar.textContent = 'Request failed — check the URL format';
    statusBadge.textContent = 'Error';
  }
}

function fetchFromUrl(which) {
  var path;
  if (which === 'user') {
    path = parseFakeUrl(document.getElementById('url-user').value);
    if (!path || !path.startsWith('/api/')) { document.getElementById('user-out').textContent = '// Invalid URL — expected: corp-portal.internal/api/vulnerable/users/<id>'; return; }
    doFetch(path, { outId:'user-out', flagId:'user-flag', pathDisplayId:'user-path-display', httpBadgeId:'user-http-badge', statusBarId:'user-status-bar', statusBadgeId:'user-status-badge', flagKey:'user' });
  } else {
    path = parseFakeUrl(document.getElementById('url-doc').value);
    if (!path || !path.startsWith('/api/')) { document.getElementById('doc-out').textContent = '// Invalid URL — expected: corp-portal.internal/api/vulnerable/documents/<id>'; return; }
    doFetch(path, { outId:'doc-out', flagId:'doc-flag', pathDisplayId:'doc-path-display', httpBadgeId:'doc-http-badge', statusBarId:'doc-status-bar', statusBadgeId:'doc-status-badge', flagKey:'doc' });
  }
}

async function fetchPatched() {
  var path  = parseFakeUrl(document.getElementById('url-patched').value);
  var myId  = document.getElementById('patch-userid').value;
  var out   = document.getElementById('patch-out');
  var badge = document.getElementById('patch-http-badge');
  var pathD = document.getElementById('patch-path-display');
  var sb    = document.getElementById('patch-status-bar');
  if (!path || !path.startsWith('/api/')) { out.textContent = '// Invalid URL format'; return; }
  pathD.textContent = path;
  out.innerHTML     = '// Sending with x-user-id: ' + myId + '\u2026';
  badge.className   = 'http-badge';
  badge.textContent = '';
  recordTry();
  try {
    var r    = await fetch(path, { headers: { 'x-user-id': myId } });
    var data = await r.json();
    var body = JSON.stringify(data, null, 2);
    out.innerHTML     = hl(body);
    badge.textContent = r.status;
    badge.className   = 'http-badge http-' + r.status;
    sb.textContent    = path + '  \u2014  HTTP ' + r.status + '  (x-user-id: ' + myId + ')';
  } catch (e) {
    out.innerHTML  = '// Error: ' + e.message;
    sb.textContent = 'Request failed';
  }
}

function revealHint(idx, auto) {
  var body = document.getElementById('hint-body-' + idx);
  if (hintsRevealed[idx]) { body.classList.toggle('open'); return; }
  var cost = HINT_DEDUCTIONS[idx];
  if (!auto && cost > 0) {
    if (!confirm('This hint costs ' + cost + ' points.\nYour current score: ' + currentScore() + ' pts.\n\nReveal anyway?')) return;
  }
  hintsRevealed[idx] = true;
  totalDeducted = Math.min(MAX_SCORE, totalDeducted + cost);
  body.classList.add('open');
  updateScoreUI();
  var lbl = document.getElementById('hl' + idx);
  if (lbl) lbl.innerHTML = lbl.innerHTML.replace('&#128274;', '&#128275;');
  document.getElementById('hints-used-label').textContent = hintsRevealed.filter(Boolean).length + ' of 4 revealed';
}

// ── Wire up all events via addEventListener (no inline handlers) ──
document.getElementById('url-user').addEventListener('keydown', function(e){ if(e.key === 'Enter') fetchFromUrl('user'); });
document.getElementById('go-user').addEventListener('click', function(){ fetchFromUrl('user'); });
document.getElementById('reload-user').addEventListener('click', function(){ fetchFromUrl('user'); });
document.getElementById('wrap-user').addEventListener('click', function(){ document.getElementById('url-user').focus(); });

document.getElementById('url-doc').addEventListener('keydown', function(e){ if(e.key === 'Enter') fetchFromUrl('doc'); });
document.getElementById('go-doc').addEventListener('click', function(){ fetchFromUrl('doc'); });
document.getElementById('reload-doc').addEventListener('click', function(){ fetchFromUrl('doc'); });
document.getElementById('wrap-doc').addEventListener('click', function(){ document.getElementById('url-doc').focus(); });

document.getElementById('url-patched').addEventListener('keydown', function(e){ if(e.key === 'Enter') fetchPatched(); });
document.getElementById('go-patched').addEventListener('click', function(){ fetchPatched(); });
document.getElementById('reload-patched').addEventListener('click', function(){ fetchPatched(); });
document.getElementById('wrap-patched').addEventListener('click', function(){ document.getElementById('url-patched').focus(); });
<\/script>

<script>
(function(){
  var token    = new URLSearchParams(window.location.search).get('token');
  var BACKEND  = '${backendUrl}';
  var FRONTEND = '${frontendUrl}';
  function recheck(){
    if(!token){ window.location.href = FRONTEND+'/login.html'; return; }
    fetch(BACKEND+'/api/auth/me',{ headers:{ 'Authorization':'Bearer '+token } })
      .then(function(r){ if(!r.ok) window.location.href = FRONTEND+'/login.html'; })
      .catch(function(){});
  }
  setTimeout(function loop(){ recheck(); setTimeout(loop, 5000); }, 5000);
})();
<\/script>
</body>
</html>`);
});

app.listen(PORT, () => console.log('\uD83D\uDD13 IDOR Lab running on http://localhost:' + PORT));