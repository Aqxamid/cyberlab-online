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
    </script></head><body></body></html>`);
  }

  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    return res.redirect(`${FRONTEND_URL}/login.html`);
  }

  try {
    const r = await nodeFetch(`${BACKEND_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!r.ok) return res.redirect(`${FRONTEND_URL}/login.html`);
  } catch (err) {
    console.warn('[idor-lab] Backend unreachable for auth check:', err.message);
  }

  next();
}

app.use(requireLabAuth);
// ─────────────────────────────────────────────────────────────

// ── Rate limit lab API endpoints ─────────────────────────────
const labLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests to the lab. Slow down and read the theory!' },
});
app.use('/api', labLimiter);

// ── Lab data (fictional — no real credentials) ────────────────
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

// ── VULNERABLE endpoints ──────────────────────────────────────
app.get('/api/vulnerable/users/:id',     (req, res) => { const u = users[+req.params.id];     u ? res.json(u) : res.status(404).json({ error: 'Not found' }); });
app.get('/api/vulnerable/documents/:id', (req, res) => { const d = documents[+req.params.id]; d ? res.json(d) : res.status(404).json({ error: 'Not found' }); });

// ── PATCHED endpoints ─────────────────────────────────────────
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

// ── UI ────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  const token       = req.query.token || '';
  const backendUrl  = BACKEND_URL;
  const frontendUrl = FRONTEND_URL;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CorpPortal — IDOR Lab</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath fill='%231d4ed8' d='M16 2L4 7v9c0 7.18 5.16 13.9 12 15.93C23.84 29.9 29 23.18 29 16V7L16 2z'/%3E%3Cpath fill='white' d='M13 20.5l-4-4 1.41-1.41L13 17.67l8.59-8.58L23 10.5z'/%3E%3C/svg%3E">
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
body { font-family: 'Inter', sans-serif; background: #f1f5f9; }
pre  { background: #0f172a; color: #94a3b8; padding: 1rem; border-radius: 8px; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; min-height: 60px; line-height: 1.6; }
.flag-box { background: #fef9c3; border: 2px solid #eab308; color: #713f12; padding: 0.75rem 1rem; border-radius: 8px; font-family: monospace; font-weight: 700; font-size: 0.85rem; display: none; margin: 0 1rem 1rem; word-break: break-all; }

/* ── Fake Browser Shell ── */
.fake-browser { border: 1px solid #cbd5e1; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.08); background: white; }
.browser-chrome { background: #e2e8f0; padding: 8px 12px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #cbd5e1; }
.traffic-lights { display: flex; gap: 5px; flex-shrink: 0; }
.tl { width: 11px; height: 11px; border-radius: 50%; }
.tl-r { background: #ef4444; } .tl-y { background: #f59e0b; } .tl-g { background: #22c55e; }
.nav-area { display: flex; gap: 3px; flex-shrink: 0; }
.nav-btn { background: none; border: none; cursor: default; color: #94a3b8; font-size: 15px; padding: 1px 5px; border-radius: 4px; line-height: 1; }
.nav-btn.clickable { cursor: pointer; }
.nav-btn.clickable:hover { background: #cbd5e1; color: #475569; }
.url-wrap { flex: 1; display: flex; align-items: center; background: white; border: 1px solid #94a3b8; border-radius: 5px; padding: 0 8px; height: 28px; gap: 5px; transition: border-color 0.15s, box-shadow 0.15s; cursor: text; }
.url-wrap:focus-within { border-color: #3b82f6; box-shadow: 0 0 0 2px rgba(59,130,246,0.2); }
.url-scheme { font-size: 12px; color: #16a34a; font-family: 'Courier New', monospace; flex-shrink: 0; user-select: none; font-weight: 600; }
.url-input { flex: 1; border: none; outline: none; font-size: 12.5px; font-family: 'Courier New', monospace; color: #1e293b; background: transparent; padding: 0; min-width: 0; caret-color: #3b82f6; }
.url-go-btn { background: none; border: none; cursor: pointer; color: #64748b; font-size: 14px; padding: 0 2px; line-height: 1; flex-shrink: 0; transition: color 0.1s; }
.url-go-btn:hover { color: #1d4ed8; }
.browser-status-bar { background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 3px 12px; font-size: 10.5px; color: #94a3b8; font-family: monospace; min-height: 20px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* ── Inner page chrome ── */
.page-topbar { background: #1d4ed8; color: white; padding: 8px 16px; display: flex; justify-content: space-between; align-items: center; font-size: 11px; }
.response-panel { margin: 12px; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
.response-panel-header { background: #f8fafc; border-bottom: 1px solid #e2e8f0; padding: 6px 12px; display: flex; align-items: center; gap: 8px; font-size: 11px; font-family: monospace; color: #475569; flex-wrap: wrap; }
.http-badge { padding: 1px 7px; border-radius: 3px; font-weight: 700; font-size: 11px; }
.http-200 { background: #dcfce7; color: #166534; }
.http-403 { background: #fee2e2; color: #991b1b; }
.http-404 { background: #fef9c3; color: #713f12; }
.method-tag { background: #dbeafe; color: #1d4ed8; padding: 1px 6px; border-radius: 3px; font-weight: 700; font-size: 11px; flex-shrink: 0; }

/* ── Hint system ── */
.hint-body { display: none; }
.hint-body.open { display: block; }
.hint-trigger { transition: background 0.15s; }
.hint-trigger:hover { background: #fffbeb; }

/* ── Try pips ── */
.pip { width: 10px; height: 10px; border-radius: 50%; background: #e2e8f0; transition: background 0.2s; display: inline-block; }
.pip.used { background: #ef4444; }
.pip.warn { background: #f59e0b; }

/* ── Patched header inputs ── */
.header-field { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 4px; padding: 3px 8px; font-family: monospace; font-size: 12px; color: #166534; }
.header-field:focus { outline: none; border-color: #4ade80; }
</style>
</head>
<body class="min-h-screen">

<!-- ── Top nav ── -->
<nav class="bg-blue-700 text-white px-6 py-3 flex items-center justify-between shadow-lg">
  <div class="flex items-center gap-3">
    <div class="w-8 h-8 bg-white rounded flex items-center justify-center">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#1d4ed8" class="w-5 h-5">
        <path fill-rule="evenodd" d="M12 1.5a5.25 5.25 0 00-5.25 5.25v3a3 3 0 00-3 3v6.75a3 3 0 003 3h10.5a3 3 0 003-3v-6.75a3 3 0 00-3-3v-3c0-2.9-2.35-5.25-5.25-5.25zm3.75 8.25v-3a3.75 3.75 0 10-7.5 0v3h7.5z" clip-rule="evenodd"/>
      </svg>
    </div>
    <span class="font-bold text-lg">CorpPortal</span>
    <span class="text-blue-300 text-sm">Employee Directory</span>
    <span class="text-xs bg-red-500 text-white px-2 py-0.5 rounded font-semibold">IDOR Lab</span>
  </div>
  <div class="text-sm text-blue-200">Logged in as: <strong class="text-white">alice (ID: 1)</strong></div>
</nav>

<div class="max-w-6xl mx-auto px-4 py-6 space-y-5">

  <!-- Objective -->
  <div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">
    <span class="text-2xl flex-shrink-0 mt-0.5">🎯</span>
    <div>
      <p class="font-semibold text-amber-800 text-sm">IDOR Lab — Type the URL yourself</p>
      <p class="text-amber-700 text-xs mt-1">
        You are <strong>Alice (ID: 1)</strong>. Each fake browser below has an editable URL bar — just like a real browser.
        <strong>Edit the URL and press Enter</strong> to send the request. Your goal: find the 2 hidden flags by changing object IDs in the URL path.
        Use the hint panel if you get stuck — hints cost attempts.
      </p>
    </div>
  </div>

  <div class="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">

    <!-- ══ LEFT: Browsers ══ -->
    <div class="xl:col-span-2 space-y-5">

      <!-- Challenge 1: Vulnerable Users -->
      <div>
        <div class="flex items-center gap-2 mb-2">
          <span class="text-sm font-semibold text-gray-800">Challenge 1 — User Profile Endpoint</span>
          <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-semibold">VULNERABLE</span>
        </div>
        <div class="fake-browser">
          <div class="browser-chrome">
            <div class="traffic-lights"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="nav-area">
              <button class="nav-btn" title="Back">&#8592;</button>
              <button class="nav-btn" title="Forward">&#8594;</button>
              <button class="nav-btn clickable" title="Reload" onclick="fetchFromUrl('user')">&#8635;</button>
            </div>
            <div class="url-wrap" onclick="document.getElementById('url-user').focus()">
              <span class="url-scheme">https://</span>
              <input type="text" class="url-input" id="url-user"
                value="corp-portal.internal/api/vulnerable/users/1"
                spellcheck="false" autocomplete="off"
                onkeydown="if(event.key==='Enter'){fetchFromUrl('user')}"
              >
              <button class="url-go-btn" onclick="fetchFromUrl('user')" title="Navigate">&#10148;</button>
            </div>
          </div>
          <div class="page-topbar">
            <span>corp-portal.internal &nbsp;/&nbsp; Employee Directory API</span>
            <span id="user-status-badge" class="opacity-60">ready</span>
          </div>
          <div>
            <div class="response-panel">
              <div class="response-panel-header">
                <span class="method-tag">GET</span>
                <span id="user-path-display" class="flex-1 truncate">/api/vulnerable/users/1</span>
                <span id="user-http-badge" class="http-badge"></span>
              </div>
              <pre id="user-out">// Edit the URL above and press Enter (or click &#10148;) to send the request
// Try changing the number at the end — you are user ID 1</pre>
            </div>
            <div id="user-flag" class="flag-box">&#127937; </div>
          </div>
          <div class="browser-status-bar" id="user-status-bar">Waiting for navigation...</div>
        </div>
        <p class="text-xs text-gray-400 font-mono mt-1.5 pl-1">↑ Change the number at the end of the URL path to explore other users</p>
      </div>

      <!-- Challenge 2: Vulnerable Documents -->
      <div>
        <div class="flex items-center gap-2 mb-2">
          <span class="text-sm font-semibold text-gray-800">Challenge 2 — Document Store Endpoint</span>
          <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-semibold">VULNERABLE</span>
        </div>
        <div class="fake-browser">
          <div class="browser-chrome">
            <div class="traffic-lights"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="nav-area">
              <button class="nav-btn">&#8592;</button>
              <button class="nav-btn">&#8594;</button>
              <button class="nav-btn clickable" title="Reload" onclick="fetchFromUrl('doc')">&#8635;</button>
            </div>
            <div class="url-wrap" onclick="document.getElementById('url-doc').focus()">
              <span class="url-scheme">https://</span>
              <input type="text" class="url-input" id="url-doc"
                value="corp-portal.internal/api/vulnerable/documents/1"
                spellcheck="false" autocomplete="off"
                onkeydown="if(event.key==='Enter'){fetchFromUrl('doc')}"
              >
              <button class="url-go-btn" onclick="fetchFromUrl('doc')" title="Navigate">&#10148;</button>
            </div>
          </div>
          <div class="page-topbar">
            <span>corp-portal.internal &nbsp;/&nbsp; Document Store API</span>
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
        <p class="text-xs text-gray-400 font-mono mt-1.5 pl-1">↑ Document IDs aren't always 1, 2, 3... what other IDs might exist?</p>
      </div>

      <!-- Challenge 3: Patched -->
      <div>
        <div class="flex items-center gap-2 mb-2">
          <span class="text-sm font-semibold text-gray-800">Challenge 3 — Compare: Patched Endpoint</span>
          <span class="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded font-semibold">FIXED</span>
        </div>
        <div class="fake-browser">
          <div class="browser-chrome">
            <div class="traffic-lights"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="nav-area">
              <button class="nav-btn">&#8592;</button>
              <button class="nav-btn">&#8594;</button>
              <button class="nav-btn clickable" onclick="fetchPatched()">&#8635;</button>
            </div>
            <div class="url-wrap" onclick="document.getElementById('url-patched').focus()">
              <span class="url-scheme">https://</span>
              <input type="text" class="url-input" id="url-patched"
                value="corp-portal.internal/api/patched/users/1"
                spellcheck="false" autocomplete="off"
                onkeydown="if(event.key==='Enter'){fetchPatched()}"
              >
              <button class="url-go-btn" onclick="fetchPatched()">&#10148;</button>
            </div>
          </div>
          <div class="page-topbar" style="background:#166534;">
            <span>corp-portal.internal &nbsp;/&nbsp; Patched API — ownership checks enabled</span>
          </div>
          <!-- Editable request headers panel -->
          <div style="background:#f0fdf4;border-bottom:1px solid #bbf7d0;padding:8px 14px;">
            <p class="text-xs font-semibold text-green-800 mb-2">&#128274; Request Headers (sent with every request)</p>
            <div class="flex items-center gap-3 flex-wrap">
              <code class="text-xs text-green-700 font-mono">x-user-id:</code>
              <input type="text" id="patch-userid" value="1" class="header-field" style="width:60px;" placeholder="1">
              <span class="text-xs text-green-600">← your session identity (you are Alice = 1)</span>
            </div>
          </div>
          <div>
            <div class="response-panel">
              <div class="response-panel-header">
                <span class="method-tag">GET</span>
                <span id="patch-path-display" class="flex-1 truncate">/api/patched/users/99</span>
                <span id="patch-http-badge" class="http-badge"></span>
              </div>
              <pre id="patch-out">// Try the SAME URL as Challenge 1 but via this patched endpoint.
// Change x-user-id above and observe the difference.
// What happens when your ID doesn't match the requested ID?</pre>
            </div>
          </div>
          <div class="browser-status-bar" id="patch-status-bar">Waiting for navigation...</div>
        </div>
      </div>

    </div>

    <!-- ══ RIGHT: Sidebar ══ -->
    <div class="space-y-4">

      <!-- Attempt counter -->
      <div class="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
        <div class="flex items-center justify-between mb-3">
          <span class="text-sm font-semibold text-gray-700">Attempts</span>
          <span id="tries-text" class="text-xs text-gray-400 font-mono">0 / 10</span>
        </div>
        <div class="flex flex-wrap gap-1 mb-3" id="pip-row"></div>
        <p class="text-xs text-gray-400 leading-relaxed">Every URL you submit uses an attempt. After <strong>5 failed attempts</strong> a hint auto-unlocks. Opening a paid hint costs extra attempts.</p>
        <div class="mt-3 pt-3 border-t border-gray-100">
          <div class="flex justify-between text-xs mb-1">
            <span class="text-gray-500">Flags captured</span>
            <span id="flags-count" class="font-bold text-green-600">0 / 2</span>
          </div>
          <div class="w-full bg-gray-100 rounded-full h-2">
            <div id="flag-progress" class="bg-green-500 h-2 rounded-full transition-all duration-500" style="width:0%"></div>
          </div>
        </div>
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

        <!-- Hint 1 (free) -->
        <div class="border-b border-gray-100">
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" onclick="revealHint(0)">
            <span class="text-xs font-medium text-gray-700" id="hl0">&#128274; What is IDOR?</span>
            <span class="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded font-medium">free</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-0">
            <strong>Insecure Direct Object Reference</strong> — the server uses a user-supplied value (like an ID in the URL) to look up an object, but never checks if <em>you're allowed to access it</em>. Change the ID, get someone else's data.
          </div>
        </div>

        <!-- Hint 2 (-1 attempt) -->
        <div class="border-b border-gray-100">
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" onclick="revealHint(1)">
            <span class="text-xs font-medium text-gray-700" id="hl1">&#128274; Where to look</span>
            <span class="text-xs bg-amber-100 text-amber-700 px-2 py-0.5 rounded font-medium">−1 attempt</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-1">
            The number at the end of the URL is the <strong>object ID</strong>. Regular users have IDs 1, 2, 3. But could there be a privileged account with a much higher ID? Try enumerating.
          </div>
        </div>

        <!-- Hint 3 (-2 attempts) -->
        <div class="border-b border-gray-100">
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" onclick="revealHint(2)">
            <span class="text-xs font-medium text-gray-700" id="hl2">&#128274; Flag 1 — ID range</span>
            <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-medium">−2 attempts</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-2">
            The admin account has a <strong>non-sequential ID</strong>. It's a two-digit number between <strong>90 and 100</strong>. Try those values in the User Profile URL.
          </div>
        </div>

        <!-- Hint 4 (-2 attempts) -->
        <div>
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" onclick="revealHint(3)">
            <span class="text-xs font-medium text-gray-700" id="hl3">&#128274; Flag 2 — Document ID</span>
            <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-medium">−2 attempts</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-3">
            The second flag is in the <strong>Document endpoint</strong>. Document IDs 1–3 are normal user files. There's a document with a specific ID that belongs to the admin. Think: what ID would an admin document have?
          </div>
        </div>
      </div>

      <!-- Observe panel -->
      <div class="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">
        <p class="text-xs font-semibold text-gray-700 mb-2">&#128270; Things to observe</p>
        <ul class="text-xs text-gray-500 space-y-1.5 leading-relaxed">
          <li>&#10140; Does the server check <em>who</em> is making the request?</li>
          <li>&#10140; What HTTP status code appears for a valid vs unknown ID?</li>
          <li>&#10140; Try the same URL on Challenge 3 — what's different?</li>
          <li>&#10140; What header does the patched endpoint use to verify identity?</li>
        </ul>
      </div>

    </div>
  </div>
</div>

<script>
// ── State ──────────────────────────────────────────────────────────────────
const MAX_TRIES = 10;
const AUTO_HINT_THRESHOLD = 5;
let tries = 0;
let flagsCaptured = 0;
let flagIds = { user: false, doc: false };
const hintsRevealed = [false, false, false, false];
const hintCosts     = [0, 1, 2, 2];

// ── Pips ────────────────────────────────────────────────────────────────────
function renderPips() {
  const row = document.getElementById('pip-row');
  row.innerHTML = '';
  for (let i = 0; i < MAX_TRIES; i++) {
    const d = document.createElement('div');
    const isUsed = i < tries;
    const isWarn = isUsed && (tries - i <= 2);
    d.className = 'pip' + (isUsed ? (isWarn ? ' warn' : ' used') : '');
    row.appendChild(d);
  }
  document.getElementById('tries-text').textContent = tries + ' / ' + MAX_TRIES;
}

function recordTry(cost = 1) {
  tries = Math.min(MAX_TRIES, tries + cost);
  renderPips();
  if (tries >= AUTO_HINT_THRESHOLD && !hintsRevealed[1]) revealHint(1, true);
}

renderPips();

// ── Flag progress ────────────────────────────────────────────────────────────
function updateFlagProgress() {
  document.getElementById('flags-count').textContent = flagsCaptured + ' / 2';
  document.getElementById('flag-progress').style.width = (flagsCaptured * 50) + '%';
}

// ── URL parser: strip scheme + fake hostname, return /api/... path ───────────
function parseFakeUrl(raw) {
  let s = raw.trim().replace(/^https?:\\/\\//i, '');
  const slash = s.indexOf('/');
  return slash === -1 ? null : s.slice(slash);
}

// ── JSON syntax highlight ────────────────────────────────────────────────────
function hl(json) {
  return json.replace(/("(\\\\u[a-zA-Z0-9]{4}|\\\\[^u]|[^\\\\"])*"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?)/g, m => {
    if (/^"/.test(m)) {
      if (/:$/.test(m)) return '<span style="color:#7dd3fc">' + m + '</span>';
      return '<span style="color:#86efac">' + m + '</span>';
    }
    if (/true|false/.test(m)) return '<span style="color:#fdba74">' + m + '</span>';
    if (/null/.test(m))        return '<span style="color:#f87171">' + m + '</span>';
    return '<span style="color:#c4b5fd">' + m + '</span>';
  });
}

// ── Core fetch ────────────────────────────────────────────────────────────────
async function doFetch(apiPath, ids, headers = {}) {
  const { outId, flagId, pathDisplayId, httpBadgeId, statusBarId, statusBadgeId, flagKey } = ids;

  const out        = document.getElementById(outId);
  const flagEl     = document.getElementById(flagId);
  const pathDisp   = document.getElementById(pathDisplayId);
  const httpBadge  = document.getElementById(httpBadgeId);
  const statusBar  = document.getElementById(statusBarId);
  const statusBadge= document.getElementById(statusBadgeId);

  pathDisp.textContent    = apiPath;
  statusBar.textContent   = 'Connecting\\u2026';
  statusBadge.textContent = 'Loading\\u2026';
  out.innerHTML           = '// Sending request\\u2026';
  httpBadge.className     = 'http-badge';
  httpBadge.textContent   = '';
  flagEl.style.display    = 'none';

  recordTry();

  try {
    const r    = await fetch(apiPath, { headers });
    const data = await r.json();
    const body = JSON.stringify(data, null, 2);

    out.innerHTML           = hl(body);
    httpBadge.textContent   = r.status;
    httpBadge.className     = 'http-badge http-' + r.status;
    statusBar.textContent   = apiPath + '  \\u2014  HTTP ' + r.status + (r.ok ? ' OK' : ' Error');
    statusBadge.textContent = r.status + (r.ok ? ' OK' : ' Error');

    const match = body.match(/FLAG\\{[^}]+\\}/);
    if (match) {
      flagEl.textContent   = '\\uD83C\\uDFC1 Flag captured: ' + match[0];
      flagEl.style.display = 'block';
      if (!flagIds[flagKey]) {
        flagIds[flagKey] = true;
        flagsCaptured++;
        updateFlagProgress();
      }
    }
  } catch (e) {
    out.innerHTML           = '// Network error: ' + e.message;
    statusBar.textContent   = 'Request failed — check the URL format';
    statusBadge.textContent = 'Error';
  }
}

// ── Challenge 1 ─────────────────────────────────────────────────────────────
function fetchFromUrl(which) {
  if (which === 'user') {
    const path = parseFakeUrl(document.getElementById('url-user').value);
    if (!path || !path.startsWith('/api/')) {
      document.getElementById('user-out').textContent = '// Invalid URL\\n// Expected: corp-portal.internal/api/vulnerable/users/<id>';
      return;
    }
    doFetch(path, { outId:'user-out', flagId:'user-flag', pathDisplayId:'user-path-display', httpBadgeId:'user-http-badge', statusBarId:'user-status-bar', statusBadgeId:'user-status-badge', flagKey:'user' });
  } else {
    const path = parseFakeUrl(document.getElementById('url-doc').value);
    if (!path || !path.startsWith('/api/')) {
      document.getElementById('doc-out').textContent = '// Invalid URL\\n// Expected: corp-portal.internal/api/vulnerable/documents/<id>';
      return;
    }
    doFetch(path, { outId:'doc-out', flagId:'doc-flag', pathDisplayId:'doc-path-display', httpBadgeId:'doc-http-badge', statusBarId:'doc-status-bar', statusBadgeId:'doc-status-badge', flagKey:'doc' });
  }
}

// ── Challenge 3 ─────────────────────────────────────────────────────────────
async function fetchPatched() {
  const path  = parseFakeUrl(document.getElementById('url-patched').value);
  const myId  = document.getElementById('patch-userid').value;
  const out   = document.getElementById('patch-out');
  const badge = document.getElementById('patch-http-badge');
  const pathD = document.getElementById('patch-path-display');
  const sb    = document.getElementById('patch-status-bar');

  if (!path || !path.startsWith('/api/')) {
    out.textContent = '// Invalid URL format';
    return;
  }

  pathD.textContent = path;
  out.innerHTML     = '// Sending with x-user-id: ' + myId + '\\u2026';
  badge.className   = 'http-badge';
  badge.textContent = '';

  recordTry();

  try {
    const r    = await fetch(path, { headers: { 'x-user-id': myId } });
    const data = await r.json();
    const body = JSON.stringify(data, null, 2);
    out.innerHTML   = hl(body);
    badge.textContent = r.status;
    badge.className   = 'http-badge http-' + r.status;
    sb.textContent    = path + '  \\u2014  HTTP ' + r.status + '  (x-user-id: ' + myId + ')';
  } catch (e) {
    out.innerHTML = '// Error: ' + e.message;
    sb.textContent = 'Request failed';
  }
}

// ── Hint system ────────────────────────────────────────────────────────────
function revealHint(idx, auto = false) {
  const body = document.getElementById('hint-body-' + idx);

  if (hintsRevealed[idx]) {
    body.classList.toggle('open');
    return;
  }

  const cost = hintCosts[idx];
  if (!auto && cost > 0) {
    const remaining = MAX_TRIES - tries;
    const msg = 'This hint costs ' + cost + ' attempt(s).\\nYou have ' + remaining + ' remaining.\\n\\nReveal anyway?';
    if (!confirm(msg)) return;
    recordTry(cost);
  }

  hintsRevealed[idx] = true;
  body.classList.add('open');

  // update lock icon to unlocked
  const lbl = document.getElementById('hl' + idx);
  if (lbl) lbl.textContent = lbl.textContent.replace('\\uD83D\\uDD12', '\\uD83D\\uDD13');

  const used = hintsRevealed.filter(Boolean).length;
  document.getElementById('hints-used-label').textContent = used + ' of 4 revealed';
}
</script>

<!-- ── Periodic auth re-check ── -->
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
</script>
</body>
</html>`);
});

app.listen(PORT, () => console.log(`\uD83D\uDD13 IDOR Lab running on http://localhost:${PORT}`));