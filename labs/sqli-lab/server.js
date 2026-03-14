const express = require('express');
const cors    = require('cors');
const jwt     = require('jsonwebtoken');
const https   = require('https');
const http    = require('http');

const app  = express();
const PORT = process.env.PORT || 5002;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── CyberLab Auth Guard ──────────────────────────────────────
const JWT_SECRET   = process.env.JWT_SECRET   || 'cyberlab_secret_change_in_production';
const BACKEND_URL  = process.env.BACKEND_URL  || 'http://localhost:4000';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

function nodeFetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib    = parsed.protocol === 'https:' ? https : http;
    const req    = lib.request({
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
    console.warn('[sqli-lab] Backend unreachable for auth check:', err.message);
  }

  next();
}

app.use(requireLabAuth);
// ─────────────────────────────────────────────────────────────

const fakeDb = [
  { id:1, username:'alice', password:'alice123',   role:'user',  secret:null },
  { id:2, username:'bob',   password:'bob456',     role:'user',  secret:null },
  { id:3, username:'admin', password:'sup3rs3cr3t', role:'admin', secret:'FLAG{sql_injected_success}' },
];

app.post('/api/vulnerable/login', (req, res) => {
  const { username, password } = req.body;
  const simulatedQuery = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  const isBypass   = /'\s*OR\s*['"]?1['"]?\s*=\s*['"]?1['"]?|'\s*OR\s*1\s*=\s*1\s*--|'\s*--/i.test(username + password);
  const exactMatch = fakeDb.find(u => u.username === username && u.password === password);
  if (isBypass)   return res.json({ success:true,  bypassed:true,  query:simulatedQuery, user:fakeDb[2], message:'SQLi bypass successful!', flag:'FLAG{sql_injected_success}' });
  if (exactMatch) return res.json({ success:true,  bypassed:false, query:simulatedQuery, user:exactMatch, message:`Welcome back, ${exactMatch.username}!` });
  res.status(401).json({ success:false, query:simulatedQuery, message:'Invalid username or password.' });
});

app.post('/api/patched/login', (req, res) => {
  const { username, password } = req.body;
  const user = fakeDb.find(u => u.username === username && u.password === password);
  if (user) return res.json({ success:true, user:{ id:user.id, username:user.username, role:user.role }, message:`Welcome, ${user.username}!` });
  res.status(401).json({ success:false, message:'Invalid username or password.' });
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
<title>BankSecure — SQLi Lab</title>
<!-- Same shield favicon style as IDOR lab -->
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath fill='%231d4ed8' d='M16 2L4 7v9c0 7.18 5.16 13.9 12 15.93C23.84 29.9 29 23.18 29 16V7L16 2z'/%3E%3Cpath fill='white' d='M13 20.5l-4-4 1.41-1.41L13 17.67l8.59-8.58L23 10.5z'/%3E%3C/svg%3E">
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
* { box-sizing: border-box; }
body { font-family: 'Inter', sans-serif; background: #0f172a; min-height: 100vh; }
pre  { background: #0f172a; color: #94a3b8; padding: 1rem; border-radius: 8px; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; min-height: 48px; line-height: 1.6; border: 1px solid #1e293b; }
.mono { font-family: 'JetBrains Mono', monospace; }
.flag-box { background: #fef9c3; border: 2px solid #eab308; color: #713f12; padding: 0.75rem 1rem; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 0.85rem; display:none; margin-top: 0.75rem; word-break: break-all; }

/* ── Fake login page chrome ── */
.login-browser { border: 1px solid #334155; border-radius: 10px; overflow: hidden; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
.browser-chrome { background: #1e293b; padding: 8px 12px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #334155; }
.traffic-lights { display: flex; gap: 5px; flex-shrink: 0; }
.tl { width: 11px; height: 11px; border-radius: 50%; }
.tl-r { background: #ef4444; } .tl-y { background: #f59e0b; } .tl-g { background: #22c55e; }
.nav-btn { background: none; border: none; cursor: default; color: #475569; font-size: 15px; padding: 1px 5px; border-radius: 4px; line-height: 1; }
.nav-btn.clickable { cursor: pointer; }
.nav-btn.clickable:hover { background: #334155; color: #94a3b8; }
.url-wrap { flex: 1; display: flex; align-items: center; background: #0f172a; border: 1px solid #475569; border-radius: 5px; padding: 0 8px; height: 28px; gap: 5px; transition: border-color 0.15s; cursor: text; }
.url-wrap.locked { border-color: #334155; cursor: default; }
.url-scheme-green { font-size: 11px; color: #22c55e; font-family: 'JetBrains Mono', monospace; flex-shrink: 0; font-weight: 600; user-select: none; }
.url-static { flex: 1; font-size: 12px; font-family: 'JetBrains Mono', monospace; color: #64748b; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; user-select: none; }
.lock-icon { font-size: 11px; color: #22c55e; flex-shrink: 0; user-select: none; }
.browser-status { background: #1e293b; border-top: 1px solid #334155; padding: 3px 12px; font-size: 10.5px; color: #475569; font-family: 'JetBrains Mono', monospace; min-height: 20px; }

/* ── Login page inside browser ── */
.page-bg { background: linear-gradient(135deg, #1e3a5f 0%, #0f2340 100%); padding: 28px 20px; }
.login-card { background: white; border-radius: 16px; overflow: hidden; max-width: 380px; margin: 0 auto; box-shadow: 0 20px 48px rgba(0,0,0,0.4); }
.card-header { background: linear-gradient(135deg, #1e40af, #1e3a8a); padding: 24px; text-align: center; }
.form-input { width: 100%; border: 1.5px solid #e2e8f0; border-radius: 8px; padding: 10px 12px; font-size: 13px; font-family: 'JetBrains Mono', monospace; outline: none; transition: border-color 0.15s, box-shadow 0.15s; color: #1e293b; }
.form-input:focus { border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.15); }
.form-input.injected { border-color: #ef4444; box-shadow: 0 0 0 3px rgba(239,68,68,0.15); color: #dc2626; }
.sign-in-btn { width: 100%; background: #1d4ed8; color: white; border: none; padding: 11px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.15s; }
.sign-in-btn:hover { background: #1e40af; }
.sign-in-btn:active { transform: scale(0.99); }
.sign-in-btn:disabled { background: #94a3b8; cursor: not-allowed; }

/* ── SQL query display ── */
.query-token-normal { color: #7dd3fc; }
.query-token-inject { color: #f87171; font-weight: 600; }
.query-token-string { color: #86efac; }
.query-token-kw { color: #c4b5fd; }

/* ── Hint system ── */
.hint-body { display: none; }
.hint-body.open { display: block; }
.hint-trigger { transition: background 0.15s; }
.hint-trigger:hover { background: #fffbeb; }
.pip { width: 10px; height: 10px; border-radius: 50%; background: #334155; display: inline-block; transition: background 0.2s; }
.pip.used { background: #ef4444; }
.pip.warn { background: #f59e0b; }

/* ── Response states ── */
.resp-success { background: #f0fdf4; border: 1px solid #86efac; border-radius: 8px; padding: 12px; }
.resp-bypass  { background: #fef2f2; border: 1px solid #fca5a5; border-radius: 8px; padding: 12px; }
.resp-fail    { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; }
</style>
</head>
<body>

<!-- ── Top nav ── -->
<nav class="bg-slate-900 border-b border-slate-700 px-6 py-3 flex items-center justify-between">
  <div class="flex items-center gap-3">
    <div class="w-8 h-8 bg-blue-600 rounded flex items-center justify-center">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white" class="w-4 h-4">
        <path fill-rule="evenodd" d="M12 1.5a5.25 5.25 0 00-5.25 5.25v3a3 3 0 00-3 3v6.75a3 3 0 003 3h10.5a3 3 0 003-3v-6.75a3 3 0 00-3-3v-3c0-2.9-2.35-5.25-5.25-5.25zm3.75 8.25v-3a3.75 3.75 0 10-7.5 0v3h7.5z" clip-rule="evenodd"/>
      </svg>
    </div>
    <span class="font-bold text-white text-lg">BankSecure</span>
    <span class="text-slate-400 text-sm">Online Banking Portal</span>
    <span class="text-xs bg-red-600 text-white px-2 py-0.5 rounded font-semibold">SQLi Lab</span>
  </div>
  <div class="text-sm text-slate-400">Not logged in — <span class="text-slate-200 font-medium">attempt to bypass</span></div>
</nav>

<div class="max-w-6xl mx-auto px-4 py-6 space-y-5">

  <!-- Objective -->
  <div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">
    <span class="text-2xl flex-shrink-0 mt-0.5">🎯</span>
    <div>
      <p class="font-semibold text-amber-800 text-sm">SQL Injection Lab — Objective</p>
      <p class="text-amber-700 text-xs mt-1 leading-relaxed">
        This login form builds its SQL query using <strong>string concatenation</strong> — no sanitization, no parameterized queries.
        Your goal: <strong>bypass authentication</strong> by injecting SQL into the username or password field and capture the flag.
        Type your payloads manually. Watch the live query preview update as you type.
      </p>
    </div>
  </div>

  <div class="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">

    <!-- ══ LEFT: Labs ══ -->
    <div class="xl:col-span-2 space-y-5">

      <!-- Challenge 1: Vulnerable login -->
      <div>
        <div class="flex items-center gap-2 mb-2">
          <span class="text-sm font-semibold text-slate-200">Challenge 1 — Vulnerable Login Form</span>
          <span class="text-xs bg-red-900 text-red-300 px-2 py-0.5 rounded font-semibold">VULNERABLE</span>
        </div>
        <div class="login-browser">
          <!-- Browser chrome (URL locked — this is a login page, URL doesn't change) -->
          <div class="browser-chrome">
            <div class="traffic-lights"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="flex gap-1">
              <button class="nav-btn">&#8592;</button>
              <button class="nav-btn">&#8594;</button>
              <button class="nav-btn clickable" onclick="resetVulnForm()" title="Reset form">&#8635;</button>
            </div>
            <div class="url-wrap locked">
              <span class="lock-icon">&#128274;</span>
              <span class="url-scheme-green">https://</span>
              <span class="url-static">banksecure.internal/login</span>
            </div>
          </div>
          <!-- Page content -->
          <div class="page-bg">
            <div class="login-card">
              <div class="card-header">
                <div class="w-12 h-12 bg-white/20 rounded-full flex items-center justify-center mx-auto mb-3">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white" class="w-6 h-6">
                    <path d="M11.584 2.376a.75.75 0 01.832 0l9 6a.75.75 0 11-.832 1.248L12 3.901 3.416 9.624a.75.75 0 01-.832-1.248l9-6z"/>
                    <path fill-rule="evenodd" d="M20.25 10.332v9.918H21a.75.75 0 010 1.5H3a.75.75 0 010-1.5h.75v-9.918a.75.75 0 01.634-.74A49.109 49.109 0 0112 9c2.59 0 5.134.202 7.616.592a.75.75 0 01.634.74zm-7.5 2.418a.75.75 0 00-1.5 0v6.75a.75.75 0 001.5 0v-6.75zm3-.75a.75.75 0 01.75.75v6.75a.75.75 0 01-1.5 0v-6.75a.75.75 0 01.75-.75zM9 12.75a.75.75 0 00-1.5 0v6.75a.75.75 0 001.5 0v-6.75z" clip-rule="evenodd"/>
                  </svg>
                </div>
                <h1 class="text-white font-bold text-xl">BankSecure</h1>
                <p class="text-blue-300 text-xs mt-1">Online Banking Portal</p>
                <span class="inline-block mt-2 text-xs bg-red-500 text-white px-2 py-0.5 rounded font-semibold">VULNERABLE</span>
              </div>
              <div class="p-6 space-y-4">
                <div>
                  <label class="text-xs text-gray-500 uppercase tracking-wide font-semibold block mb-1.5">Username</label>
                  <input id="v-user" type="text" placeholder="Enter username..."
                    class="form-input mono" autocomplete="off" spellcheck="false"
                    oninput="onInputChange()"
                    onkeydown="if(event.key==='Enter') doVulnLogin()">
                </div>
                <div>
                  <label class="text-xs text-gray-500 uppercase tracking-wide font-semibold block mb-1.5">Password</label>
                  <input id="v-pass" type="text" placeholder="Enter password..."
                    class="form-input mono" autocomplete="off" spellcheck="false"
                    oninput="onInputChange()"
                    onkeydown="if(event.key==='Enter') doVulnLogin()">
                </div>
                <button id="sign-in-btn" class="sign-in-btn" onclick="doVulnLogin()">Sign In</button>
                <div id="v-result" style="display:none;"></div>
                <div id="v-flag" class="flag-box"></div>
              </div>
            </div>
          </div>
          <div class="browser-status" id="vuln-status">Waiting for login attempt...</div>
        </div>
        <p class="text-xs text-slate-500 font-mono mt-1.5 pl-1">↑ Type directly into the fields — what happens when you include SQL characters?</p>
      </div>

      <!-- Live query preview -->
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-4">
        <div class="flex items-center gap-2 mb-3">
          <span class="text-xs font-semibold text-slate-300">&#128269; Live SQL Query Preview</span>
          <span class="text-xs text-slate-500">(updates as you type)</span>
        </div>
        <pre id="query-display" class="text-xs" style="background:#0f172a;border-color:#1e293b;"><span class="query-token-kw">SELECT</span> * <span class="query-token-kw">FROM</span> users <span class="query-token-kw">WHERE</span> username=<span class="query-token-string">'?'</span> <span class="query-token-kw">AND</span> password=<span class="query-token-string">'?'</span></pre>
        <p class="text-xs text-slate-500 mt-2">Built by string concatenation — your input is inserted raw. Can you break out of the quotes?</p>
      </div>

      <!-- Challenge 2: Patched login -->
      <div>
        <div class="flex items-center gap-2 mb-2">
          <span class="text-sm font-semibold text-slate-200">Challenge 2 — Patched Login (Parameterized Query)</span>
          <span class="text-xs bg-green-900 text-green-300 px-2 py-0.5 rounded font-semibold">FIXED</span>
        </div>
        <div class="login-browser">
          <div class="browser-chrome">
            <div class="traffic-lights"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="flex gap-1">
              <button class="nav-btn">&#8592;</button>
              <button class="nav-btn">&#8594;</button>
              <button class="nav-btn clickable" onclick="resetPatchedForm()" title="Reset">&#8635;</button>
            </div>
            <div class="url-wrap locked">
              <span class="lock-icon">&#128274;</span>
              <span class="url-scheme-green">https://</span>
              <span class="url-static">banksecure.internal/login?version=patched</span>
            </div>
          </div>
          <div class="page-bg" style="background: linear-gradient(135deg, #14532d 0%, #052e16 100%);">
            <div class="login-card">
              <div class="card-header" style="background: linear-gradient(135deg, #166534, #14532d);">
                <div class="w-12 h-12 bg-white/20 rounded-full flex items-center justify-center mx-auto mb-3">
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white" class="w-6 h-6">
                    <path fill-rule="evenodd" d="M12 1.5a5.25 5.25 0 00-5.25 5.25v3a3 3 0 00-3 3v6.75a3 3 0 003 3h10.5a3 3 0 003-3v-6.75a3 3 0 00-3-3v-3c0-2.9-2.35-5.25-5.25-5.25zm3.75 8.25v-3a3.75 3.75 0 10-7.5 0v3h7.5z" clip-rule="evenodd"/>
                  </svg>
                </div>
                <h1 class="text-white font-bold text-xl">BankSecure</h1>
                <p class="text-green-300 text-xs mt-1">Secured Login — v2</p>
                <span class="inline-block mt-2 text-xs bg-green-600 text-white px-2 py-0.5 rounded font-semibold">PATCHED</span>
              </div>
              <div class="p-6 space-y-4">
                <p class="text-xs text-gray-500 bg-gray-50 rounded-lg p-3 leading-relaxed">
                  This version uses <strong>parameterized queries</strong>. Your input is never inserted directly into the SQL string — it's passed as a bound parameter. Try the same payloads you used above.
                </p>
                <div>
                  <label class="text-xs text-gray-500 uppercase tracking-wide font-semibold block mb-1.5">Username</label>
                  <input id="p-user" type="text" placeholder="Enter username..."
                    class="form-input mono" autocomplete="off" spellcheck="false"
                    onkeydown="if(event.key==='Enter') doPatchLogin()">
                </div>
                <div>
                  <label class="text-xs text-gray-500 uppercase tracking-wide font-semibold block mb-1.5">Password</label>
                  <input id="p-pass" type="text" placeholder="Enter password..."
                    class="form-input mono" autocomplete="off" spellcheck="false"
                    onkeydown="if(event.key==='Enter') doPatchLogin()">
                </div>
                <button class="sign-in-btn" style="background:#16a34a;" onmouseover="this.style.background='#15803d'" onmouseout="this.style.background='#16a34a'" onclick="doPatchLogin()">Sign In</button>
                <div id="p-result" style="display:none;"></div>
              </div>
            </div>
          </div>
          <div class="browser-status" id="patched-status">Waiting for login attempt...</div>
        </div>
        <p class="text-xs text-slate-500 font-mono mt-1.5 pl-1">↑ Try the exact same payload — notice the difference in how the server handles your input</p>
      </div>

    </div>

    <!-- ══ RIGHT: Sidebar ══ -->
    <div class="space-y-4">

      <!-- Attempt counter -->
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-4">
        <div class="flex items-center justify-between mb-3">
          <span class="text-sm font-semibold text-slate-200">Attempts</span>
          <span id="tries-text" class="text-xs text-slate-400 font-mono">0 / 10</span>
        </div>
        <div class="flex flex-wrap gap-1 mb-3" id="pip-row"></div>
        <p class="text-xs text-slate-500 leading-relaxed">Each login attempt counts. After <strong class="text-slate-300">5 failed attempts</strong> a hint auto-unlocks. Paid hints cost additional attempts.</p>
        <div class="mt-3 pt-3 border-t border-slate-700">
          <div class="flex justify-between text-xs mb-1">
            <span class="text-slate-400">Flag captured</span>
            <span id="flags-count" class="font-bold text-green-400">0 / 1</span>
          </div>
          <div class="w-full bg-slate-700 rounded-full h-2">
            <div id="flag-progress" class="bg-green-500 h-2 rounded-full transition-all duration-500" style="width:0%"></div>
          </div>
        </div>
      </div>

      <!-- Hints -->
      <div class="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
        <div class="bg-amber-900/40 border-b border-amber-700/50 px-4 py-3 flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span>&#128161;</span>
            <span class="text-sm font-semibold text-amber-300">Hints</span>
          </div>
          <span class="text-xs bg-amber-900/50 text-amber-400 px-2 py-0.5 rounded font-medium" id="hints-used-label">0 of 4 revealed</span>
        </div>

        <!-- Hint 1 (free) -->
        <div class="border-b border-slate-700">
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left hover:bg-slate-700/50" onclick="revealHint(0)">
            <span class="text-xs font-medium text-slate-300" id="hl0">&#128274; What is SQL injection?</span>
            <span class="text-xs bg-green-900/50 text-green-400 px-2 py-0.5 rounded font-medium">free</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-slate-400 leading-relaxed bg-slate-900/30" id="hint-body-0">
            SQL injection happens when user input is inserted <em>directly</em> into a query string. By including SQL syntax like <code class="bg-slate-700 px-1 rounded text-slate-200">'</code> or <code class="bg-slate-700 px-1 rounded text-slate-200">--</code> you can change the <em>logic</em> of the query itself — not just the values it searches for.
          </div>
        </div>

        <!-- Hint 2 (-1 attempt) -->
        <div class="border-b border-slate-700">
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left hover:bg-slate-700/50" onclick="revealHint(1)">
            <span class="text-xs font-medium text-slate-300" id="hl1">&#128274; Breaking out of the query</span>
            <span class="text-xs bg-amber-900/50 text-amber-400 px-2 py-0.5 rounded font-medium">−1 attempt</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-slate-400 leading-relaxed bg-slate-900/30" id="hint-body-1">
            The query looks like: <code class="bg-slate-700 px-1 rounded text-slate-200 text-xs">WHERE username='YOUR_INPUT'</code>. If you type a <code class="bg-slate-700 px-1 rounded text-slate-200">'</code> in your input, you close the string early. What could you add after the closing quote to make the condition always true?
          </div>
        </div>

        <!-- Hint 3 (-2 attempts) -->
        <div class="border-b border-slate-700">
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left hover:bg-slate-700/50" onclick="revealHint(2)">
            <span class="text-xs font-medium text-slate-300" id="hl2">&#128274; Always-true condition</span>
            <span class="text-xs bg-red-900/50 text-red-400 px-2 py-0.5 rounded font-medium">−2 attempts</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-slate-400 leading-relaxed bg-slate-900/30" id="hint-body-2">
            After closing the quote, add an <code class="bg-slate-700 px-1 rounded text-slate-200">OR</code> clause that is always true — like <code class="bg-slate-700 px-1 rounded text-slate-200">1=1</code>. Then use <code class="bg-slate-700 px-1 rounded text-slate-200">--</code> to comment out the rest of the query (including the password check). Watch the live query preview update as you type.
          </div>
        </div>

        <!-- Hint 4 (-2 attempts) -->
        <div>
          <button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left hover:bg-slate-700/50" onclick="revealHint(3)">
            <span class="text-xs font-medium text-slate-300" id="hl3">&#128274; Exact payload structure</span>
            <span class="text-xs bg-red-900/50 text-red-400 px-2 py-0.5 rounded font-medium">−2 attempts</span>
          </button>
          <div class="hint-body px-4 pb-3 text-xs text-slate-400 leading-relaxed bg-slate-900/30" id="hint-body-3">
            Put this in the <strong>username</strong> field and anything in the password field:<br>
            <code class="bg-slate-700 px-1 py-0.5 rounded text-green-300 text-xs block mt-2 break-all">' OR 1=1--</code>
            The <code class="bg-slate-700 px-1 rounded text-slate-200">'</code> closes the string, <code class="bg-slate-700 px-1 rounded">OR 1=1</code> makes it always true, <code class="bg-slate-700 px-1 rounded">--</code> comments out the password check.
          </div>
        </div>
      </div>

      <!-- Observe panel -->
      <div class="bg-slate-800 border border-slate-700 rounded-xl p-4">
        <p class="text-xs font-semibold text-slate-300 mb-2">&#128270; Things to observe</p>
        <ul class="text-xs text-slate-500 space-y-1.5 leading-relaxed">
          <li>&#10140; Watch the live query preview as you type</li>
          <li>&#10140; What does a <code class="bg-slate-700 px-1 rounded text-slate-300">'</code> do to the query structure?</li>
          <li>&#10140; Try the same payload on the patched form</li>
          <li>&#10140; Why does the patched version not show your input in the query?</li>
        </ul>
      </div>

    </div>
  </div>
</div>

<script>
// ── State ───────────────────────────────────────────────────────────────────
const MAX_TRIES = 10;
const AUTO_HINT_THRESHOLD = 5;
let tries = 0;
let flagCaptured = false;
const hintsRevealed = [false, false, false, false];
const hintCosts     = [0, 1, 2, 2];

// ── Pips ─────────────────────────────────────────────────────────────────────
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

// ── Live query preview ────────────────────────────────────────────────────────
function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function hasSqlChars(s) {
  return /['";\\-\\-]/.test(s);
}

function renderQuery() {
  const u = document.getElementById('v-user').value;
  const p = document.getElementById('v-pass').value;
  const uSafe = escHtml(u);
  const pSafe = escHtml(p);
  const uClass = hasSqlChars(u) ? 'query-token-inject' : 'query-token-string';
  const pClass = hasSqlChars(p) ? 'query-token-inject' : 'query-token-string';

  // toggle red border if SQL chars detected
  document.getElementById('v-user').className = 'form-input mono' + (hasSqlChars(u) ? ' injected' : '');
  document.getElementById('v-pass').className = 'form-input mono' + (hasSqlChars(p) ? ' injected' : '');

  document.getElementById('query-display').innerHTML =
    '<span class="query-token-kw">SELECT</span> * <span class="query-token-kw">FROM</span> users ' +
    '<span class="query-token-kw">WHERE</span> username=<span class="' + uClass + '">\'' + uSafe + '\'</span> ' +
    '<span class="query-token-kw">AND</span> password=<span class="' + pClass + '">\'' + pSafe + '\'</span>';
}

function onInputChange() { renderQuery(); }

// ── Vuln login ────────────────────────────────────────────────────────────────
async function doVulnLogin() {
  const u   = document.getElementById('v-user').value;
  const p   = document.getElementById('v-pass').value;
  const btn = document.getElementById('sign-in-btn');
  const res = document.getElementById('v-result');
  const fl  = document.getElementById('v-flag');
  const sb  = document.getElementById('vuln-status');

  if (!u && !p) return;

  btn.disabled = true;
  btn.textContent = 'Signing in...';
  sb.textContent = 'Sending POST /api/vulnerable/login\u2026';
  res.style.display = 'none';
  fl.style.display  = 'none';

  recordTry();

  try {
    const r = await fetch('/api/vulnerable/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p }),
    });
    const d = await r.json();

    res.style.display = 'block';
    sb.textContent = 'POST /api/vulnerable/login \u2014 HTTP ' + r.status + (r.ok ? ' OK' : ' Unauthorized');

    if (d.bypassed) {
      res.innerHTML = '<div class="resp-bypass"><p class="font-bold text-red-600 text-sm">\uD83D\uDEA8 Authentication Bypassed!</p><p class="text-red-500 text-xs mt-1">Logged in as: <strong>' + d.user.username + '</strong> (' + d.user.role + ')</p></div>';
      fl.textContent = '\uD83C\uDFC1 Flag: ' + d.flag;
      fl.style.display = 'block';
      if (!flagCaptured) {
        flagCaptured = true;
        document.getElementById('flags-count').textContent = '1 / 1';
        document.getElementById('flag-progress').style.width = '100%';
      }
    } else if (d.success) {
      res.innerHTML = '<div class="resp-success"><p class="text-green-700 font-semibold text-sm">\u2705 ' + d.message + '</p><p class="text-green-600 text-xs mt-1">Role: ' + d.user.role + ' \u2014 No flag here though.</p></div>';
    } else {
      res.innerHTML = '<div class="resp-fail"><p class="text-gray-600 text-sm">\u274C ' + d.message + '</p></div>';
    }
  } catch (e) {
    res.style.display = 'block';
    res.innerHTML = '<div class="resp-fail"><p class="text-gray-600 text-sm">Network error: ' + e.message + '</p></div>';
    sb.textContent = 'Request failed';
  }

  btn.disabled = false;
  btn.textContent = 'Sign In';
}

// ── Patched login ─────────────────────────────────────────────────────────────
async function doPatchLogin() {
  const u  = document.getElementById('p-user').value;
  const p  = document.getElementById('p-pass').value;
  const sb = document.getElementById('patched-status');
  const res = document.getElementById('p-result');

  if (!u && !p) return;
  sb.textContent = 'Sending POST /api/patched/login\u2026';
  res.style.display = 'none';

  recordTry();

  try {
    const r = await fetch('/api/patched/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p }),
    });
    const d = await r.json();
    sb.textContent = 'POST /api/patched/login \u2014 HTTP ' + r.status + (r.ok ? ' OK' : ' Unauthorized');
    res.style.display = 'block';
    if (d.success) {
      res.innerHTML = '<div class="resp-success"><p class="text-green-700 font-semibold text-sm">\u2705 ' + d.message + '</p></div>';
    } else {
      res.innerHTML = '<div class="resp-fail"><p class="text-gray-600 text-sm">\u274C ' + d.message + '<br><span class="text-xs text-gray-400 mt-1 block">SQLi payload was treated as a literal string \u2014 no bypass possible.</span></p></div>';
    }
  } catch (e) {
    res.style.display = 'block';
    res.innerHTML = '<div class="resp-fail"><p class="text-gray-600 text-sm">Error: ' + e.message + '</p></div>';
  }
}

// ── Reset helpers ─────────────────────────────────────────────────────────────
function resetVulnForm() {
  document.getElementById('v-user').value = '';
  document.getElementById('v-pass').value = '';
  document.getElementById('v-user').className = 'form-input mono';
  document.getElementById('v-pass').className = 'form-input mono';
  document.getElementById('v-result').style.display = 'none';
  document.getElementById('v-flag').style.display = 'none';
  document.getElementById('vuln-status').textContent = 'Waiting for login attempt...';
  renderQuery();
}
function resetPatchedForm() {
  document.getElementById('p-user').value = '';
  document.getElementById('p-pass').value = '';
  document.getElementById('p-result').style.display = 'none';
  document.getElementById('patched-status').textContent = 'Waiting for login attempt...';
}

// ── Hint system ───────────────────────────────────────────────────────────────
function revealHint(idx, auto = false) {
  const body = document.getElementById('hint-body-' + idx);
  if (hintsRevealed[idx]) { body.classList.toggle('open'); return; }

  const cost = hintCosts[idx];
  if (!auto && cost > 0) {
    const remaining = MAX_TRIES - tries;
    if (!confirm('This hint costs ' + cost + ' attempt(s).\\nYou have ' + remaining + ' remaining. Reveal anyway?')) return;
    recordTry(cost);
  }

  hintsRevealed[idx] = true;
  body.classList.add('open');
  const lbl = document.getElementById('hl' + idx);
  if (lbl) lbl.innerHTML = lbl.innerHTML.replace('\\uD83D\\uDD12', '\\uD83D\\uDD13');
  document.getElementById('hints-used-label').textContent = hintsRevealed.filter(Boolean).length + ' of 4 revealed';
}
</script>

<!-- ── Periodic auth re-check ── -->
<script>
(function(){
  var token    = new URLSearchParams(window.location.search).get('token');
  var BACKEND  = '${backendUrl}';
  var FRONTEND = '${frontendUrl}';
  function recheck(){
    if(!token){ window.location.href=FRONTEND+'/login.html'; return; }
    fetch(BACKEND+'/api/auth/me',{headers:{'Authorization':'Bearer '+token}})
      .then(function(r){ if(!r.ok) window.location.href=FRONTEND+'/login.html'; })
      .catch(function(){});
  }
  setTimeout(function loop(){ recheck(); setTimeout(loop,5000); },5000);
})();
</script>
</body>
</html>`);
});

app.listen(PORT, () => console.log(`\uD83D\uDC89 SQLi Lab running on http://localhost:${PORT}`));