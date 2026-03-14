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
  { id:1, username:'alice', password:'alice123',    role:'user',  secret:null },
  { id:2, username:'bob',   password:'bob456',      role:'user',  secret:null },
  { id:3, username:'admin', password:'sup3rs3cr3t', role:'admin', secret:'FLAG{sql_injected_success}' },
];

app.post('/api/vulnerable/login', (req, res) => {
  const { username, password } = req.body;
  const simulatedQuery = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  const isBypass   = /'\s*OR\s*['"]?1['"]?\s*=\s*['"]?1['"]?|'\s*OR\s*1\s*=\s*1\s*--|'\s*--/i.test(username + password);
  const exactMatch = fakeDb.find(u => u.username === username && u.password === password);
  if (isBypass)   return res.json({ success:true,  bypassed:true,  query:simulatedQuery, user:fakeDb[2], message:'SQLi bypass successful!', flag:'FLAG{sql_injected_success}' });
  if (exactMatch) return res.json({ success:true,  bypassed:false, query:simulatedQuery, user:exactMatch, message:'Welcome back, ' + exactMatch.username + '!' });
  res.status(401).json({ success:false, query:simulatedQuery, message:'Invalid username or password.' });
});

app.post('/api/patched/login', (req, res) => {
  const { username, password } = req.body;
  const user = fakeDb.find(u => u.username === username && u.password === password);
  if (user) return res.json({ success:true, user:{ id:user.id, username:user.username, role:user.role }, message:'Welcome, ' + user.username + '!' });
  res.status(401).json({ success:false, message:'Invalid username or password.' });
});

// ── UI ────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  const backendUrl  = BACKEND_URL;
  const frontendUrl = FRONTEND_URL;
  const token       = req.query.token || '';

  // Unique SQLi favicon: red syringe/injection needle
  const favicon = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23dc2626'/%3E%3Ctext x='16' y='22' font-size='18' text-anchor='middle' fill='white'%3E%F0%9F%92%89%3C/text%3E%3C/svg%3E";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BankSecure — SQLi Lab</title>
<link rel="icon" type="image/svg+xml" href="${favicon}">
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;}
body{font-family:'Inter',sans-serif;background:#0f172a;min-height:100vh;}
.mono{font-family:'JetBrains Mono',monospace;}
pre{background:#0f172a;color:#94a3b8;padding:1rem;border-radius:8px;font-size:.75rem;overflow-x:auto;white-space:pre-wrap;min-height:48px;line-height:1.6;border:1px solid #1e293b;}
.flag-box{background:#fef9c3;border:2px solid #eab308;color:#713f12;padding:.75rem 1rem;border-radius:8px;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.85rem;display:none;margin-top:.75rem;word-break:break-all;}
/* browser chrome */
.fake-browser{border:1px solid #334155;border-radius:10px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.4);}
.b-chrome{background:#1e293b;padding:8px 12px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #334155;}
.tl-row{display:flex;gap:5px;flex-shrink:0;}
.tl{width:11px;height:11px;border-radius:50%;}
.tl-r{background:#ef4444;}.tl-y{background:#f59e0b;}.tl-g{background:#22c55e;}
.nb{background:none;border:none;cursor:default;color:#475569;font-size:15px;padding:1px 5px;border-radius:4px;line-height:1;}
.nb.cl{cursor:pointer;}
.nb.cl:hover{background:#334155;color:#94a3b8;}
.url-bar{flex:1;display:flex;align-items:center;background:#0f172a;border:1px solid #334155;border-radius:5px;padding:0 8px;height:28px;gap:5px;}
.url-scheme{font-size:11px;color:#22c55e;font-family:'JetBrains Mono',monospace;flex-shrink:0;font-weight:600;user-select:none;}
.url-text{flex:1;font-size:12px;font-family:'JetBrains Mono',monospace;color:#475569;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;user-select:none;}
.b-status{background:#1e293b;border-top:1px solid #334155;padding:3px 12px;font-size:10.5px;color:#475569;font-family:'JetBrains Mono',monospace;min-height:20px;}
/* login card */
.page-bg{background:linear-gradient(135deg,#1e3a5f 0%,#0f2340 100%);padding:28px 20px;}
.login-card{background:white;border-radius:16px;overflow:hidden;max-width:380px;margin:0 auto;box-shadow:0 20px 48px rgba(0,0,0,.4);}
.card-hdr{background:linear-gradient(135deg,#1e40af,#1e3a8a);padding:24px;text-align:center;}
.fi{width:100%;border:1.5px solid #e2e8f0;border-radius:8px;padding:10px 12px;font-size:13px;font-family:'JetBrains Mono',monospace;outline:none;transition:border-color .15s,box-shadow .15s;color:#1e293b;background:white;}
.fi:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15);}
.fi.bad{border-color:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,.15);color:#dc2626;}
.si-btn{width:100%;background:#1d4ed8;color:white;border:none;padding:11px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:background .15s;}
.si-btn:hover{background:#1e40af;}
.si-btn:disabled{background:#94a3b8;cursor:not-allowed;}
/* query tokens */
.kw{color:#c4b5fd;}.qs{color:#86efac;}.qi{color:#f87171;font-weight:600;}
/* hint */
.hint-body{display:none;}.hint-body.open{display:block;}
.ht:hover{background:rgba(255,255,255,.05);}
/* pips */
.pip{width:10px;height:10px;border-radius:50%;background:#334155;display:inline-block;transition:background .2s;}
.pip.used{background:#ef4444;}.pip.warn{background:#f59e0b;}
/* resp */
.r-ok{background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:12px;}
.r-bad{background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:12px;}
.r-fail{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;}
</style>
</head>
<body>

<nav class="bg-slate-900 border-b border-slate-700 px-6 py-3 flex items-center justify-between">
  <div class="flex items-center gap-3">
    <div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center text-white text-sm font-bold">SQL</div>
    <span class="font-bold text-white text-lg">BankSecure</span>
    <span class="text-slate-400 text-sm">Online Banking Portal</span>
    <span class="text-xs bg-red-700 text-red-200 px-2 py-0.5 rounded font-semibold">SQLi Lab</span>
  </div>
  <div class="text-sm text-slate-400">Not logged in &mdash; <span class="text-slate-200 font-medium">attempt to bypass</span></div>
</nav>

<div class="max-w-6xl mx-auto px-4 py-6 space-y-5">

  <div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">
    <span class="text-2xl flex-shrink-0 mt-0.5">&#127919;</span>
    <div>
      <p class="font-semibold text-amber-800 text-sm">SQL Injection Lab &mdash; Objective</p>
      <p class="text-amber-700 text-xs mt-1 leading-relaxed">
        This login form builds its SQL query by <strong>concatenating your input directly</strong> into the query string &mdash; no sanitization.
        Your goal: <strong>bypass authentication</strong> without knowing any valid password. Type your payloads manually into the fields.
        Watch the live query preview update as you type to understand what&apos;s happening.
      </p>
    </div>
  </div>

  <div class="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">

    <div class="xl:col-span-2 space-y-5">

      <!-- Challenge 1 -->
      <div>
        <div class="flex items-center gap-2 mb-2">
          <span class="text-sm font-semibold text-slate-200">Challenge 1 &mdash; Vulnerable Login Form</span>
          <span class="text-xs bg-red-900 text-red-300 px-2 py-0.5 rounded font-semibold">VULNERABLE</span>
        </div>
        <div class="fake-browser">
          <div class="b-chrome">
            <div class="tl-row"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="flex gap-1">
              <button class="nb">&#8592;</button>
              <button class="nb">&#8594;</button>
              <button class="nb cl" title="Reset form" onclick="resetVuln()">&#8635;</button>
            </div>
            <div class="url-bar">
              <span style="font-size:11px;color:#22c55e;flex-shrink:0;">&#128274;</span>
              <span class="url-scheme">https://</span>
              <span class="url-text">banksecure.internal/login</span>
            </div>
          </div>
          <div class="page-bg">
            <div class="login-card">
              <div class="card-hdr">
                <div style="width:48px;height:48px;background:rgba(255,255,255,.2);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:24px;">&#127963;</div>
                <h1 style="color:white;font-weight:700;font-size:1.2rem;">BankSecure</h1>
                <p style="color:#93c5fd;font-size:11px;margin-top:4px;">Online Banking Portal</p>
                <span style="display:inline-block;margin-top:8px;font-size:11px;background:#ef4444;color:white;padding:2px 8px;border-radius:4px;font-weight:600;">VULNERABLE</span>
              </div>
              <div style="padding:24px;">
                <div style="margin-bottom:14px;">
                  <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Username</label>
                  <input id="v-user" type="text" placeholder="Enter username..." class="fi mono" autocomplete="off" spellcheck="false">
                </div>
                <div style="margin-bottom:16px;">
                  <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Password</label>
                  <input id="v-pass" type="text" placeholder="Enter password..." class="fi mono" autocomplete="off" spellcheck="false">
                </div>
                <button id="sign-in-btn" class="si-btn" onclick="doVulnLogin()">Sign In</button>
                <div id="v-result" style="display:none;margin-top:12px;"></div>
                <div id="v-flag" class="flag-box"></div>
              </div>
            </div>
          </div>
          <div class="b-status" id="vuln-status">Waiting for login attempt...</div>
        </div>
        <p style="font-size:11px;color:#475569;font-family:'JetBrains Mono',monospace;margin-top:6px;padding-left:4px;">&#8593; Type directly into the fields &mdash; what happens when you include SQL characters like &apos; or --</p>
      </div>

      <!-- Live query preview -->
      <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
          <span style="font-size:12px;font-weight:600;color:#cbd5e1;">&#128269; Live SQL Query Preview</span>
          <span style="font-size:11px;color:#475569;">(updates as you type)</span>
        </div>
        <pre id="query-display"><span class="kw">SELECT</span> * <span class="kw">FROM</span> users <span class="kw">WHERE</span> username=<span class="qs">'?'</span> <span class="kw">AND</span> password=<span class="qs">'?'</span></pre>
        <p style="font-size:11px;color:#475569;margin-top:8px;">Your input is inserted raw &mdash; can you break out of the string quotes?</p>
      </div>

      <!-- Challenge 2 -->
      <div>
        <div class="flex items-center gap-2 mb-2">
          <span class="text-sm font-semibold text-slate-200">Challenge 2 &mdash; Patched Login (Parameterized Query)</span>
          <span class="text-xs bg-green-900 text-green-300 px-2 py-0.5 rounded font-semibold">FIXED</span>
        </div>
        <div class="fake-browser">
          <div class="b-chrome">
            <div class="tl-row"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
            <div class="flex gap-1">
              <button class="nb">&#8592;</button>
              <button class="nb">&#8594;</button>
              <button class="nb cl" title="Reset" onclick="resetPatched()">&#8635;</button>
            </div>
            <div class="url-bar">
              <span style="font-size:11px;color:#22c55e;flex-shrink:0;">&#128274;</span>
              <span class="url-scheme">https://</span>
              <span class="url-text">banksecure.internal/login?version=patched</span>
            </div>
          </div>
          <div class="page-bg" style="background:linear-gradient(135deg,#14532d 0%,#052e16 100%);">
            <div class="login-card">
              <div class="card-hdr" style="background:linear-gradient(135deg,#166534,#14532d);">
                <div style="width:48px;height:48px;background:rgba(255,255,255,.2);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:24px;">&#128274;</div>
                <h1 style="color:white;font-weight:700;font-size:1.2rem;">BankSecure</h1>
                <p style="color:#86efac;font-size:11px;margin-top:4px;">Secured Login &mdash; v2</p>
                <span style="display:inline-block;margin-top:8px;font-size:11px;background:#16a34a;color:white;padding:2px 8px;border-radius:4px;font-weight:600;">PATCHED</span>
              </div>
              <div style="padding:24px;">
                <p style="font-size:12px;color:#6b7280;background:#f9fafb;border-radius:8px;padding:10px 12px;margin-bottom:16px;line-height:1.6;">
                  This version uses <strong>parameterized queries</strong>. Input is passed as a bound parameter &mdash; never inserted into the SQL string. Try the same payloads.
                </p>
                <div style="margin-bottom:14px;">
                  <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Username</label>
                  <input id="p-user" type="text" placeholder="Enter username..." class="fi mono" autocomplete="off" spellcheck="false">
                </div>
                <div style="margin-bottom:16px;">
                  <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Password</label>
                  <input id="p-pass" type="text" placeholder="Enter password..." class="fi mono" autocomplete="off" spellcheck="false">
                </div>
                <button class="si-btn" style="background:#16a34a;" onclick="this.style.background='#15803d'" onmouseout="this.style.background='#16a34a'" onclick="doPatchLogin()">Sign In</button>
                <div id="p-result" style="display:none;margin-top:12px;"></div>
              </div>
            </div>
          </div>
          <div class="b-status" id="patch-status">Waiting for login attempt...</div>
        </div>
        <p style="font-size:11px;color:#475569;font-family:'JetBrains Mono',monospace;margin-top:6px;padding-left:4px;">&#8593; Try the exact same payload &mdash; notice how the server handles your input differently</p>
      </div>

    </div>

    <!-- Sidebar -->
    <div class="space-y-4">

      <!-- Attempt counter -->
      <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
          <span style="font-size:14px;font-weight:600;color:#e2e8f0;">Attempts</span>
          <span id="tries-text" style="font-size:12px;color:#64748b;font-family:'JetBrains Mono',monospace;">0 / 10</span>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px;" id="pip-row"></div>
        <p style="font-size:12px;color:#64748b;line-height:1.6;">Each login attempt counts. After <strong style="color:#94a3b8;">5 failed attempts</strong> a hint auto-unlocks.</p>
        <div style="margin-top:12px;padding-top:12px;border-top:1px solid #334155;">
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
            <span style="color:#64748b;">Flag captured</span>
            <span id="flags-count" style="font-weight:700;color:#4ade80;">0 / 1</span>
          </div>
          <div style="width:100%;background:#334155;border-radius:9999px;height:8px;">
            <div id="flag-progress" style="background:#22c55e;height:8px;border-radius:9999px;width:0%;transition:width .5s;"></div>
          </div>
        </div>
      </div>

      <!-- Hints -->
      <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;overflow:hidden;">
        <div style="background:rgba(120,53,15,.3);border-bottom:1px solid rgba(180,83,9,.4);padding:10px 16px;display:flex;align-items:center;justify-content:space-between;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span>&#128161;</span>
            <span style="font-size:14px;font-weight:600;color:#fbbf24;">Hints</span>
          </div>
          <span id="hints-used-label" style="font-size:11px;background:rgba(120,53,15,.4);color:#fbbf24;padding:2px 8px;border-radius:4px;font-weight:500;">0 of 4 revealed</span>
        </div>

        <div style="border-bottom:1px solid #334155;">
          <button class="ht" style="width:100%;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;background:none;border:none;cursor:pointer;text-align:left;" onclick="revealHint(0)">
            <span id="hl0" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; What is SQL injection?</span>
            <span style="font-size:11px;background:rgba(21,128,61,.3);color:#4ade80;padding:2px 8px;border-radius:4px;font-weight:500;">free</span>
          </button>
          <div class="hint-body" id="hint-body-0" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">
            SQL injection happens when user input is inserted <em>directly</em> into a query string. By including SQL syntax like <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">'</code> or <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">--</code> you can change the <em>logic</em> of the query itself &mdash; not just the values it searches for.
          </div>
        </div>

        <div style="border-bottom:1px solid #334155;">
          <button class="ht" style="width:100%;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;background:none;border:none;cursor:pointer;text-align:left;" onclick="revealHint(1)">
            <span id="hl1" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; Breaking out of the query</span>
            <span style="font-size:11px;background:rgba(120,53,15,.3);color:#fbbf24;padding:2px 8px;border-radius:4px;font-weight:500;">&#8722;1 attempt</span>
          </button>
          <div class="hint-body" id="hint-body-1" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">
            The query looks like: <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">WHERE username='YOUR_INPUT'</code>. If you type a <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">'</code>, you close that string early. What could you add after it to make the whole condition always evaluate to true?
          </div>
        </div>

        <div style="border-bottom:1px solid #334155;">
          <button class="ht" style="width:100%;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;background:none;border:none;cursor:pointer;text-align:left;" onclick="revealHint(2)">
            <span id="hl2" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; Always-true condition</span>
            <span style="font-size:11px;background:rgba(127,29,29,.3);color:#f87171;padding:2px 8px;border-radius:4px;font-weight:500;">&#8722;2 attempts</span>
          </button>
          <div class="hint-body" id="hint-body-2" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">
            After closing the quote, add an <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">OR</code> clause that is always true &mdash; like <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">1=1</code>. Then use <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">--</code> to comment out the rest of the query including the password check. Watch the live query preview react as you type.
          </div>
        </div>

        <div>
          <button class="ht" style="width:100%;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;background:none;border:none;cursor:pointer;text-align:left;" onclick="revealHint(3)">
            <span id="hl3" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; Exact payload structure</span>
            <span style="font-size:11px;background:rgba(127,29,29,.3);color:#f87171;padding:2px 8px;border-radius:4px;font-weight:500;">&#8722;2 attempts</span>
          </button>
          <div class="hint-body" id="hint-body-3" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">
            Put this in the <strong style="color:#e2e8f0;">username</strong> field, anything in password:<br>
            <code style="display:block;background:#0f172a;color:#4ade80;padding:6px 10px;border-radius:6px;margin-top:8px;font-size:12px;">' OR 1=1--</code>
            The <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">'</code> closes the string, <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">OR 1=1</code> makes it always true, <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">--</code> kills the password check.
          </div>
        </div>
      </div>

      <!-- Observe -->
      <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">
        <p style="font-size:12px;font-weight:600;color:#cbd5e1;margin-bottom:8px;">&#128270; Things to observe</p>
        <ul style="font-size:12px;color:#64748b;line-height:1.8;">
          <li>&#10140; Watch the live query as you type</li>
          <li>&#10140; What does a <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#94a3b8;">'</code> do to the query structure?</li>
          <li>&#10140; Try the same payload on the patched form</li>
          <li>&#10140; Why doesn&apos;t the patched version show your input in the query?</li>
        </ul>
      </div>

    </div>
  </div>
</div>

<script>
var MAX_TRIES = 10;
var AUTO_HINT = 5;
var tries = 0;
var flagDone = false;
var hintsRevealed = [false, false, false, false];
var hintCosts = [0, 1, 2, 2];

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

function recordTry(cost) {
  cost = cost || 1;
  tries = Math.min(MAX_TRIES, tries + cost);
  renderPips();
  if (tries >= AUTO_HINT && !hintsRevealed[1]) revealHint(1, true);
}

renderPips();

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function hasSql(s) {
  return /['";\-]/.test(s);
}

function renderQuery() {
  var u = document.getElementById('v-user').value;
  var p = document.getElementById('v-pass').value;
  var uSafe = escHtml(u);
  var pSafe = escHtml(p);
  var uCls = hasSql(u) ? 'qi' : 'qs';
  var pCls = hasSql(p) ? 'qi' : 'qs';
  document.getElementById('v-user').className = 'fi mono' + (hasSql(u) ? ' bad' : '');
  document.getElementById('v-pass').className = 'fi mono' + (hasSql(p) ? ' bad' : '');
  document.getElementById('query-display').innerHTML =
    '<span class="kw">SELECT</span> * <span class="kw">FROM</span> users <span class="kw">WHERE</span> username=<span class="' + uCls + '">\'' + uSafe + '\'</span> <span class="kw">AND</span> password=<span class="' + pCls + '">\'' + pSafe + '\'</span>';
}

document.getElementById('v-user').addEventListener('input', renderQuery);
document.getElementById('v-pass').addEventListener('input', renderQuery);
document.getElementById('v-user').addEventListener('keydown', function(e){ if(e.key==='Enter') doVulnLogin(); });
document.getElementById('v-pass').addEventListener('keydown', function(e){ if(e.key==='Enter') doVulnLogin(); });
document.getElementById('p-user').addEventListener('keydown', function(e){ if(e.key==='Enter') doPatchLogin(); });
document.getElementById('p-pass').addEventListener('keydown', function(e){ if(e.key==='Enter') doPatchLogin(); });

function doVulnLogin() {
  var u = document.getElementById('v-user').value;
  var p = document.getElementById('v-pass').value;
  if (!u && !p) return;
  var btn = document.getElementById('sign-in-btn');
  var res = document.getElementById('v-result');
  var fl  = document.getElementById('v-flag');
  var sb  = document.getElementById('vuln-status');
  btn.disabled = true;
  btn.textContent = 'Signing in...';
  sb.textContent = 'Sending POST /api/vulnerable/login...';
  res.style.display = 'none';
  fl.style.display  = 'none';
  recordTry();
  fetch('/api/vulnerable/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  }).then(function(r) {
    sb.textContent = 'POST /api/vulnerable/login  —  HTTP ' + r.status + (r.ok ? ' OK' : ' Unauthorized');
    return r.json().then(function(d) {
      res.style.display = 'block';
      if (d.bypassed) {
        res.innerHTML = '<div class="r-bad"><p style="font-weight:700;color:#dc2626;font-size:13px;">Authentication Bypassed!</p><p style="color:#ef4444;font-size:12px;margin-top:4px;">Logged in as: <strong>' + d.user.username + '</strong> (' + d.user.role + ')</p></div>';
        fl.textContent = 'Flag: ' + d.flag;
        fl.style.display = 'block';
        if (!flagDone) {
          flagDone = true;
          document.getElementById('flags-count').textContent = '1 / 1';
          document.getElementById('flag-progress').style.width = '100%';
        }
      } else if (d.success) {
        res.innerHTML = '<div class="r-ok"><p style="color:#15803d;font-weight:600;font-size:13px;">Logged in as ' + d.user.username + '</p><p style="color:#16a34a;font-size:12px;margin-top:4px;">Role: ' + d.user.role + ' — no flag here though.</p></div>';
      } else {
        res.innerHTML = '<div class="r-fail"><p style="color:#64748b;font-size:13px;">Invalid username or password.</p></div>';
      }
      btn.disabled = false;
      btn.textContent = 'Sign In';
    });
  }).catch(function(e) {
    res.style.display = 'block';
    res.innerHTML = '<div class="r-fail"><p style="color:#64748b;font-size:13px;">Network error: ' + e.message + '</p></div>';
    sb.textContent = 'Request failed';
    btn.disabled = false;
    btn.textContent = 'Sign In';
  });
}

function doPatchLogin() {
  var u = document.getElementById('p-user').value;
  var p = document.getElementById('p-pass').value;
  if (!u && !p) return;
  var sb  = document.getElementById('patch-status');
  var res = document.getElementById('p-result');
  sb.textContent = 'Sending POST /api/patched/login...';
  res.style.display = 'none';
  recordTry();
  fetch('/api/patched/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p })
  }).then(function(r) {
    sb.textContent = 'POST /api/patched/login  —  HTTP ' + r.status + (r.ok ? ' OK' : ' Unauthorized');
    return r.json().then(function(d) {
      res.style.display = 'block';
      if (d.success) {
        res.innerHTML = '<div class="r-ok"><p style="color:#15803d;font-weight:600;font-size:13px;">Logged in as ' + d.user.username + '</p></div>';
      } else {
        res.innerHTML = '<div class="r-fail"><p style="color:#64748b;font-size:13px;">Invalid credentials.<br><span style="font-size:11px;color:#94a3b8;">SQLi payload treated as a literal string — no bypass possible.</span></p></div>';
      }
    });
  }).catch(function(e) {
    res.style.display = 'block';
    res.innerHTML = '<div class="r-fail"><p style="color:#64748b;font-size:13px;">Error: ' + e.message + '</p></div>';
  });
}

function resetVuln() {
  document.getElementById('v-user').value = '';
  document.getElementById('v-pass').value = '';
  document.getElementById('v-user').className = 'fi mono';
  document.getElementById('v-pass').className = 'fi mono';
  document.getElementById('v-result').style.display = 'none';
  document.getElementById('v-flag').style.display = 'none';
  document.getElementById('vuln-status').textContent = 'Waiting for login attempt...';
  document.getElementById('query-display').innerHTML = '<span class="kw">SELECT</span> * <span class="kw">FROM</span> users <span class="kw">WHERE</span> username=<span class="qs">\'?\'</span> <span class="kw">AND</span> password=<span class="qs">\'?\'</span>';
}

function resetPatched() {
  document.getElementById('p-user').value = '';
  document.getElementById('p-pass').value = '';
  document.getElementById('p-result').style.display = 'none';
  document.getElementById('patch-status').textContent = 'Waiting for login attempt...';
}

function revealHint(idx, auto) {
  var body = document.getElementById('hint-body-' + idx);
  if (hintsRevealed[idx]) { body.classList.toggle('open'); return; }
  var cost = hintCosts[idx];
  if (!auto && cost > 0) {
    var rem = MAX_TRIES - tries;
    if (!confirm('This hint costs ' + cost + ' attempt(s).\nYou have ' + rem + ' remaining. Reveal anyway?')) return;
    recordTry(cost);
  }
  hintsRevealed[idx] = true;
  body.classList.add('open');
  var lbl = document.getElementById('hl' + idx);
  if (lbl) lbl.innerHTML = lbl.innerHTML.replace('\u{1F512}', '\u{1F513}').replace('&#128274;', '&#128275;');
  var used = hintsRevealed.filter(Boolean).length;
  document.getElementById('hints-used-label').textContent = used + ' of 4 revealed';
}
<\/script>

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
<\/script>
</body>
</html>`;

  res.send(html);
});

app.listen(PORT, () => console.log('SQLi Lab running on http://localhost:' + PORT));