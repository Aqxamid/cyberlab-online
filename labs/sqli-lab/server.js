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

  // Build page using string concat so Node template vars stay isolated
  // and no </script> inside JS blocks can split the tag
  const page = '<!DOCTYPE html>\n'
  + '<html lang="en">\n'
  + '<head>\n'
  + '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n'
  + '<title>BankSecure \u2014 SQLi Lab</title>\n'
  + '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 32 32\'%3E%3Crect width=\'32\' height=\'32\' rx=\'6\' fill=\'%23dc2626\'/%3E%3Ctext x=\'16\' y=\'23\' font-size=\'17\' text-anchor=\'middle\' fill=\'white\' font-family=\'monospace\' font-weight=\'bold\'%3ESQL%3C/text%3E%3C/svg%3E">\n'
  + '<script src="https://cdn.tailwindcss.com"></s' + 'cript>\n'
  + '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">\n'
  + '<style>\n'
  + '*{box-sizing:border-box;}\n'
  + 'body{font-family:Inter,sans-serif;background:#0f172a;min-height:100vh;}\n'
  + '.mono{font-family:"JetBrains Mono",monospace;}\n'
  + 'pre{background:#0f172a;color:#94a3b8;padding:1rem;border-radius:8px;font-size:.75rem;overflow-x:auto;white-space:pre-wrap;min-height:48px;line-height:1.6;border:1px solid #1e293b;margin:0;}\n'
  + '.flag-box{background:#fef9c3;border:2px solid #eab308;color:#713f12;padding:.75rem 1rem;border-radius:8px;font-family:"JetBrains Mono",monospace;font-weight:700;font-size:.85rem;display:none;margin-top:.75rem;word-break:break-all;}\n'
  + '.fake-browser{border:1px solid #334155;border-radius:10px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.4);}\n'
  + '.b-chrome{background:#1e293b;padding:8px 12px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #334155;}\n'
  + '.tl-row{display:flex;gap:5px;flex-shrink:0;}\n'
  + '.tl{width:11px;height:11px;border-radius:50%;}\n'
  + '.tl-r{background:#ef4444;}.tl-y{background:#f59e0b;}.tl-g{background:#22c55e;}\n'
  + '.nb{background:none;border:none;cursor:default;color:#475569;font-size:15px;padding:1px 5px;border-radius:4px;line-height:1;}\n'
  + '.nb.cl{cursor:pointer;}.nb.cl:hover{background:#334155;color:#94a3b8;}\n'
  + '.url-bar{flex:1;display:flex;align-items:center;background:#0f172a;border:1px solid #334155;border-radius:5px;padding:0 8px;height:28px;gap:5px;}\n'
  + '.url-scheme{font-size:11px;color:#22c55e;font-family:"JetBrains Mono",monospace;flex-shrink:0;font-weight:600;user-select:none;}\n'
  + '.url-text{flex:1;font-size:12px;font-family:"JetBrains Mono",monospace;color:#475569;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;user-select:none;}\n'
  + '.b-status{background:#1e293b;border-top:1px solid #334155;padding:3px 12px;font-size:10.5px;color:#475569;font-family:"JetBrains Mono",monospace;min-height:20px;}\n'
  + '.page-bg{background:linear-gradient(135deg,#1e3a5f 0%,#0f2340 100%);padding:28px 20px;}\n'
  + '.login-card{background:white;border-radius:16px;overflow:hidden;max-width:380px;margin:0 auto;box-shadow:0 20px 48px rgba(0,0,0,.4);}\n'
  + '.card-hdr{background:linear-gradient(135deg,#1e40af,#1e3a8a);padding:24px;text-align:center;}\n'
  + '.fi{width:100%;border:1.5px solid #e2e8f0;border-radius:8px;padding:10px 12px;font-size:13px;font-family:"JetBrains Mono",monospace;outline:none;transition:border-color .15s,box-shadow .15s;color:#1e293b;background:white;display:block;}\n'
  + '.fi:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15);}\n'
  + '.fi.bad{border-color:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,.15);color:#dc2626;}\n'
  + '.si-btn{width:100%;background:#1d4ed8;color:white;border:none;padding:11px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:background .15s;display:block;}\n'
  + '.si-btn:hover{background:#1e40af;}.si-btn:disabled{background:#94a3b8;cursor:not-allowed;}\n'
  + '.kw{color:#c4b5fd;}.qs{color:#86efac;}.qi{color:#f87171;font-weight:600;}\n'
  + '.hint-body{display:none;}.hint-body.open{display:block;}\n'
  + '.ht{width:100%;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;background:none;border:none;cursor:pointer;text-align:left;transition:background .15s;}\n'
  + '.ht:hover{background:rgba(255,255,255,.04);}\n'
  + '.pip{width:10px;height:10px;border-radius:50%;background:#334155;display:inline-block;transition:background .2s;}\n'
  + '.pip.used{background:#ef4444;}.pip.warn{background:#f59e0b;}\n'
  + '.r-ok{background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:12px;}\n'
  + '.r-bad{background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:12px;}\n'
  + '.r-fail{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;}\n'
  + '</style>\n'
  + '</head>\n'
  + '<body>\n'

  // Nav
  + '<nav class="bg-slate-900 border-b border-slate-700 px-6 py-3 flex items-center justify-between">\n'
  + '  <div class="flex items-center gap-3">\n'
  + '    <div style="width:32px;height:32px;background:#dc2626;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:white;font-family:monospace;">SQL</div>\n'
  + '    <span style="font-weight:700;color:white;font-size:1.1rem;">BankSecure</span>\n'
  + '    <span style="color:#64748b;font-size:13px;">Online Banking Portal</span>\n'
  + '    <span style="font-size:11px;background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-weight:600;">SQLi Lab</span>\n'
  + '  </div>\n'
  + '  <div style="font-size:13px;color:#64748b;">Not logged in &mdash; <span style="color:#e2e8f0;font-weight:500;">attempt to bypass</span></div>\n'
  + '</nav>\n'

  + '<div class="max-w-6xl mx-auto px-4 py-6 space-y-5">\n'

  // Objective
  + '<div style="background:#fffbeb;border-left:4px solid #f59e0b;border-radius:12px;padding:16px;display:flex;gap:12px;">\n'
  + '  <span style="font-size:1.5rem;flex-shrink:0;margin-top:2px;">&#127919;</span>\n'
  + '  <div>\n'
  + '    <p style="font-weight:600;color:#92400e;font-size:13px;">SQL Injection Lab &mdash; Objective</p>\n'
  + '    <p style="color:#b45309;font-size:12px;margin-top:4px;line-height:1.6;">This login form builds its SQL query by <strong>concatenating your input directly</strong> into the string &mdash; no sanitization. Your goal: <strong>bypass authentication</strong> without knowing any valid password. Type payloads manually into the fields and watch the live query preview update as you type.</p>\n'
  + '  </div>\n'
  + '</div>\n'

  + '<div class="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">\n'
  + '<div class="xl:col-span-2 space-y-5">\n'

  // Challenge 1
  + '<div>\n'
  + '  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">\n'
  + '    <span style="font-size:13px;font-weight:600;color:#e2e8f0;">Challenge 1 &mdash; Vulnerable Login Form</span>\n'
  + '    <span style="font-size:11px;background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-weight:600;">VULNERABLE</span>\n'
  + '  </div>\n'
  + '  <div class="fake-browser">\n'
  + '    <div class="b-chrome">\n'
  + '      <div class="tl-row"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>\n'
  + '      <div style="display:flex;gap:3px;">\n'
  + '        <button class="nb">&#8592;</button>\n'
  + '        <button class="nb">&#8594;</button>\n'
  + '        <button class="nb cl" title="Reset" id="reset-vuln-btn">&#8635;</button>\n'
  + '      </div>\n'
  + '      <div class="url-bar">\n'
  + '        <span style="font-size:11px;color:#22c55e;flex-shrink:0;">&#128274;</span>\n'
  + '        <span class="url-scheme">https://</span>\n'
  + '        <span class="url-text">banksecure.internal/login</span>\n'
  + '      </div>\n'
  + '    </div>\n'
  + '    <div class="page-bg">\n'
  + '      <div class="login-card">\n'
  + '        <div class="card-hdr">\n'
  + '          <div style="width:48px;height:48px;background:rgba(255,255,255,.2);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:24px;">&#127963;</div>\n'
  + '          <h1 style="color:white;font-weight:700;font-size:1.1rem;">BankSecure</h1>\n'
  + '          <p style="color:#93c5fd;font-size:11px;margin-top:4px;">Online Banking Portal</p>\n'
  + '          <span style="display:inline-block;margin-top:8px;font-size:11px;background:#ef4444;color:white;padding:2px 8px;border-radius:4px;font-weight:600;">VULNERABLE</span>\n'
  + '        </div>\n'
  + '        <div style="padding:24px;">\n'
  + '          <div style="margin-bottom:14px;">\n'
  + '            <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Username</label>\n'
  + '            <input id="v-user" type="text" placeholder="Enter username..." class="fi mono" autocomplete="off" spellcheck="false">\n'
  + '          </div>\n'
  + '          <div style="margin-bottom:16px;">\n'
  + '            <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Password</label>\n'
  + '            <input id="v-pass" type="text" placeholder="Enter password..." class="fi mono" autocomplete="off" spellcheck="false">\n'
  + '          </div>\n'
  + '          <button id="sign-in-btn" class="si-btn">Sign In</button>\n'
  + '          <div id="v-result" style="display:none;margin-top:12px;"></div>\n'
  + '          <div id="v-flag" class="flag-box"></div>\n'
  + '        </div>\n'
  + '      </div>\n'
  + '    </div>\n'
  + '    <div class="b-status" id="vuln-status">Waiting for login attempt...</div>\n'
  + '  </div>\n'
  + '  <p style="font-size:11px;color:#475569;font-family:monospace;margin-top:6px;padding-left:4px;">&#8593; Type directly into the fields &mdash; what happens when you include SQL characters like &apos; or --</p>\n'
  + '</div>\n'

  // Live query panel
  + '<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">\n'
  + '  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">\n'
  + '    <span style="font-size:12px;font-weight:600;color:#cbd5e1;">&#128269; Live SQL Query Preview</span>\n'
  + '    <span style="font-size:11px;color:#475569;">(updates as you type)</span>\n'
  + '  </div>\n'
  + '  <pre id="query-display"><span class="kw">SELECT</span> * <span class="kw">FROM</span> users <span class="kw">WHERE</span> username=<span class="qs">\'?\'</span> <span class="kw">AND</span> password=<span class="qs">\'?\'</span></pre>\n'
  + '  <p style="font-size:11px;color:#475569;margin-top:8px;">Your input is inserted raw &mdash; can you break out of the string quotes?</p>\n'
  + '</div>\n'

  // Challenge 2
  + '<div>\n'
  + '  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">\n'
  + '    <span style="font-size:13px;font-weight:600;color:#e2e8f0;">Challenge 2 &mdash; Patched Login (Parameterized Query)</span>\n'
  + '    <span style="font-size:11px;background:#14532d;color:#86efac;padding:2px 8px;border-radius:4px;font-weight:600;">FIXED</span>\n'
  + '  </div>\n'
  + '  <div class="fake-browser">\n'
  + '    <div class="b-chrome">\n'
  + '      <div class="tl-row"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>\n'
  + '      <div style="display:flex;gap:3px;">\n'
  + '        <button class="nb">&#8592;</button>\n'
  + '        <button class="nb">&#8594;</button>\n'
  + '        <button class="nb cl" title="Reset" id="reset-patch-btn">&#8635;</button>\n'
  + '      </div>\n'
  + '      <div class="url-bar">\n'
  + '        <span style="font-size:11px;color:#22c55e;flex-shrink:0;">&#128274;</span>\n'
  + '        <span class="url-scheme">https://</span>\n'
  + '        <span class="url-text">banksecure.internal/login?version=patched</span>\n'
  + '      </div>\n'
  + '    </div>\n'
  + '    <div class="page-bg" style="background:linear-gradient(135deg,#14532d 0%,#052e16 100%);">\n'
  + '      <div class="login-card">\n'
  + '        <div class="card-hdr" style="background:linear-gradient(135deg,#166534,#14532d);">\n'
  + '          <div style="width:48px;height:48px;background:rgba(255,255,255,.2);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:24px;">&#128274;</div>\n'
  + '          <h1 style="color:white;font-weight:700;font-size:1.1rem;">BankSecure</h1>\n'
  + '          <p style="color:#86efac;font-size:11px;margin-top:4px;">Secured Login &mdash; v2</p>\n'
  + '          <span style="display:inline-block;margin-top:8px;font-size:11px;background:#16a34a;color:white;padding:2px 8px;border-radius:4px;font-weight:600;">PATCHED</span>\n'
  + '        </div>\n'
  + '        <div style="padding:24px;">\n'
  + '          <p style="font-size:12px;color:#6b7280;background:#f9fafb;border-radius:8px;padding:10px 12px;margin-bottom:16px;line-height:1.6;">Uses <strong>parameterized queries</strong> &mdash; input is never concatenated into SQL. Try the same payloads.</p>\n'
  + '          <div style="margin-bottom:14px;">\n'
  + '            <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Username</label>\n'
  + '            <input id="p-user" type="text" placeholder="Enter username..." class="fi mono" autocomplete="off" spellcheck="false">\n'
  + '          </div>\n'
  + '          <div style="margin-bottom:16px;">\n'
  + '            <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Password</label>\n'
  + '            <input id="p-pass" type="text" placeholder="Enter password..." class="fi mono" autocomplete="off" spellcheck="false">\n'
  + '          </div>\n'
  + '          <button id="patch-btn" class="si-btn" style="background:#16a34a;">Sign In</button>\n'
  + '          <div id="p-result" style="display:none;margin-top:12px;"></div>\n'
  + '        </div>\n'
  + '      </div>\n'
  + '    </div>\n'
  + '    <div class="b-status" id="patch-status">Waiting for login attempt...</div>\n'
  + '  </div>\n'
  + '  <p style="font-size:11px;color:#475569;font-family:monospace;margin-top:6px;padding-left:4px;">&#8593; Try the exact same payload &mdash; notice the difference</p>\n'
  + '</div>\n'

  + '</div>\n' // end left col

  // Sidebar
  + '<div class="space-y-4">\n'

  // Attempt counter
  + '<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">\n'
  + '  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">\n'
  + '    <span style="font-size:14px;font-weight:600;color:#e2e8f0;">Attempts</span>\n'
  + '    <span id="tries-text" style="font-size:12px;color:#64748b;font-family:monospace;">0 / 10</span>\n'
  + '  </div>\n'
  + '  <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px;" id="pip-row"></div>\n'
  + '  <p style="font-size:12px;color:#64748b;line-height:1.6;">Each login attempt counts. After <strong style="color:#94a3b8;">5 attempts</strong> a hint auto-unlocks.</p>\n'
  + '  <div style="margin-top:12px;padding-top:12px;border-top:1px solid #334155;">\n'
  + '    <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">\n'
  + '      <span style="color:#64748b;">Flag captured</span>\n'
  + '      <span id="flags-count" style="font-weight:700;color:#4ade80;">0 / 1</span>\n'
  + '    </div>\n'
  + '    <div style="width:100%;background:#334155;border-radius:9999px;height:8px;">\n'
  + '      <div id="flag-progress" style="background:#22c55e;height:8px;border-radius:9999px;width:0%;transition:width .5s;"></div>\n'
  + '    </div>\n'
  + '  </div>\n'
  + '</div>\n'

  // Hints
  + '<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;overflow:hidden;">\n'
  + '  <div style="background:rgba(120,53,15,.3);border-bottom:1px solid rgba(180,83,9,.4);padding:10px 16px;display:flex;align-items:center;justify-content:space-between;">\n'
  + '    <div style="display:flex;align-items:center;gap:8px;"><span>&#128161;</span><span style="font-size:14px;font-weight:600;color:#fbbf24;">Hints</span></div>\n'
  + '    <span id="hints-used-label" style="font-size:11px;background:rgba(120,53,15,.4);color:#fbbf24;padding:2px 8px;border-radius:4px;">0 of 4 revealed</span>\n'
  + '  </div>\n'
  + '  <div style="border-bottom:1px solid #334155;">\n'
  + '    <button class="ht" id="hbtn0"><span id="hl0" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; What is SQL injection?</span><span style="font-size:11px;background:rgba(21,128,61,.3);color:#4ade80;padding:2px 8px;border-radius:4px;">free</span></button>\n'
  + '    <div class="hint-body" id="hint-body-0" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">SQL injection happens when user input is inserted <em>directly</em> into a query string. By including characters like <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">\'</code> or <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">--</code> you can change the logic of the query itself.</div>\n'
  + '  </div>\n'
  + '  <div style="border-bottom:1px solid #334155;">\n'
  + '    <button class="ht" id="hbtn1"><span id="hl1" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; Breaking out of the query</span><span style="font-size:11px;background:rgba(120,53,15,.3);color:#fbbf24;padding:2px 8px;border-radius:4px;">&#8722;1 attempt</span></button>\n'
  + '    <div class="hint-body" id="hint-body-1" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">The query looks like: <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">WHERE username=\'YOUR_INPUT\'</code>. If you type a <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">\'</code>, you close that string early. What could you add after it to make the condition always true?</div>\n'
  + '  </div>\n'
  + '  <div style="border-bottom:1px solid #334155;">\n'
  + '    <button class="ht" id="hbtn2"><span id="hl2" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; Always-true condition</span><span style="font-size:11px;background:rgba(127,29,29,.3);color:#f87171;padding:2px 8px;border-radius:4px;">&#8722;2 attempts</span></button>\n'
  + '    <div class="hint-body" id="hint-body-2" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">After closing the quote, add an <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">OR</code> clause that is always true like <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">1=1</code>. Then use <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">--</code> to comment out the rest including the password check.</div>\n'
  + '  </div>\n'
  + '  <div>\n'
  + '    <button class="ht" id="hbtn3"><span id="hl3" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; Exact payload structure</span><span style="font-size:11px;background:rgba(127,29,29,.3);color:#f87171;padding:2px 8px;border-radius:4px;">&#8722;2 attempts</span></button>\n'
  + '    <div class="hint-body" id="hint-body-3" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">Put this in the <strong style="color:#e2e8f0;">username</strong> field, anything in password:<br><code style="display:block;background:#0f172a;color:#4ade80;padding:6px 10px;border-radius:6px;margin-top:8px;font-size:12px;">\' OR 1=1--</code>The <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">\'</code> closes the string, <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">OR 1=1</code> makes it always true, <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">--</code> kills the password check.</div>\n'
  + '  </div>\n'
  + '</div>\n'

  // Observe
  + '<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">\n'
  + '  <p style="font-size:12px;font-weight:600;color:#cbd5e1;margin-bottom:8px;">&#128270; Things to observe</p>\n'
  + '  <ul style="font-size:12px;color:#64748b;line-height:2;">\n'
  + '    <li>&#10140; Watch the live query as you type</li>\n'
  + '    <li>&#10140; What does a <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#94a3b8;">\'</code> do to the query?</li>\n'
  + '    <li>&#10140; Try the same payload on the patched form</li>\n'
  + '    <li>&#10140; Why doesn\'t the patched version reflect your input?</li>\n'
  + '  </ul>\n'
  + '</div>\n'

  + '</div>\n' // end sidebar
  + '</div>\n' // end grid
  + '</div>\n' // end max-w

  // Single script block — no template vars, no closing tag conflicts
  + '<script>\n'
  + 'var MAX_TRIES = 10;\n'
  + 'var AUTO_HINT = 5;\n'
  + 'var tries = 0;\n'
  + 'var flagDone = false;\n'
  + 'var hintsRevealed = [false,false,false,false];\n'
  + 'var hintCosts = [0,1,2,2];\n'
  + '\n'
  + 'function renderPips(){\n'
  + '  var row = document.getElementById("pip-row");\n'
  + '  row.innerHTML = "";\n'
  + '  for(var i=0;i<MAX_TRIES;i++){\n'
  + '    var d = document.createElement("div");\n'
  + '    var used = i < tries;\n'
  + '    var warn = used && (tries-i <= 2);\n'
  + '    d.className = "pip"+(used?(warn?" warn":" used"):"");\n'
  + '    row.appendChild(d);\n'
  + '  }\n'
  + '  document.getElementById("tries-text").textContent = tries+" / "+MAX_TRIES;\n'
  + '}\n'
  + '\n'
  + 'function recordTry(cost){\n'
  + '  cost = cost||1;\n'
  + '  tries = Math.min(MAX_TRIES, tries+cost);\n'
  + '  renderPips();\n'
  + '  if(tries >= AUTO_HINT && !hintsRevealed[1]) revealHint(1,true);\n'
  + '}\n'
  + '\n'
  + 'renderPips();\n'
  + '\n'
  + 'function escHtml(s){\n'
  + '  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");\n'
  + '}\n'
  + '\n'
  + 'function hasSql(s){ return /[\'";\\-]/.test(s); }\n'
  + '\n'
  + 'function renderQuery(){\n'
  + '  var u = document.getElementById("v-user").value;\n'
  + '  var p = document.getElementById("v-pass").value;\n'
  + '  var uCls = hasSql(u)?"qi":"qs";\n'
  + '  var pCls = hasSql(p)?"qi":"qs";\n'
  + '  document.getElementById("v-user").className = "fi mono"+(hasSql(u)?" bad":"");\n'
  + '  document.getElementById("v-pass").className = "fi mono"+(hasSql(p)?" bad":"");\n'
  + '  document.getElementById("query-display").innerHTML =\n'
  + '    \'<span class="kw">SELECT</span> * <span class="kw">FROM</span> users \'\n'
  + '    +\'<span class="kw">WHERE</span> username=<span class="\'+uCls+\'">\\\'\'+ escHtml(u) +\'\\\'</span> \'\n'
  + '    +\'<span class="kw">AND</span> password=<span class="\'+pCls+\'">\\\'\'+ escHtml(p) +\'\\\'</span>\';\n'
  + '}\n'
  + '\n'
  + 'document.getElementById("v-user").addEventListener("input",renderQuery);\n'
  + 'document.getElementById("v-pass").addEventListener("input",renderQuery);\n'
  + 'document.getElementById("v-user").addEventListener("keydown",function(e){if(e.key==="Enter")doVulnLogin();});\n'
  + 'document.getElementById("v-pass").addEventListener("keydown",function(e){if(e.key==="Enter")doVulnLogin();});\n'
  + 'document.getElementById("p-user").addEventListener("keydown",function(e){if(e.key==="Enter")doPatchLogin();});\n'
  + 'document.getElementById("p-pass").addEventListener("keydown",function(e){if(e.key==="Enter")doPatchLogin();});\n'
  + 'document.getElementById("sign-in-btn").addEventListener("click",doVulnLogin);\n'
  + 'document.getElementById("patch-btn").addEventListener("click",doPatchLogin);\n'
  + 'document.getElementById("reset-vuln-btn").addEventListener("click",resetVuln);\n'
  + 'document.getElementById("reset-patch-btn").addEventListener("click",resetPatched);\n'
  + '\n'
  + 'function doVulnLogin(){\n'
  + '  var u = document.getElementById("v-user").value;\n'
  + '  var p = document.getElementById("v-pass").value;\n'
  + '  if(!u && !p) return;\n'
  + '  var btn = document.getElementById("sign-in-btn");\n'
  + '  var res = document.getElementById("v-result");\n'
  + '  var fl  = document.getElementById("v-flag");\n'
  + '  var sb  = document.getElementById("vuln-status");\n'
  + '  btn.disabled = true; btn.textContent = "Signing in...";\n'
  + '  sb.textContent = "Sending POST /api/vulnerable/login...";\n'
  + '  res.style.display = "none"; fl.style.display = "none";\n'
  + '  recordTry();\n'
  + '  fetch("/api/vulnerable/login",{\n'
  + '    method:"POST",\n'
  + '    headers:{"Content-Type":"application/json"},\n'
  + '    body:JSON.stringify({username:u,password:p})\n'
  + '  }).then(function(r){\n'
  + '    sb.textContent = "POST /api/vulnerable/login  \u2014  HTTP "+r.status+(r.ok?" OK":" Unauthorized");\n'
  + '    return r.json().then(function(d){\n'
  + '      res.style.display = "block";\n'
  + '      if(d.bypassed){\n'
  + '        res.innerHTML = \'<div class="r-bad"><p style="font-weight:700;color:#dc2626;font-size:13px;">Authentication Bypassed!</p><p style="color:#ef4444;font-size:12px;margin-top:4px;">Logged in as: <strong>\'+d.user.username+\'</strong> (\'+d.user.role+\')</p></div>\';\n'
  + '        fl.textContent = "Flag: "+d.flag;\n'
  + '        fl.style.display = "block";\n'
  + '        if(!flagDone){ flagDone=true; document.getElementById("flags-count").textContent="1 / 1"; document.getElementById("flag-progress").style.width="100%"; }\n'
  + '      } else if(d.success){\n'
  + '        res.innerHTML = \'<div class="r-ok"><p style="color:#15803d;font-weight:600;font-size:13px;">Logged in as \'+d.user.username+\'</p><p style="color:#16a34a;font-size:12px;margin-top:4px;">Role: \'+d.user.role+\' \u2014 no flag here though.</p></div>\';\n'
  + '      } else {\n'
  + '        res.innerHTML = \'<div class="r-fail"><p style="color:#64748b;font-size:13px;">Invalid username or password.</p></div>\';\n'
  + '      }\n'
  + '      btn.disabled=false; btn.textContent="Sign In";\n'
  + '    });\n'
  + '  }).catch(function(e){\n'
  + '    res.style.display="block";\n'
  + '    res.innerHTML=\'<div class="r-fail"><p style="color:#64748b;font-size:13px;">Network error: \'+e.message+\'</p></div>\';\n'
  + '    sb.textContent="Request failed";\n'
  + '    btn.disabled=false; btn.textContent="Sign In";\n'
  + '  });\n'
  + '}\n'
  + '\n'
  + 'function doPatchLogin(){\n'
  + '  var u = document.getElementById("p-user").value;\n'
  + '  var p = document.getElementById("p-pass").value;\n'
  + '  if(!u && !p) return;\n'
  + '  var sb  = document.getElementById("patch-status");\n'
  + '  var res = document.getElementById("p-result");\n'
  + '  sb.textContent = "Sending POST /api/patched/login...";\n'
  + '  res.style.display = "none";\n'
  + '  recordTry();\n'
  + '  fetch("/api/patched/login",{\n'
  + '    method:"POST",\n'
  + '    headers:{"Content-Type":"application/json"},\n'
  + '    body:JSON.stringify({username:u,password:p})\n'
  + '  }).then(function(r){\n'
  + '    sb.textContent = "POST /api/patched/login  \u2014  HTTP "+r.status+(r.ok?" OK":" Unauthorized");\n'
  + '    return r.json().then(function(d){\n'
  + '      res.style.display = "block";\n'
  + '      if(d.success){\n'
  + '        res.innerHTML = \'<div class="r-ok"><p style="color:#15803d;font-weight:600;font-size:13px;">Logged in as \'+d.user.username+\'</p></div>\';\n'
  + '      } else {\n'
  + '        res.innerHTML = \'<div class="r-fail"><p style="color:#64748b;font-size:13px;">Invalid credentials.<br><span style="font-size:11px;color:#94a3b8;">SQLi payload treated as literal string \u2014 no bypass possible.</span></p></div>\';\n'
  + '      }\n'
  + '    });\n'
  + '  }).catch(function(e){\n'
  + '    res.style.display="block";\n'
  + '    res.innerHTML=\'<div class="r-fail"><p style="color:#64748b;font-size:13px;">Error: \'+e.message+\'</p></div>\';\n'
  + '  });\n'
  + '}\n'
  + '\n'
  + 'function resetVuln(){\n'
  + '  document.getElementById("v-user").value="";\n'
  + '  document.getElementById("v-pass").value="";\n'
  + '  document.getElementById("v-user").className="fi mono";\n'
  + '  document.getElementById("v-pass").className="fi mono";\n'
  + '  document.getElementById("v-result").style.display="none";\n'
  + '  document.getElementById("v-flag").style.display="none";\n'
  + '  document.getElementById("vuln-status").textContent="Waiting for login attempt...";\n'
  + '  document.getElementById("query-display").innerHTML=\'<span class="kw">SELECT</span> * <span class="kw">FROM</span> users <span class="kw">WHERE</span> username=<span class="qs">\\\'?\\\'</span> <span class="kw">AND</span> password=<span class="qs">\\\'?\\\'</span>\';\n'
  + '}\n'
  + '\n'
  + 'function resetPatched(){\n'
  + '  document.getElementById("p-user").value="";\n'
  + '  document.getElementById("p-pass").value="";\n'
  + '  document.getElementById("p-result").style.display="none";\n'
  + '  document.getElementById("patch-status").textContent="Waiting for login attempt...";\n'
  + '}\n'
  + '\n'
  + 'function revealHint(idx,auto){\n'
  + '  var body = document.getElementById("hint-body-"+idx);\n'
  + '  if(hintsRevealed[idx]){ body.classList.toggle("open"); return; }\n'
  + '  var cost = hintCosts[idx];\n'
  + '  if(!auto && cost>0){\n'
  + '    var rem = MAX_TRIES-tries;\n'
  + '    if(!confirm("This hint costs "+cost+" attempt(s).\\nYou have "+rem+" remaining. Reveal anyway?")) return;\n'
  + '    recordTry(cost);\n'
  + '  }\n'
  + '  hintsRevealed[idx]=true;\n'
  + '  body.classList.add("open");\n'
  + '  var lbl = document.getElementById("hl"+idx);\n'
  + '  if(lbl) lbl.innerHTML = lbl.innerHTML.replace("&#128274;","&#128275;");\n'
  + '  document.getElementById("hints-used-label").textContent = hintsRevealed.filter(Boolean).length+" of 4 revealed";\n'
  + '}\n'
  + '\n'
  + 'document.getElementById("hbtn0").addEventListener("click",function(){revealHint(0);});\n'
  + 'document.getElementById("hbtn1").addEventListener("click",function(){revealHint(1);});\n'
  + 'document.getElementById("hbtn2").addEventListener("click",function(){revealHint(2);});\n'
  + 'document.getElementById("hbtn3").addEventListener("click",function(){revealHint(3);});\n'
  + '</' + 'script>\n'

  // Auth recheck — Node vars injected here, separate from the JS above
  + '<script>\n'
  + '(function(){\n'
  + '  var token    = new URLSearchParams(window.location.search).get("token");\n'
  + '  var BACKEND  = "' + backendUrl + '";\n'
  + '  var FRONTEND = "' + frontendUrl + '";\n'
  + '  function recheck(){\n'
  + '    if(!token){ window.location.href=FRONTEND+"/login.html"; return; }\n'
  + '    fetch(BACKEND+"/api/auth/me",{headers:{"Authorization":"Bearer "+token}})\n'
  + '      .then(function(r){ if(!r.ok) window.location.href=FRONTEND+"/login.html"; })\n'
  + '      .catch(function(){});\n'
  + '  }\n'
  + '  setTimeout(function loop(){ recheck(); setTimeout(loop,5000); },5000);\n'
  + '})();\n'
  + '</' + 'script>\n'
  + '</body>\n</html>';

  res.send(page);
});

app.listen(PORT, () => console.log('SQLi Lab running on http://localhost:' + PORT));