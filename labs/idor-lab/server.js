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
  } catch (err) { console.warn('[idor-lab] Backend unreachable:', err.message); }
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
  1:  { id:1,  owner_id:1,  title:'Q1 Report',      content:"Alice's Q1 review. Rating: 4/5.",         classification:'internal' },
  2:  { id:2,  owner_id:2,  title:'Project Roadmap', content:"Bob's engineering roadmap for 2025.",      classification:'internal' },
  3:  { id:3,  owner_id:3,  title:'Campaign Brief',  content:"Charlie's marketing campaign brief.",      classification:'internal' },
  42: { id:42, owner_id:99, title:'Admin Credentials', content:'CONFIDENTIAL -- FLAG{idor_is_dangerous_123}', classification:'top-secret' },
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
  res.send(buildPage(BACKEND_URL, FRONTEND_URL));
});

app.listen(PORT, () => console.log('IDOR Lab running on http://localhost:' + PORT));


function buildPage(backendUrl, frontendUrl) {
  var js = "\nvar MAX_TRIES       = 10;\nvar AUTO_HINT       = 5;\nvar MAX_SCORE       = 100;\nvar SCORE_FLOOR     = 20;\nvar LAB_SLUG        = 'idor-basics';\nvar HINT_DEDUCTIONS = [0, 5, 20, 25];\nvar ATTEMPT_COST    = 1;\nvar BACKEND_URL_VAR = '__BACKEND__';\n\nvar tries         = 0;\nvar flagCaptured  = false;\nvar hintsRevealed = [false, false, false, false];\nvar totalDeducted = 0;\n\nfunction currentScore() {\n  return Math.max(SCORE_FLOOR, MAX_SCORE - totalDeducted);\n}\n\nfunction updateScoreUI() {\n  document.getElementById('score-val').textContent = currentScore();\n  var dedEl = document.getElementById('score-deduction');\n  if (totalDeducted > 0) {\n    dedEl.style.display = 'block';\n    dedEl.textContent   = '-' + totalDeducted + ' pts deducted';\n  } else {\n    dedEl.style.display = 'none';\n  }\n  var prev = document.getElementById('submit-score-preview');\n  if (prev) prev.textContent = currentScore();\n}\n\nfunction renderPips() {\n  var row = document.getElementById('pip-row');\n  row.innerHTML = '';\n  for (var i = 0; i < MAX_TRIES; i++) {\n    var d = document.createElement('div');\n    var used = i < tries;\n    var warn = used && (tries - i <= 2);\n    d.className = 'pip' + (used ? (warn ? ' warn' : ' used') : '');\n    row.appendChild(d);\n  }\n  document.getElementById('tries-text').textContent = tries + ' / ' + MAX_TRIES;\n}\n\nfunction recordTry() {\n  tries = Math.min(MAX_TRIES, tries + 1);\n  totalDeducted = Math.min(MAX_SCORE - SCORE_FLOOR, totalDeducted + ATTEMPT_COST);\n  updateScoreUI();\n  renderPips();\n  if (tries >= AUTO_HINT && !hintsRevealed[1]) revealHint(1, true);\n}\n\nrenderPips();\n\nfunction parseFakeUrl(raw) {\n  var s = raw.trim().replace(/^https?:\\/\\//i, '');\n  var slash = s.indexOf('/');\n  return slash === -1 ? null : s.slice(slash);\n}\n\nfunction hl(json) {\n  return json.replace(/(\"[^\"\\\\]*\"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(\\.\\d*)?)/g, function(m) {\n    if (/^\"/.test(m)) {\n      if (/:$/.test(m)) return '<span style=\"color:#7dd3fc\">' + m + '</span>';\n      return '<span style=\"color:#86efac\">' + m + '</span>';\n    }\n    if (/true|false/.test(m)) return '<span style=\"color:#fdba74\">' + m + '</span>';\n    if (/null/.test(m))       return '<span style=\"color:#f87171\">' + m + '</span>';\n    return '<span style=\"color:#c4b5fd\">' + m + '</span>';\n  });\n}\n\nfunction showCompletionBanner(pts) {\n  var score = pts !== undefined ? pts : currentScore();\n  var banner = document.getElementById('completion-banner');\n  banner.style.display = 'block';\n  document.getElementById('banner-score').textContent = score;\n  var dedEl = document.getElementById('banner-deductions');\n  if (totalDeducted > 0) {\n    dedEl.textContent   = '-' + totalDeducted + ' pts deducted (hints + attempts)';\n    dedEl.style.display = 'block';\n  }\n  banner.scrollIntoView({ behavior: 'smooth', block: 'start' });\n}\n\nfunction doFetch(apiPath, ids, headers) {\n  headers = headers || {};\n  var out         = document.getElementById(ids.outId);\n  var flagEl      = document.getElementById(ids.flagId);\n  var pathDisp    = document.getElementById(ids.pathDisplayId);\n  var httpBadge   = document.getElementById(ids.httpBadgeId);\n  var statusBar   = document.getElementById(ids.statusBarId);\n  var statusBadge = document.getElementById(ids.statusBadgeId);\n\n  pathDisp.textContent    = apiPath;\n  statusBar.textContent   = 'Connecting...';\n  statusBadge.textContent = 'Loading...';\n  out.innerHTML           = '// Sending request...';\n  httpBadge.className     = 'http-badge';\n  httpBadge.textContent   = '';\n  flagEl.style.display    = 'none';\n\n  recordTry();\n\n  fetch(apiPath, { headers: headers })\n    .then(function(r) {\n      return r.json().then(function(data) {\n        var body = JSON.stringify(data, null, 2);\n        out.innerHTML           = hl(body);\n        httpBadge.textContent   = r.status;\n        httpBadge.className     = 'http-badge http-' + r.status;\n        statusBar.textContent   = apiPath + '  --  HTTP ' + r.status + (r.ok ? ' OK' : ' Error');\n        statusBadge.textContent = r.status + (r.ok ? ' OK' : ' Error');\n\n        var match = body.match(/FLAG\\{[^}]+\\}/);\n        if (match && !flagCaptured) {\n          flagCaptured = true;\n          flagEl.textContent   = 'Flag found: ' + match[0];\n          flagEl.style.display = 'block';\n          document.getElementById('flags-count').textContent = '1 / 1';\n          document.getElementById('flag-progress').style.width = '100%';\n          // winning attempt is free -- reverse its cost\n          totalDeducted = Math.max(0, totalDeducted - ATTEMPT_COST);\n          updateScoreUI();\n          // show submit box pre-filled\n          document.getElementById('flag-input').value = match[0];\n          document.getElementById('flag-submit-section').style.display = 'block';\n          document.getElementById('flag-submit-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });\n        }\n      });\n    })\n    .catch(function(e) {\n      out.innerHTML           = '// Network error: ' + e.message;\n      statusBar.textContent   = 'Request failed';\n      statusBadge.textContent = 'Error';\n    });\n}\n\nfunction fetchFromUrl(which) {\n  var inputId = which === 'user' ? 'url-user' : 'url-doc';\n  var path = parseFakeUrl(document.getElementById(inputId).value);\n  if (!path || path.indexOf('/api/') !== 0) {\n    var outId = which === 'user' ? 'user-out' : 'doc-out';\n    document.getElementById(outId).textContent = '// Invalid URL -- edit the path above and press Enter';\n    return;\n  }\n  if (which === 'user') {\n    doFetch(path, { outId:'user-out', flagId:'user-flag', pathDisplayId:'user-path-display', httpBadgeId:'user-http-badge', statusBarId:'user-status-bar', statusBadgeId:'user-status-badge' });\n  } else {\n    doFetch(path, { outId:'doc-out', flagId:'doc-flag', pathDisplayId:'doc-path-display', httpBadgeId:'doc-http-badge', statusBarId:'doc-status-bar', statusBadgeId:'doc-status-badge' });\n  }\n}\n\nfunction fetchPatched() {\n  var path  = parseFakeUrl(document.getElementById('url-patched').value);\n  var myId  = document.getElementById('patch-userid').value;\n  var out   = document.getElementById('patch-out');\n  var badge = document.getElementById('patch-http-badge');\n  var pathD = document.getElementById('patch-path-display');\n  var sb    = document.getElementById('patch-status-bar');\n  if (!path || path.indexOf('/api/') !== 0) { out.textContent = '// Invalid URL -- edit the path above'; return; }\n  pathD.textContent = path;\n  out.innerHTML     = '// Sending with x-user-id: ' + myId + '...';\n  badge.className   = 'http-badge';\n  badge.textContent = '';\n  recordTry();\n  fetch(path, { headers: { 'x-user-id': myId } })\n    .then(function(r) {\n      return r.json().then(function(data) {\n        var body = JSON.stringify(data, null, 2);\n        out.innerHTML     = hl(body);\n        badge.textContent = r.status;\n        badge.className   = 'http-badge http-' + r.status;\n        sb.textContent    = path + '  --  HTTP ' + r.status + '  (x-user-id: ' + myId + ')';\n      });\n    })\n    .catch(function(e) { out.innerHTML = '// Error: ' + e.message; sb.textContent = 'Request failed'; });\n}\n\nfunction revealHint(idx, auto) {\n  var body = document.getElementById('hint-body-' + idx);\n  if (hintsRevealed[idx]) { body.classList.toggle('open'); return; }\n  var cost = HINT_DEDUCTIONS[idx];\n  if (!auto && cost > 0) {\n    if (!confirm('This hint costs ' + cost + ' points. Current score: ' + currentScore() + ' pts. Reveal anyway?')) return;\n  }\n  hintsRevealed[idx] = true;\n  totalDeducted = Math.min(MAX_SCORE - SCORE_FLOOR, totalDeducted + cost);\n  body.classList.add('open');\n  updateScoreUI();\n  var lbl = document.getElementById('hl' + idx);\n  if (lbl) lbl.innerHTML = lbl.innerHTML.replace('&#128274;', '&#128275;');\n  document.getElementById('hints-used-label').textContent = hintsRevealed.filter(Boolean).length + ' of 4 revealed';\n}\n\ndocument.getElementById('url-user').addEventListener('keydown', function(e) { if (e.key === 'Enter') fetchFromUrl('user'); });\ndocument.getElementById('go-user').addEventListener('click', function() { fetchFromUrl('user'); });\ndocument.getElementById('reload-user').addEventListener('click', function() { fetchFromUrl('user'); });\ndocument.getElementById('url-doc').addEventListener('keydown', function(e) { if (e.key === 'Enter') fetchFromUrl('doc'); });\ndocument.getElementById('go-doc').addEventListener('click', function() { fetchFromUrl('doc'); });\ndocument.getElementById('reload-doc').addEventListener('click', function() { fetchFromUrl('doc'); });\ndocument.getElementById('url-patched').addEventListener('keydown', function(e) { if (e.key === 'Enter') fetchPatched(); });\ndocument.getElementById('go-patched').addEventListener('click', function() { fetchPatched(); });\ndocument.getElementById('reload-patched').addEventListener('click', function() { fetchPatched(); });\ndocument.getElementById('hint-btn-0').addEventListener('click', function() { revealHint(0); });\ndocument.getElementById('hint-btn-1').addEventListener('click', function() { revealHint(1); });\ndocument.getElementById('hint-btn-2').addEventListener('click', function() { revealHint(2); });\ndocument.getElementById('hint-btn-3').addEventListener('click', function() { revealHint(3); });\n\ndocument.getElementById('submit-flag-btn').addEventListener('click', function() {\n  var flag  = document.getElementById('flag-input').value.trim();\n  if (!flag) return;\n  var btn   = document.getElementById('submit-flag-btn');\n  var token = new URLSearchParams(window.location.search).get('token');\n  if (!token) return;\n  btn.disabled = true;\n  btn.textContent = 'Submitting...';\n  fetch(BACKEND_URL_VAR + '/api/labs/' + LAB_SLUG + '/attempt', {\n    method:  'POST',\n    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },\n    body:    JSON.stringify({\n      flag:           flag,\n      hints_used:     totalDeducted,\n      attempts_count: tries\n    })\n  })\n  .then(function(r) { return r.json(); })\n  .then(function(d) {\n    if (d.correct) {\n      document.getElementById('flag-submit-section').style.display = 'none';\n      showCompletionBanner(d.points_earned);\n    } else {\n      btn.disabled = false;\n      btn.textContent = 'Submit Flag';\n      alert(d.message || 'Wrong flag.');\n    }\n  })\n  .catch(function() {\n    btn.disabled = false;\n    btn.textContent = 'Submit Flag';\n  });\n});\n".replace('__BACKEND__', backendUrl);
  var favicon = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%231d4ed8'/%3E%3Ccircle cx='13' cy='13' r='5' fill='none' stroke='white' stroke-width='2.5'/%3E%3Cline x1='17' y1='17' x2='23' y2='23' stroke='white' stroke-width='2.5' stroke-linecap='round'/%3E%3Crect x='7' y='20' width='8' height='6' rx='1.5' fill='white' opacity='0.9'/%3E%3Crect x='10' y='18.5' width='2' height='3' rx='1' fill='white'/%3E%3C/svg%3E";

  return '<!DOCTYPE html>\n'
  + '<html lang="en"><head>\n'
  + '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n'
  + '<title>CorpPortal -- IDOR Lab</title>\n'
  + '<link rel="icon" type="image/svg+xml" href="' + favicon + '">\n'
  + '<script src="https://cdn.tailwindcss.com"><' + '/script>\n'
  + '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">\n'
  + '<style>\n'
  + 'body{font-family:Inter,sans-serif;background:#f1f5f9;}\n'
  + 'pre{background:#0f172a;color:#94a3b8;padding:1rem;border-radius:8px;font-size:.75rem;overflow-x:auto;white-space:pre-wrap;min-height:60px;line-height:1.6;}\n'
  + '.flag-box{background:#fef9c3;border:2px solid #eab308;color:#713f12;padding:.75rem 1rem;border-radius:8px;font-family:monospace;font-weight:700;font-size:.85rem;display:none;margin:0 1rem 1rem;word-break:break-all;}\n'
  + '.fake-browser{border:1px solid #cbd5e1;border-radius:10px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,.08);background:white;}\n'
  + '.b-chrome{background:#e2e8f0;padding:8px 12px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #cbd5e1;flex-wrap:wrap;}\n'
  + '.tl-row{display:flex;gap:5px;flex-shrink:0;}.tl{width:11px;height:11px;border-radius:50%;}\n'
  + '.tl-r{background:#ef4444;}.tl-y{background:#f59e0b;}.tl-g{background:#22c55e;}\n'
  + '.nb{background:none;border:none;cursor:default;color:#94a3b8;font-size:15px;padding:1px 5px;border-radius:4px;line-height:1;}\n'
  + '.nb.cl{cursor:pointer;}.nb.cl:hover{background:#cbd5e1;color:#475569;}\n'
  + '.url-wrap{flex:1;display:flex;align-items:center;background:white;border:1px solid #94a3b8;border-radius:5px;padding:0 8px;height:28px;gap:5px;min-width:0;cursor:text;}\n'
  + '.url-wrap:focus-within{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,.2);}\n'
  + '.url-scheme{font-size:12px;color:#16a34a;font-family:monospace;flex-shrink:0;font-weight:600;user-select:none;}\n'
  + '.url-input{flex:1;border:none;outline:none;font-size:12.5px;font-family:monospace;color:#1e293b;background:transparent;padding:0;min-width:0;caret-color:#3b82f6;}\n'
  + '.url-go-btn{background:none;border:none;cursor:pointer;color:#64748b;font-size:14px;padding:0 2px;line-height:1;flex-shrink:0;}.url-go-btn:hover{color:#1d4ed8;}\n'
  + '.b-status{background:#f8fafc;border-top:1px solid #e2e8f0;padding:3px 12px;font-size:10.5px;color:#94a3b8;font-family:monospace;min-height:20px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}\n'
  + '.page-topbar{background:#1d4ed8;color:white;padding:8px 16px;display:flex;justify-content:space-between;align-items:center;font-size:11px;flex-wrap:wrap;gap:4px;}\n'
  + '.response-panel{margin:12px;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;}\n'
  + '.response-panel-header{background:#f8fafc;border-bottom:1px solid #e2e8f0;padding:6px 12px;display:flex;align-items:center;gap:8px;font-size:11px;font-family:monospace;color:#475569;flex-wrap:wrap;}\n'
  + '.http-badge{padding:1px 7px;border-radius:3px;font-weight:700;font-size:11px;}\n'
  + '.http-200{background:#dcfce7;color:#166534;}.http-403{background:#fee2e2;color:#991b1b;}.http-404{background:#fef9c3;color:#713f12;}\n'
  + '.method-tag{background:#dbeafe;color:#1d4ed8;padding:1px 6px;border-radius:3px;font-weight:700;font-size:11px;flex-shrink:0;}\n'
  + '.hint-body{display:none;}.hint-body.open{display:block;}\n'
  + '.hint-trigger{transition:background .15s;}.hint-trigger:hover{background:#fffbeb;}\n'
  + '.pip{width:10px;height:10px;border-radius:50%;background:#e2e8f0;display:inline-block;transition:background .2s;}\n'
  + '.pip.used{background:#ef4444;}.pip.warn{background:#f59e0b;}\n'
  + '.header-field{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:4px;padding:3px 8px;font-family:monospace;font-size:12px;color:#166634;}\n'
  + '.header-field:focus{outline:none;border-color:#4ade80;}\n'
  + '.score-pill{display:inline-flex;align-items:center;gap:6px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:6px 12px;}\n'
  + '.score-val{font-size:22px;font-weight:700;color:#1d4ed8;line-height:1;}\n'
  + '.score-deduction{font-size:11px;color:#ef4444;font-weight:600;}\n'
  + '.completion-banner{display:none;background:linear-gradient(135deg,#1d4ed8,#1e40af);border-radius:12px;padding:20px;color:white;text-align:center;margin-bottom:16px;}\n'
  + '@media(max-width:480px){.b-chrome{flex-wrap:wrap;}.url-wrap{flex-basis:100%;order:3;}.url-input{font-size:13px;}}\n'
  + '</style></head>\n'
  + '<body class="min-h-screen">\n'

  + '<nav class="bg-blue-700 text-white px-6 py-3 flex items-center justify-between shadow-lg flex-wrap gap-2">\n'
  + '  <div class="flex items-center gap-3 flex-wrap">\n'
  + '    <div class="w-8 h-8 bg-white rounded flex items-center justify-center flex-shrink-0">\n'
  + '      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#1d4ed8" class="w-5 h-5"><path fill-rule="evenodd" d="M12 1.5a5.25 5.25 0 00-5.25 5.25v3a3 3 0 00-3 3v6.75a3 3 0 003 3h10.5a3 3 0 003-3v-6.75a3 3 0 00-3-3v-3c0-2.9-2.35-5.25-5.25-5.25zm3.75 8.25v-3a3.75 3.75 0 10-7.5 0v3h7.5z" clip-rule="evenodd"/></svg>\n'
  + '    </div>\n'
  + '    <span class="font-bold text-lg">CorpPortal</span>\n'
  + '    <span class="text-blue-300 text-sm hidden sm:inline">Employee Directory</span>\n'
  + '    <span class="text-xs bg-red-500 text-white px-2 py-0.5 rounded font-semibold">IDOR Lab</span>\n'
  + '  </div>\n'
  + '  <div class="text-sm text-blue-200">Logged in as: <strong class="text-white">alice (ID: 1)</strong></div>\n'
  + '</nav>\n'

  + '<div class="max-w-6xl mx-auto px-4 py-6 space-y-5">\n'

  + '<div class="completion-banner" id="completion-banner">\n'
  + '  <div style="font-size:2rem;margin-bottom:8px;">&#127881;</div>\n'
  + '  <p style="font-size:18px;font-weight:700;margin-bottom:4px;">Lab Complete!</p>\n'
  + '  <p style="font-size:13px;opacity:.85;margin-bottom:12px;">You found the flag and earned:</p>\n'
  + '  <div style="font-size:42px;font-weight:800;" id="banner-score">100</div>\n'
  + '  <div style="font-size:13px;opacity:.7;margin-top:2px;">out of 100 points</div>\n'
  + '  <div id="banner-deductions" style="font-size:12px;color:#fca5a5;margin-top:8px;display:none;"></div>\n'
  + '</div>\n'

  + '<div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">\n'
  + '  <span class="text-2xl flex-shrink-0 mt-0.5">&#127919;</span>\n'
  + '  <div><p class="font-semibold text-amber-800 text-sm">IDOR Lab -- Type the URL yourself</p>\n'
  + '  <p class="text-amber-700 text-xs mt-1">You are <strong>Alice (ID: 1)</strong>. Edit the URL and press Enter. Find the hidden flag by changing object IDs. Each attempt costs 1 pt. Hints cost extra.</p></div>\n'
  + '</div>\n'

  + '<div class="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">\n'
  + '<div class="xl:col-span-2 space-y-5">\n'

  // Challenge 1
  + '<div>\n'
  + '<div class="flex items-center gap-2 mb-2 flex-wrap"><span class="text-sm font-semibold text-gray-800">Challenge 1 -- User Profile Endpoint</span><span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-semibold">VULNERABLE</span></div>\n'
  + '<div class="fake-browser">\n'
  + '  <div class="b-chrome"><div class="tl-row"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>\n'
  + '    <div style="display:flex;gap:3px;"><button class="nb">&#8592;</button><button class="nb">&#8594;</button><button class="nb cl" id="reload-user">&#8635;</button></div>\n'
  + '    <div class="url-wrap" id="wrap-user"><span class="url-scheme">https://</span><input type="text" class="url-input" id="url-user" value="corp-portal.internal/api/vulnerable/users/1" spellcheck="false" autocomplete="off"><button class="url-go-btn" id="go-user">&#10148;</button></div>\n'
  + '  </div>\n'
  + '  <div class="page-topbar"><span>corp-portal.internal / Employee Directory API</span><span id="user-status-badge" style="opacity:.6">ready</span></div>\n'
  + '  <div class="response-panel"><div class="response-panel-header"><span class="method-tag">GET</span><span id="user-path-display" class="flex-1 truncate">/api/vulnerable/users/1</span><span id="user-http-badge" class="http-badge"></span></div>\n'
  + '  <pre id="user-out">// Edit the URL above and press Enter\n// Try changing the number at the end -- you are user ID 1</pre></div>\n'
  + '  <div id="user-flag" class="flag-box"></div>\n'
  + '  <div class="b-status" id="user-status-bar">Waiting for navigation...</div>\n'
  + '</div><p class="text-xs text-gray-400 font-mono mt-1.5 pl-1">&#8593; Change the number at the end of the URL path</p>\n'
  + '</div>\n'

  // Challenge 2
  + '<div>\n'
  + '<div class="flex items-center gap-2 mb-2 flex-wrap"><span class="text-sm font-semibold text-gray-800">Challenge 2 -- Document Store Endpoint</span><span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-semibold">VULNERABLE</span></div>\n'
  + '<div class="fake-browser">\n'
  + '  <div class="b-chrome"><div class="tl-row"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>\n'
  + '    <div style="display:flex;gap:3px;"><button class="nb">&#8592;</button><button class="nb">&#8594;</button><button class="nb cl" id="reload-doc">&#8635;</button></div>\n'
  + '    <div class="url-wrap" id="wrap-doc"><span class="url-scheme">https://</span><input type="text" class="url-input" id="url-doc" value="corp-portal.internal/api/vulnerable/documents/1" spellcheck="false" autocomplete="off"><button class="url-go-btn" id="go-doc">&#10148;</button></div>\n'
  + '  </div>\n'
  + '  <div class="page-topbar"><span>corp-portal.internal / Document Store API</span><span id="doc-status-badge" style="opacity:.6">ready</span></div>\n'
  + '  <div class="response-panel"><div class="response-panel-header"><span class="method-tag">GET</span><span id="doc-path-display" class="flex-1 truncate">/api/vulnerable/documents/1</span><span id="doc-http-badge" class="http-badge"></span></div>\n'
  + '  <pre id="doc-out">// Edit the URL above and press Enter\n// Document IDs are not always sequential -- try other numbers</pre></div>\n'
  + '  <div id="doc-flag" class="flag-box"></div>\n'
  + '  <div class="b-status" id="doc-status-bar">Waiting for navigation...</div>\n'
  + '</div><p class="text-xs text-gray-400 font-mono mt-1.5 pl-1">&#8593; Document IDs are not always 1, 2, 3...</p>\n'
  + '</div>\n'


  + '<div id="flag-submit-section" style="display:none;">\n'
  + '<div class="bg-green-50 border border-green-300 rounded-xl p-4 mx-0 mb-2">\n'
  + '  <p class="text-sm font-semibold text-green-800 mb-3">&#127937; Flag found! Submit it to record your score.</p>\n'
  + '  <div class="flex gap-2 flex-wrap">\n'
  + '    <input id="flag-input" type="text" class="flex-1 min-w-0 border border-green-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-green-400" placeholder="FLAG{...}" spellcheck="false">\n'
  + '    <button id="submit-flag-btn" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-semibold">Submit Flag</button>\n'
  + '  </div>\n'
  + '  <p class="text-xs text-green-600 mt-2">Your score at submission: <span id="submit-score-preview"></span> pts</p>\n'
  + '</div></div>\n'

  // Challenge 3
  + '<div>\n'
  + '<div class="flex items-center gap-2 mb-2 flex-wrap"><span class="text-sm font-semibold text-gray-800">Challenge 3 -- Patched Endpoint</span><span class="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded font-semibold">FIXED</span></div>\n'
  + '<div class="fake-browser">\n'
  + '  <div class="b-chrome"><div class="tl-row"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>\n'
  + '    <div style="display:flex;gap:3px;"><button class="nb">&#8592;</button><button class="nb">&#8594;</button><button class="nb cl" id="reload-patched">&#8635;</button></div>\n'
  + '    <div class="url-wrap" id="wrap-patched"><span class="url-scheme">https://</span><input type="text" class="url-input" id="url-patched" value="corp-portal.internal/api/patched/users/1" spellcheck="false" autocomplete="off"><button class="url-go-btn" id="go-patched">&#10148;</button></div>\n'
  + '  </div>\n'
  + '  <div class="page-topbar" style="background:#166534;"><span>corp-portal.internal / Patched API -- ownership checks enabled</span></div>\n'
  + '  <div style="background:#f0fdf4;border-bottom:1px solid #bbf7d0;padding:8px 14px;">\n'
  + '    <p class="text-xs font-semibold text-green-800 mb-2">&#128274; Request Headers</p>\n'
  + '    <div class="flex items-center gap-3 flex-wrap"><code class="text-xs text-green-700 font-mono">x-user-id:</code><input type="text" id="patch-userid" value="1" class="header-field" style="width:60px;"><span class="text-xs text-green-600">your session identity (Alice = 1)</span></div>\n'
  + '  </div>\n'
  + '  <div class="response-panel"><div class="response-panel-header"><span class="method-tag">GET</span><span id="patch-path-display" class="flex-1 truncate">/api/patched/users/1</span><span id="patch-http-badge" class="http-badge"></span></div>\n'
  + '  <pre id="patch-out">// Try a user ID in the URL above and press Enter\n// Adjust x-user-id and observe what changes</pre></div>\n'
  + '  <div class="b-status" id="patch-status-bar">Waiting for navigation...</div>\n'
  + '</div>\n'
  + '</div>\n'

  + '</div>\n' // end left col

  // Sidebar
  + '<div class="space-y-4">\n'
  + '<div class="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">\n'
  + '  <div class="flex items-center justify-between mb-3"><span class="text-sm font-semibold text-gray-700">Score</span><span class="text-xs text-gray-400">max 100 pts / floor 20 pts</span></div>\n'
  + '  <div class="score-pill w-full justify-center mb-3"><span class="score-val" id="score-val">100</span><div><div style="font-size:12px;color:#64748b;">/ 100 pts</div><div class="score-deduction" id="score-deduction" style="display:none;"></div></div></div>\n'
  + '  <div class="mt-2 pt-2 border-t border-gray-100">\n'
  + '    <div class="flex justify-between text-xs mb-1"><span class="text-gray-500">Flag captured</span><span id="flags-count" class="font-bold text-green-600">0 / 1</span></div>\n'
  + '    <div class="w-full bg-gray-100 rounded-full h-2"><div id="flag-progress" class="bg-green-500 h-2 rounded-full transition-all" style="width:0%"></div></div>\n'
  + '  </div>\n'
  + '  <p class="text-xs text-gray-400 mt-2 leading-relaxed">Each attempt costs 1 pt. Hints cost extra. Min score: 20 pts.</p>\n'
  + '</div>\n'
  + '<div class="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">\n'
  + '  <div class="flex items-center justify-between mb-3"><span class="text-sm font-semibold text-gray-700">Attempts</span><span id="tries-text" class="text-xs text-gray-400 font-mono">0 / 10</span></div>\n'
  + '  <div class="flex flex-wrap gap-1 mb-2" id="pip-row"></div>\n'
  + '  <p class="text-xs text-gray-400">After <strong>5 attempts</strong> a hint auto-unlocks.</p>\n'
  + '</div>\n'
  + '<div class="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">\n'
  + '  <div class="bg-amber-50 border-b border-amber-200 px-4 py-3 flex items-center justify-between">\n'
  + '    <div class="flex items-center gap-2"><span>&#128161;</span><span class="text-sm font-semibold text-amber-800">Hints</span></div>\n'
  + '    <span class="text-xs bg-amber-100 text-amber-700 px-2 py-0.5 rounded" id="hints-used-label">0 of 4 revealed</span>\n'
  + '  </div>\n'
  + '  <div class="border-b border-gray-100"><button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" id="hint-btn-0"><span class="text-xs font-medium text-gray-700" id="hl0">&#128274; What is IDOR?</span><span class="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded">free</span></button>\n'
  + '  <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-0"><strong>Insecure Direct Object Reference</strong> -- the server uses a user-supplied value to look up an object but never checks if you are allowed to access it. Change the ID, get someone elses data.</div></div>\n'
  + '  <div class="border-b border-gray-100"><button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" id="hint-btn-1"><span class="text-xs font-medium text-gray-700" id="hl1">&#128274; Where to look</span><span class="text-xs bg-amber-100 text-amber-700 px-2 py-0.5 rounded">-5 pts</span></button>\n'
  + '  <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-1">The number at the end of the URL is the <strong>object ID</strong>. Regular users have IDs 1, 2, 3. Could there be a privileged account with a much higher ID?</div></div>\n'
  + '  <div class="border-b border-gray-100"><button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" id="hint-btn-2"><span class="text-xs font-medium text-gray-700" id="hl2">&#128274; Flag -- User ID range</span><span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded">-20 pts</span></button>\n'
  + '  <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-2">The admin account has a <strong>non-sequential ID</strong> between <strong>90 and 100</strong>. Try those values in the User Profile URL or the Document Store URL.</div></div>\n'
  + '  <div><button class="hint-trigger w-full px-4 py-3 flex items-center justify-between text-left" id="hint-btn-3"><span class="text-xs font-medium text-gray-700" id="hl3">&#128274; Flag -- Document ID</span><span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded">-25 pts</span></button>\n'
  + '  <div class="hint-body px-4 pb-3 text-xs text-gray-600 leading-relaxed bg-amber-50" id="hint-body-3">The flag appears in both endpoints. On the Document side, look for document ID <strong>42</strong>. On the User side, try ID <strong>99</strong>.</div></div>\n'
  + '</div>\n'
  + '<div class="bg-white border border-gray-200 rounded-xl p-4 shadow-sm">\n'
  + '  <p class="text-xs font-semibold text-gray-700 mb-2">&#128270; Things to observe</p>\n'
  + '  <ul class="text-xs text-gray-500 space-y-1.5 leading-relaxed">\n'
  + '    <li>&#10140; Does the server check who is making the request?</li>\n'
  + '    <li>&#10140; What HTTP status for a valid vs unknown ID?</li>\n'
  + '    <li>&#10140; Try the same URL on Challenge 3 -- what changes?</li>\n'
  + '    <li>&#10140; What header does the patched endpoint use?</li>\n'
  + '  </ul>\n'
  + '</div>\n'
  + '</div>\n' // end sidebar
  + '</div>\n' // end grid
  + '</div>\n' // end max-w
  + '<script>' + js + '<' + '/script>\n'
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
  + '<' + '/script>\n'
  + '</body></html>';
}