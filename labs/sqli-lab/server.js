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
  try { jwt.verify(token, JWT_SECRET); } catch { return res.redirect(`${FRONTEND_URL}/login.html`); }
  try {
    const r = await nodeFetch(`${BACKEND_URL}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) return res.redirect(`${FRONTEND_URL}/login.html`);
  } catch (err) { console.warn('[sqli-lab] Backend unreachable:', err.message); }
  next();
}
app.use(requireLabAuth);

const fakeDb = [
  { id:1, username:'alice', password:'alice123',    role:'user',  secret:null },
  { id:2, username:'bob',   password:'bob456',      role:'user',  secret:null },
  { id:3, username:'admin', password:'sup3rs3cr3t', role:'admin', secret:'FLAG{sql_injected_success}' },
];

app.post('/api/vulnerable/login', (req, res) => {
  const { username, password } = req.body;
  const combined = (username || '') + (password || '');
  const simulatedQuery = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  const isBypass =
    /'\s*OR\s*'?1'?\s*=\s*'?1/i.test(combined) ||
    /'\s*OR\s*1\s*=\s*1/i.test(combined) ||
    /'\s*--/.test(combined) ||
    /'\s*#/.test(combined) ||
    /'\s*\/\*/.test(combined);
  const hasSqlChars = /['";<>\-]/.test(combined);
  const hasOr       = /\bOR\b/i.test(combined);
  const isPartial   = hasSqlChars && !isBypass;
  const exactMatch  = fakeDb.find(u => u.username === username && u.password === password);
  if (isBypass)   return res.json({ success:true, bypassed:true, query:simulatedQuery, user:fakeDb[2], message:'SQLi bypass successful!', flag:'FLAG{sql_injected_success}' });
  if (exactMatch) return res.json({ success:true, bypassed:false, query:simulatedQuery, user:exactMatch, message:'Welcome back, ' + exactMatch.username + '!' });
  if (isPartial)  return res.status(500).json({ success:false, broken:true, query:simulatedQuery, message: hasOr ? "You're on the right track — keep building the condition." : "SQL syntax error — you've broken out of the string. Now what?" });
  res.status(401).json({ success:false, query:simulatedQuery, message:'Invalid username or password.' });
});

app.post('/api/patched/login', (req, res) => {
  const { username, password } = req.body;
  const user = fakeDb.find(u => u.username === username && u.password === password);
  if (user) return res.json({ success:true, user:{ id:user.id, username:user.username, role:user.role }, message:'Welcome, ' + user.username + '!' });
  res.status(401).json({ success:false, message:'Invalid username or password.' });
});

app.get('/', (req, res) => {
  const backendUrl  = BACKEND_URL;
  const frontendUrl = FRONTEND_URL;
  const page = buildPage(backendUrl, frontendUrl);
  res.send(page);
});

app.listen(PORT, () => console.log('SQLi Lab running on http://localhost:' + PORT));

const browserJS = "\nvar MAX_TRIES       = 10;\nvar AUTO_HINT       = 5;\nvar MAX_SCORE       = 150;\nvar LAB_SLUG        = 'sql-injection-101';\nvar HINT_DEDUCTIONS = [0, 5, 20, 25];\nvar BACKEND_URL_JS  = '__BACKEND_URL__';\n\nvar tries         = 0;\nvar flagDone      = false;\nvar hintsRevealed = [false,false,false,false];\nvar totalDeducted = 0;\nvar labComplete   = false;\n\nfunction currentScore(){ return Math.max(0, MAX_SCORE - totalDeducted); }\n\nfunction updateScoreUI(){\n  document.getElementById('score-val').textContent = currentScore();\n  var dedEl = document.getElementById('score-deduction');\n  if(totalDeducted > 0){\n    dedEl.style.display = 'block';\n    dedEl.textContent   = '-' + totalDeducted + ' pts from hints';\n  } else {\n    dedEl.style.display = 'none';\n  }\n}\n\nfunction renderPips(){\n  var row = document.getElementById('pip-row');\n  row.innerHTML = '';\n  for(var i=0;i<MAX_TRIES;i++){\n    var d = document.createElement('div');\n    var used = i < tries;\n    var warn = used && (tries-i <= 2);\n    d.className = 'pip'+(used?(warn?' warn':' used'):'');\n    row.appendChild(d);\n  }\n  document.getElementById('tries-text').textContent = tries+' / '+MAX_TRIES;\n}\n\nfunction recordTry(cost){\n  cost = cost||1;\n  tries = Math.min(MAX_TRIES, tries+cost);\n  renderPips();\n  if(tries >= AUTO_HINT && !hintsRevealed[1]) revealHint(1,true);\n}\n\nrenderPips();\n\nfunction escHtml(s){\n  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');\n}\n\nfunction hasSql(s){ return /['\";\\-]/.test(s); }\n\nfunction renderQuery(){\n  var u = document.getElementById('v-user').value;\n  var p = document.getElementById('v-pass').value;\n  var uCls = hasSql(u)?'qi':'qs';\n  var pCls = hasSql(p)?'qi':'qs';\n  document.getElementById('v-user').className = 'fi mono'+(hasSql(u)?' bad':'');\n  document.getElementById('v-pass').className = 'fi mono'+(hasSql(p)?' bad':'');\n  document.getElementById('query-display').innerHTML =\n    '<span class=\"kw\">SELECT</span> * <span class=\"kw\">FROM</span> users '\n    +'<span class=\"kw\">WHERE</span> username=<span class=\"'+uCls+'\">\\''+ escHtml(u) +'\\'</span> '\n    +'<span class=\"kw\">AND</span> password=<span class=\"'+pCls+'\">\\''+ escHtml(p) +'\\'</span>';\n}\n\ndocument.getElementById('v-user').addEventListener('input',renderQuery);\ndocument.getElementById('v-pass').addEventListener('input',renderQuery);\ndocument.getElementById('v-user').addEventListener('keydown',function(e){if(e.key==='Enter')doVulnLogin();});\ndocument.getElementById('v-pass').addEventListener('keydown',function(e){if(e.key==='Enter')doVulnLogin();});\ndocument.getElementById('p-user').addEventListener('keydown',function(e){if(e.key==='Enter')doPatchLogin();});\ndocument.getElementById('p-pass').addEventListener('keydown',function(e){if(e.key==='Enter')doPatchLogin();});\ndocument.getElementById('sign-in-btn').addEventListener('click',doVulnLogin);\ndocument.getElementById('patch-btn').addEventListener('click',doPatchLogin);\ndocument.getElementById('reset-vuln-btn').addEventListener('click',resetVuln);\ndocument.getElementById('reset-patch-btn').addEventListener('click',resetPatched);\ndocument.getElementById('hbtn0').addEventListener('click',function(){revealHint(0);});\ndocument.getElementById('hbtn1').addEventListener('click',function(){revealHint(1);});\ndocument.getElementById('hbtn2').addEventListener('click',function(){revealHint(2);});\ndocument.getElementById('hbtn3').addEventListener('click',function(){revealHint(3);});\n\nfunction submitScore(){\n  var token = new URLSearchParams(window.location.search).get('token');\n  if(!token) return;\n  fetch(BACKEND_URL_JS+'/api/labs/'+LAB_SLUG+'/complete',{\n    method:'POST',\n    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},\n    body:JSON.stringify({points_earned:currentScore(),hints_used:totalDeducted})\n  }).catch(function(){});\n}\n\nfunction showCompletionBanner(){\n  var banner = document.getElementById('completion-banner');\n  banner.style.display = 'block';\n  document.getElementById('banner-score').textContent = currentScore();\n  var dedEl = document.getElementById('banner-deductions');\n  if(totalDeducted > 0){\n    dedEl.textContent = '-' + totalDeducted + ' pts deducted from hints';\n    dedEl.style.display = 'block';\n  }\n  banner.scrollIntoView({behavior:'smooth',block:'start'});\n  submitScore();\n}\n\nfunction doVulnLogin(){\n  var u = document.getElementById('v-user').value;\n  var p = document.getElementById('v-pass').value;\n  if(!u && !p) return;\n  var btn = document.getElementById('sign-in-btn');\n  var res = document.getElementById('v-result');\n  var fl  = document.getElementById('v-flag');\n  var sb  = document.getElementById('vuln-status');\n  btn.disabled = true; btn.textContent = 'Signing in...';\n  sb.textContent = 'Sending POST /api/vulnerable/login...';\n  res.style.display = 'none'; fl.style.display = 'none';\n  recordTry();\n  fetch('/api/vulnerable/login',{\n    method:'POST',\n    headers:{'Content-Type':'application/json'},\n    body:JSON.stringify({username:u,password:p})\n  }).then(function(r){\n    sb.textContent = 'POST /api/vulnerable/login  \\u2014  HTTP '+r.status+(r.ok?' OK':' Error');\n    return r.json().then(function(d){\n      res.style.display = 'block';\n      if(d.bypassed){\n        res.innerHTML = '<div class=\"r-bad\"><p style=\"font-weight:700;color:#dc2626;font-size:13px;\">&#128680; Authentication Bypassed!</p><p style=\"color:#ef4444;font-size:12px;margin-top:4px;\">Logged in as: <strong>'+d.user.username+'</strong> ('+d.user.role+')</p></div>';\n        fl.textContent = 'Flag: '+d.flag;\n        fl.style.display = 'block';\n        if(!flagDone){\n          flagDone = true;\n          document.getElementById('flags-count').textContent = '1 / 1';\n          document.getElementById('flag-progress').style.width = '100%';\n          if(!labComplete){ labComplete=true; showCompletionBanner(); }\n        }\n      } else if(d.broken){\n        res.innerHTML = '<div style=\"background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;padding:12px;\"><p style=\"font-weight:700;color:#92400e;font-size:13px;\">&#9889; SQL Error \\u2014 Query Broken</p><p style=\"color:#b45309;font-size:12px;margin-top:4px;\">'+d.message+'</p></div>';\n      } else if(d.success){\n        res.innerHTML = '<div class=\"r-ok\"><p style=\"color:#15803d;font-weight:600;font-size:13px;\">Logged in as '+d.user.username+'</p><p style=\"color:#16a34a;font-size:12px;margin-top:4px;\">Role: '+d.user.role+' \\u2014 no flag here.</p></div>';\n      } else {\n        res.innerHTML = '<div class=\"r-fail\"><p style=\"color:#64748b;font-size:13px;\">Invalid username or password.</p></div>';\n      }\n      btn.disabled=false; btn.textContent='Sign In';\n    });\n  }).catch(function(e){\n    res.style.display='block';\n    res.innerHTML='<div class=\"r-fail\"><p style=\"color:#64748b;font-size:13px;\">Network error: '+e.message+'</p></div>';\n    sb.textContent='Request failed';\n    btn.disabled=false; btn.textContent='Sign In';\n  });\n}\n\nfunction doPatchLogin(){\n  var u = document.getElementById('p-user').value;\n  var p = document.getElementById('p-pass').value;\n  if(!u && !p) return;\n  var sb  = document.getElementById('patch-status');\n  var res = document.getElementById('p-result');\n  sb.textContent = 'Sending POST /api/patched/login...';\n  res.style.display = 'none';\n  recordTry();\n  fetch('/api/patched/login',{\n    method:'POST',\n    headers:{'Content-Type':'application/json'},\n    body:JSON.stringify({username:u,password:p})\n  }).then(function(r){\n    sb.textContent = 'POST /api/patched/login  \\u2014  HTTP '+r.status+(r.ok?' OK':' Unauthorized');\n    return r.json().then(function(d){\n      res.style.display = 'block';\n      if(d.success){\n        res.innerHTML = '<div class=\"r-ok\"><p style=\"color:#15803d;font-weight:600;font-size:13px;\">Logged in as '+d.user.username+'</p></div>';\n      } else {\n        res.innerHTML = '<div class=\"r-fail\"><p style=\"color:#64748b;font-size:13px;\">Invalid credentials.<br><span style=\"font-size:11px;color:#94a3b8;\">SQLi payload treated as literal \\u2014 no bypass possible.</span></p></div>';\n      }\n    });\n  }).catch(function(e){\n    res.style.display='block';\n    res.innerHTML='<div class=\"r-fail\"><p style=\"color:#64748b;font-size:13px;\">Error: '+e.message+'</p></div>';\n  });\n}\n\nfunction resetVuln(){\n  document.getElementById('v-user').value='';\n  document.getElementById('v-pass').value='';\n  document.getElementById('v-user').className='fi mono';\n  document.getElementById('v-pass').className='fi mono';\n  document.getElementById('v-result').style.display='none';\n  document.getElementById('v-flag').style.display='none';\n  document.getElementById('vuln-status').textContent='Waiting for login attempt...';\n  document.getElementById('query-display').innerHTML='<span class=\"kw\">SELECT</span> * <span class=\"kw\">FROM</span> users <span class=\"kw\">WHERE</span> username=<span class=\"qs\">\\'?\\'</span> <span class=\"kw\">AND</span> password=<span class=\"qs\">\\'?\\'</span>';\n}\n\nfunction resetPatched(){\n  document.getElementById('p-user').value='';\n  document.getElementById('p-pass').value='';\n  document.getElementById('p-result').style.display='none';\n  document.getElementById('patch-status').textContent='Waiting for login attempt...';\n}\n\nfunction revealHint(idx,auto){\n  var body = document.getElementById('hint-body-'+idx);\n  if(hintsRevealed[idx]){ body.classList.toggle('open'); return; }\n  var cost = HINT_DEDUCTIONS[idx];\n  if(!auto && cost>0){\n    if(!confirm('This hint costs '+cost+' points.\\nYour current score: '+currentScore()+' pts.\\n\\nReveal anyway?')) return;\n  }\n  hintsRevealed[idx]=true;\n  totalDeducted = Math.min(MAX_SCORE, totalDeducted+cost);\n  body.classList.add('open');\n  updateScoreUI();\n  var lbl = document.getElementById('hl'+idx);\n  if(lbl) lbl.innerHTML = lbl.innerHTML.replace('&#128274;','&#128275;');\n  document.getElementById('hints-used-label').textContent = hintsRevealed.filter(Boolean).length+' of 4 revealed';\n}\n";

function buildPage(backendUrl, frontendUrl) {
  var BJSON = JSON.stringify(browserJS.replace('__BACKEND_URL__', backendUrl));
  // We'll inject it differently — just return the HTML string
  var bjs = browserJS.replace('__BACKEND_URL__', backendUrl);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BankSecure — SQLi Lab</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23991b1b'/%3E%3Cg transform='rotate(-45 16 16)'%3E%3Crect x='14.5' y='4' width='3' height='16' rx='1.5' fill='%23fca5a5'/%3E%3Crect x='13' y='20' width='6' height='3' rx='1' fill='%23fca5a5'/%3E%3Cpolygon points='16,30 13,23 19,23' fill='%23fca5a5'/%3E%3Crect x='11' y='8' width='2' height='2' rx='0.5' fill='%23fecaca'/%3E%3Crect x='11' y='12' width='2' height='2' rx='0.5' fill='%23fecaca'/%3E%3Crect x='19' y='8' width='2' height='2' rx='0.5' fill='%23fecaca'/%3E%3C/g%3E%3C/svg%3E">
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;}
body{font-family:Inter,sans-serif;background:#0f172a;min-height:100vh;}
.mono{font-family:"JetBrains Mono",monospace;}
pre{background:#0f172a;color:#94a3b8;padding:1rem;border-radius:8px;font-size:.75rem;overflow-x:auto;white-space:pre-wrap;min-height:48px;line-height:1.6;border:1px solid #1e293b;margin:0;}
.flag-box{background:#fef9c3;border:2px solid #eab308;color:#713f12;padding:.75rem 1rem;border-radius:8px;font-family:"JetBrains Mono",monospace;font-weight:700;font-size:.85rem;display:none;margin-top:.75rem;word-break:break-all;}
.fake-browser{border:1px solid #334155;border-radius:10px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.4);}
.b-chrome{background:#1e293b;padding:8px 12px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #334155;flex-wrap:wrap;}
.tl-row{display:flex;gap:5px;flex-shrink:0;}
.tl{width:11px;height:11px;border-radius:50%;}
.tl-r{background:#ef4444;}.tl-y{background:#f59e0b;}.tl-g{background:#22c55e;}
.nb{background:none;border:none;cursor:default;color:#475569;font-size:15px;padding:1px 5px;border-radius:4px;line-height:1;}
.nb.cl{cursor:pointer;}.nb.cl:hover{background:#334155;color:#94a3b8;}
.url-bar{flex:1;display:flex;align-items:center;background:#0f172a;border:1px solid #334155;border-radius:5px;padding:0 8px;height:28px;gap:5px;min-width:0;}
.url-scheme{font-size:11px;color:#22c55e;font-family:"JetBrains Mono",monospace;flex-shrink:0;font-weight:600;user-select:none;}
.url-text{flex:1;font-size:12px;font-family:"JetBrains Mono",monospace;color:#475569;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;user-select:none;}
.b-status{background:#1e293b;border-top:1px solid #334155;padding:3px 12px;font-size:10.5px;color:#475569;font-family:"JetBrains Mono",monospace;min-height:20px;}
.page-bg{background:linear-gradient(135deg,#1e3a5f 0%,#0f2340 100%);padding:28px 20px;}
.login-card{background:white;border-radius:16px;overflow:hidden;max-width:380px;margin:0 auto;box-shadow:0 20px 48px rgba(0,0,0,.4);}
.card-hdr{background:linear-gradient(135deg,#1e40af,#1e3a8a);padding:24px;text-align:center;}
.fi{width:100%;border:1.5px solid #e2e8f0;border-radius:8px;padding:10px 12px;font-size:13px;font-family:"JetBrains Mono",monospace;outline:none;transition:border-color .15s,box-shadow .15s;color:#1e293b;background:white;display:block;}
.fi:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15);}
.fi.bad{border-color:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,.15);color:#dc2626;}
.si-btn{width:100%;background:#1d4ed8;color:white;border:none;padding:11px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:background .15s;display:block;}
.si-btn:hover{background:#1e40af;}.si-btn:disabled{background:#94a3b8;cursor:not-allowed;}
.kw{color:#c4b5fd;}.qs{color:#86efac;}.qi{color:#f87171;font-weight:600;}
.hint-body{display:none;}.hint-body.open{display:block;}
.ht{width:100%;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;background:none;border:none;cursor:pointer;text-align:left;transition:background .15s;}
.ht:hover{background:rgba(255,255,255,.04);}
.pip{width:10px;height:10px;border-radius:50%;background:#334155;display:inline-block;transition:background .2s;}
.pip.used{background:#ef4444;}.pip.warn{background:#f59e0b;}
.r-ok{background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:12px;}
.r-bad{background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;padding:12px;}
.r-fail{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;}
.score-pill{display:inline-flex;align-items:center;gap:6px;background:rgba(30,41,59,.8);border:1px solid #475569;border-radius:8px;padding:6px 12px;}
.score-val{font-size:22px;font-weight:700;color:#4ade80;line-height:1;}
.completion-banner{display:none;background:linear-gradient(135deg,#991b1b,#7f1d1d);border-radius:12px;padding:20px;color:white;text-align:center;margin-bottom:16px;}
@media(max-width:480px){
  .b-chrome{flex-wrap:wrap;}
  .url-bar{flex-basis:100%;order:3;min-width:0;}
}
</style>
</head>
<body>
<nav style="background:#0f172a;border-bottom:1px solid #334155;padding:12px 24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
    <div style="width:32px;height:32px;background:#dc2626;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:white;font-family:monospace;flex-shrink:0;">SQL</div>
    <span style="font-weight:700;color:white;font-size:1.1rem;">BankSecure</span>
    <span style="color:#64748b;font-size:13px;" class="hidden sm:inline">Online Banking Portal</span>
    <span style="font-size:11px;background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-weight:600;">SQLi Lab</span>
  </div>
  <div style="font-size:13px;color:#64748b;">Not logged in &mdash; <span style="color:#e2e8f0;font-weight:500;">attempt to bypass</span></div>
</nav>

<div class="max-w-6xl mx-auto px-4 py-6 space-y-5">

<div class="completion-banner" id="completion-banner">
  <div style="font-size:2rem;margin-bottom:8px;">&#127881;</div>
  <p style="font-size:18px;font-weight:700;margin-bottom:4px;">Lab Complete!</p>
  <p style="font-size:13px;opacity:.85;margin-bottom:12px;">You bypassed authentication and earned:</p>
  <div style="font-size:42px;font-weight:800;letter-spacing:-1px;" id="banner-score">150</div>
  <div style="font-size:13px;opacity:.7;margin-top:2px;">out of 150 points</div>
  <div id="banner-deductions" style="font-size:12px;color:#fca5a5;margin-top:8px;display:none;"></div>
</div>

<div style="background:#fffbeb;border-left:4px solid #f59e0b;border-radius:12px;padding:16px;display:flex;gap:12px;">
  <span style="font-size:1.5rem;flex-shrink:0;margin-top:2px;">&#127919;</span>
  <div>
    <p style="font-weight:600;color:#92400e;font-size:13px;">SQL Injection Lab &mdash; Objective</p>
    <p style="color:#b45309;font-size:12px;margin-top:4px;line-height:1.6;">Bypass authentication by injecting SQL into the login form. Type payloads manually &mdash; watch the live query preview update as you type. Revealing hints reduces your score.</p>
  </div>
</div>

<div class="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">
<div class="xl:col-span-2 space-y-5">

<div>
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;">
    <span style="font-size:13px;font-weight:600;color:#e2e8f0;">Challenge 1 &mdash; Vulnerable Login Form</span>
    <span style="font-size:11px;background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-weight:600;">VULNERABLE</span>
  </div>
  <div class="fake-browser">
    <div class="b-chrome">
      <div class="tl-row"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
      <div style="display:flex;gap:3px;">
        <button class="nb">&#8592;</button><button class="nb">&#8594;</button>
        <button class="nb cl" id="reset-vuln-btn">&#8635;</button>
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
          <h1 style="color:white;font-weight:700;font-size:1.1rem;">BankSecure</h1>
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
          <button id="sign-in-btn" class="si-btn">Sign In</button>
          <div id="v-result" style="display:none;margin-top:12px;"></div>
          <div id="v-flag" class="flag-box"></div>
        </div>
      </div>
    </div>
    <div class="b-status" id="vuln-status">Waiting for login attempt...</div>
  </div>
  <p style="font-size:11px;color:#475569;font-family:monospace;margin-top:6px;padding-left:4px;">&#8593; Type into the fields &mdash; what happens when you include SQL characters like ' or --</p>
</div>

<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
    <span style="font-size:12px;font-weight:600;color:#cbd5e1;">&#128269; Live SQL Query Preview</span>
    <span style="font-size:11px;color:#475569;">(updates as you type)</span>
  </div>
  <pre id="query-display"><span class="kw">SELECT</span> * <span class="kw">FROM</span> users <span class="kw">WHERE</span> username=<span class="qs">'?'</span> <span class="kw">AND</span> password=<span class="qs">'?'</span></pre>
  <p style="font-size:11px;color:#475569;margin-top:8px;">Your input is inserted raw &mdash; can you break out of the string quotes?</p>
</div>

<div>
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;">
    <span style="font-size:13px;font-weight:600;color:#e2e8f0;">Challenge 2 &mdash; Patched Login (Parameterized Query)</span>
    <span style="font-size:11px;background:#14532d;color:#86efac;padding:2px 8px;border-radius:4px;font-weight:600;">FIXED</span>
  </div>
  <div class="fake-browser">
    <div class="b-chrome">
      <div class="tl-row"><div class="tl tl-r"></div><div class="tl tl-y"></div><div class="tl tl-g"></div></div>
      <div style="display:flex;gap:3px;">
        <button class="nb">&#8592;</button><button class="nb">&#8594;</button>
        <button class="nb cl" id="reset-patch-btn">&#8635;</button>
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
          <h1 style="color:white;font-weight:700;font-size:1.1rem;">BankSecure</h1>
          <p style="color:#86efac;font-size:11px;margin-top:4px;">Secured Login &mdash; v2</p>
          <span style="display:inline-block;margin-top:8px;font-size:11px;background:#16a34a;color:white;padding:2px 8px;border-radius:4px;font-weight:600;">PATCHED</span>
        </div>
        <div style="padding:24px;">
          <p style="font-size:12px;color:#6b7280;background:#f9fafb;border-radius:8px;padding:10px 12px;margin-bottom:16px;line-height:1.6;">Uses <strong>parameterized queries</strong> &mdash; input is never concatenated into SQL. Try the same payloads.</p>
          <div style="margin-bottom:14px;">
            <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Username</label>
            <input id="p-user" type="text" placeholder="Enter username..." class="fi mono" autocomplete="off" spellcheck="false">
          </div>
          <div style="margin-bottom:16px;">
            <label style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;font-weight:600;display:block;margin-bottom:6px;">Password</label>
            <input id="p-pass" type="text" placeholder="Enter password..." class="fi mono" autocomplete="off" spellcheck="false">
          </div>
          <button id="patch-btn" class="si-btn" style="background:#16a34a;">Sign In</button>
          <div id="p-result" style="display:none;margin-top:12px;"></div>
        </div>
      </div>
    </div>
    <div class="b-status" id="patch-status">Waiting for login attempt...</div>
  </div>
  <p style="font-size:11px;color:#475569;font-family:monospace;margin-top:6px;padding-left:4px;">&#8593; Try the exact same payload &mdash; notice the difference</p>
</div>

</div>

<div class="space-y-4">

<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
    <span style="font-size:14px;font-weight:600;color:#e2e8f0;">Score</span>
    <span style="font-size:12px;color:#64748b;">max 150 pts</span>
  </div>
  <div class="score-pill" style="width:100%;justify-content:center;margin-bottom:10px;">
    <span class="score-val" id="score-val">150</span>
    <div>
      <div style="font-size:12px;color:#94a3b8;">/ 150 pts</div>
      <div id="score-deduction" style="font-size:11px;color:#ef4444;font-weight:600;display:none;"></div>
    </div>
  </div>
  <div style="margin-top:8px;padding-top:8px;border-top:1px solid #334155;">
    <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
      <span style="color:#64748b;">Flag captured</span>
      <span id="flags-count" style="font-weight:700;color:#4ade80;">0 / 1</span>
    </div>
    <div style="width:100%;background:#334155;border-radius:9999px;height:8px;">
      <div id="flag-progress" style="background:#22c55e;height:8px;border-radius:9999px;width:0%;transition:width .5s;"></div>
    </div>
  </div>
  <p style="font-size:12px;color:#64748b;margin-top:8px;line-height:1.6;">Revealing hints reduces your final score. Solve without hints for full points.</p>
</div>

<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
    <span style="font-size:14px;font-weight:600;color:#e2e8f0;">Attempts</span>
    <span id="tries-text" style="font-size:12px;color:#64748b;font-family:monospace;">0 / 10</span>
  </div>
  <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px;" id="pip-row"></div>
  <p style="font-size:12px;color:#64748b;line-height:1.6;">After <strong style="color:#94a3b8;">5 attempts</strong> a hint auto-unlocks.</p>
</div>

<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;overflow:hidden;">
  <div style="background:rgba(120,53,15,.3);border-bottom:1px solid rgba(180,83,9,.4);padding:10px 16px;display:flex;align-items:center;justify-content:space-between;">
    <div style="display:flex;align-items:center;gap:8px;"><span>&#128161;</span><span style="font-size:14px;font-weight:600;color:#fbbf24;">Hints</span></div>
    <span id="hints-used-label" style="font-size:11px;background:rgba(120,53,15,.4);color:#fbbf24;padding:2px 8px;border-radius:4px;">0 of 4 revealed</span>
  </div>
  <div style="border-bottom:1px solid #334155;">
    <button class="ht" id="hbtn0"><span id="hl0" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; What is SQL injection?</span><span style="font-size:11px;background:rgba(21,128,61,.3);color:#4ade80;padding:2px 8px;border-radius:4px;">free</span></button>
    <div class="hint-body" id="hint-body-0" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">SQL injection happens when user input is inserted <em>directly</em> into a query string. Characters like <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">'</code> or <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">--</code> can change the logic of the query itself.</div>
  </div>
  <div style="border-bottom:1px solid #334155;">
    <button class="ht" id="hbtn1"><span id="hl1" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; Breaking out of the query</span><span style="font-size:11px;background:rgba(120,53,15,.3);color:#fbbf24;padding:2px 8px;border-radius:4px;">&#8722;5 pts</span></button>
    <div class="hint-body" id="hint-body-1" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">The query looks like <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">WHERE username='INPUT'</code>. Typing a <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">'</code> closes the string early. What could you add after it to make the condition always true?</div>
  </div>
  <div style="border-bottom:1px solid #334155;">
    <button class="ht" id="hbtn2"><span id="hl2" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; Always-true condition</span><span style="font-size:11px;background:rgba(127,29,29,.3);color:#f87171;padding:2px 8px;border-radius:4px;">&#8722;20 pts</span></button>
    <div class="hint-body" id="hint-body-2" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">After the quote add an <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">OR</code> clause that is always true like <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">1=1</code>. Then use <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">--</code> to comment out the password check. Watch the query preview react as you type.</div>
  </div>
  <div>
    <button class="ht" id="hbtn3"><span id="hl3" style="font-size:12px;font-weight:500;color:#cbd5e1;">&#128274; Exact payload structure</span><span style="font-size:11px;background:rgba(127,29,29,.3);color:#f87171;padding:2px 8px;border-radius:4px;">&#8722;25 pts</span></button>
    <div class="hint-body" id="hint-body-3" style="padding:0 16px 12px;font-size:12px;color:#94a3b8;line-height:1.6;background:rgba(0,0,0,.2);">Put this in <strong style="color:#e2e8f0;">username</strong>, anything in password:<br><code style="display:block;background:#0f172a;color:#4ade80;padding:6px 10px;border-radius:6px;margin-top:8px;font-size:12px;">' OR 1=1--</code>The <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">'</code> closes the string, <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">OR 1=1</code> is always true, <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#e2e8f0;">--</code> kills the password check.</div>
  </div>
</div>

<div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px;">
  <p style="font-size:12px;font-weight:600;color:#cbd5e1;margin-bottom:8px;">&#128270; Things to observe</p>
  <ul style="font-size:12px;color:#64748b;line-height:2;">
    <li>&#10140; Watch the live query as you type</li>
    <li>&#10140; What does a <code style="background:#334155;padding:1px 4px;border-radius:3px;color:#94a3b8;">'</code> do to the query structure?</li>
    <li>&#10140; Try the same payload on the patched form</li>
    <li>&#10140; Why doesn't the patched version reflect your input?</li>
  </ul>
</div>

</div>
</div>
</div>

<script>
${bjs}
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
}