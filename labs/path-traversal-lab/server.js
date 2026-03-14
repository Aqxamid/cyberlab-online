const express = require('express');
const cors    = require('cors');
const path    = require('path');
const jwt     = require('jsonwebtoken');
const https   = require('https');
const http    = require('http');

const app  = express();
const PORT = process.env.PORT || 5005;

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
    console.warn('[path-lab] Backend unreachable for auth check:', err.message);
  }

  next();
}

app.use(requireLabAuth);
// ─────────────────────────────────────────────────────────────

// ── Fake filesystem for the lab ───────────────────────────────
const fakeFiles = {
  'welcome.txt':         'Welcome to FileServer! Your files are safe here.',
  'readme.txt':          'FileServer v1.0 — Upload and download your documents.',
  'docs/report.pdf':     'Q1 Financial Report — Revenue: $1.2M',
  'docs/meeting.txt':    'Meeting notes from 2025-01-15: Discussed Q1 targets.',
  '../secret.txt':       'FLAG{traversed_the_path} This is a secret file outside the uploads directory.',
  '../../etc/passwd':    'FLAG{traversed_the_path} root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...',
  '/etc/passwd':         'FLAG{traversed_the_path} root:x:0:0:root:/root:/bin/bash',
  '../../../etc/shadow':  'FLAG{traversed_the_path} root:$6$xyz:19000:0:99999:7:::',
};

// VULNERABLE: no sanitization
app.get('/api/vulnerable/file', (req, res) => {
  const filename = req.query.file;
  if (!filename) return res.status(400).json({ error: 'file param required' });

  // Simulate path traversal — check against fake filesystem
  const content = fakeFiles[filename] || fakeFiles[filename.replace(/\\/g, '/')];
  if (content) {
    const flag = content.match(/FLAG\{[^}]+\}/)?.[0] || null;
    return res.json({ filename, content, flag });
  }
  res.status(404).json({ error: `File not found: ${filename}` });
});

// PATCHED: normalise and jail to /files/
app.get('/api/patched/file', (req, res) => {
  const filename = req.query.file;
  if (!filename) return res.status(400).json({ error: 'file param required' });

  // Resolve and check it stays within the allowed directory
  const base    = '/files';
  const resolved = path.posix.normalize('/' + filename);
  if (!resolved.startsWith(base + '/') && resolved !== base) {
    return res.status(403).json({ error: 'Access denied: path is outside the allowed directory' });
  }

  // Safe files only
  const safeFiles = { '/files/welcome.txt': fakeFiles['welcome.txt'], '/files/readme.txt': fakeFiles['readme.txt'], '/files/docs/report.pdf': fakeFiles['docs/report.pdf'], '/files/docs/meeting.txt': fakeFiles['docs/meeting.txt'] };
  const content = safeFiles[resolved];
  if (content) return res.json({ filename: resolved, content });
  res.status(404).json({ error: `File not found: ${resolved}` });
});

app.get('/', (req, res) => {
  const token       = req.query.token || '';
  const backendUrl  = BACKEND_URL;
  const frontendUrl = FRONTEND_URL;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FileServer — Path Traversal Lab</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
body{font-family:'Inter',sans-serif;background:#f1f5f9;}
.mono{font-family:'JetBrains Mono',monospace;}
pre{background:#0f172a;color:#94a3b8;padding:1rem;border-radius:8px;font-size:0.75rem;overflow-x:auto;white-space:pre-wrap;}
.flag{background:#fef9c3;border:2px solid #eab308;color:#713f12;padding:0.75rem;border-radius:8px;font-family:monospace;font-weight:700;}
</style>
</head>
<body class="min-h-screen p-4 py-8">
<div class="max-w-4xl mx-auto space-y-6">
  <div class="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
    <div class="flex items-center gap-3 mb-1">
      <span class="text-3xl">📁</span>
      <div>
        <h1 class="text-xl font-bold text-gray-800">FileServer</h1>
        <p class="text-xs text-gray-400">Secure Document Storage — v1.0</p>
      </div>
      <span class="ml-auto text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-medium">PATH TRAVERSAL LAB</span>
    </div>
  </div>

  <div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">
    <span class="text-2xl flex-shrink-0">⚠️</span>
    <div>
      <p class="font-semibold text-amber-800 text-sm">Path Traversal Lab — Intentionally Vulnerable</p>
      <p class="text-amber-700 text-xs mt-1">The vulnerable endpoint doesn't sanitize the <code class="font-mono">file</code> parameter. Try escaping the uploads directory using <code class="font-mono">../</code> sequences to read secret files and get the flag.</p>
    </div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Vulnerable -->
    <div class="bg-white rounded-xl shadow-sm p-6 border border-red-200">
      <h2 class="font-bold text-gray-800 mb-1 flex items-center gap-2">
        📂 File Viewer
        <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded">VULNERABLE</span>
      </h2>
      <p class="text-xs text-gray-400 mb-4 mono">GET /api/vulnerable/file?file=...</p>
      <input id="v-file" type="text" value="welcome.txt" class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-red-400 mono" placeholder="filename or ../path">
      <div class="flex gap-2 flex-wrap mb-3">
        <button class="file-btn text-xs bg-gray-100 hover:bg-gray-200 px-2 py-1 rounded mono" data-f="welcome.txt">welcome.txt</button>
        <button class="file-btn text-xs bg-gray-100 hover:bg-gray-200 px-2 py-1 rounded mono" data-f="docs/report.pdf">docs/report.pdf</button>
        <button class="file-btn text-xs bg-red-100 hover:bg-red-200 text-red-700 px-2 py-1 rounded mono font-semibold" data-f="../secret.txt">../secret.txt 🔴</button>
        <button class="file-btn text-xs bg-red-100 hover:bg-red-200 text-red-700 px-2 py-1 rounded mono font-semibold" data-f="../../etc/passwd">../../etc/passwd 🔴</button>
      </div>
      <button id="v-fetch-btn" class="w-full bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg text-sm font-semibold transition-colors mb-3">Read File</button>
      <pre id="v-out">// Click Read File</pre>
      <div id="v-flag" class="flag hidden mt-3"></div>
    </div>

    <!-- Patched -->
    <div class="bg-white rounded-xl shadow-sm p-6 border border-green-200">
      <h2 class="font-bold text-gray-800 mb-1 flex items-center gap-2">
        🛡️ Patched Viewer
        <span class="text-xs bg-green-100 text-green-600 px-2 py-0.5 rounded">FIXED</span>
      </h2>
      <p class="text-xs text-gray-400 mb-4 mono">GET /api/patched/file?file=...</p>
      <input id="p-file" type="text" value="welcome.txt" class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-green-400 mono" placeholder="filename">
      <div class="flex gap-2 flex-wrap mb-3">
        <button class="pfile-btn text-xs bg-gray-100 hover:bg-gray-200 px-2 py-1 rounded mono" data-f="welcome.txt">welcome.txt</button>
        <button class="pfile-btn text-xs bg-gray-100 hover:bg-gray-200 px-2 py-1 rounded mono" data-f="docs/report.pdf">docs/report.pdf</button>
        <button class="pfile-btn text-xs bg-orange-100 text-orange-700 px-2 py-1 rounded mono" data-f="../secret.txt">../secret.txt (blocked)</button>
        <button class="pfile-btn text-xs bg-orange-100 text-orange-700 px-2 py-1 rounded mono" data-f="../../etc/passwd">../../etc/passwd (blocked)</button>
      </div>
      <button id="p-fetch-btn" class="w-full bg-green-600 hover:bg-green-700 text-white py-2 rounded-lg text-sm font-semibold transition-colors mb-3">Read File (Safe)</button>
      <pre id="p-out">// Jails to /files/ — traversal blocked</pre>
    </div>
  </div>
</div>

<script>
document.querySelectorAll('.file-btn').forEach(b => b.addEventListener('click', () => { document.getElementById('v-file').value=b.dataset.f; fetchVuln(); }));
document.querySelectorAll('.pfile-btn').forEach(b => b.addEventListener('click', () => { document.getElementById('p-file').value=b.dataset.f; fetchPatched(); }));
document.getElementById('v-fetch-btn').addEventListener('click', fetchVuln);
document.getElementById('p-fetch-btn').addEventListener('click', fetchPatched);

async function fetchVuln(){
  const f=document.getElementById('v-file').value, el=document.getElementById('v-out'), fl=document.getElementById('v-flag');
  try{
    const r=await fetch('/api/vulnerable/file?file='+encodeURIComponent(f)), d=await r.json();
    el.textContent=JSON.stringify(d,null,2);
    if(d.flag){ fl.textContent='🏁 Flag found: '+d.flag; fl.classList.remove('hidden'); } else fl.classList.add('hidden');
  }catch(e){ el.textContent='Error: '+e.message; }
}
async function fetchPatched(){
  const f=document.getElementById('p-file').value, el=document.getElementById('p-out');
  try{
    const r=await fetch('/api/patched/file?file='+encodeURIComponent(f)), d=await r.json();
    el.textContent=(r.ok?'✅ ':'🚫 HTTP '+r.status+' — ')+JSON.stringify(d,null,2);
  }catch(e){ el.textContent='Error: '+e.message; }
}
<\/script>

<!-- ── 30-second auth re-check ── -->
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
</body></html>`);
});

app.listen(PORT, () => console.log(`📁 Path Traversal Lab running on http://localhost:${PORT}`));