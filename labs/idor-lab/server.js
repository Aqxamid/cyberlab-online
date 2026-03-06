const express = require('express');
const cors    = require('cors');
const app     = express();
const PORT    = process.env.PORT || 5001;

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
app.use(cors({ origin: FRONTEND_URL }));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── Mock data (intentionally vulnerable for teaching purposes) ────────────────
const users = {
  1:  { id: 1,  username: 'alice',   email: 'alice@corp.io',   role: 'employee', department: 'HR' },
  2:  { id: 2,  username: 'bob',     email: 'bob@corp.io',     role: 'employee', department: 'Engineering' },
  3:  { id: 3,  username: 'charlie', email: 'charlie@corp.io', role: 'employee', department: 'Marketing' },
  99: { id: 99, username: 'admin',   email: 'admin@corp.io',   role: 'admin',    department: 'Executive',
        secret: process.env.IDOR_USER_FLAG || 'FLAG{idor_is_dangerous_123}' },
};

const documents = {
  1:  { id: 1,  owner_id: 1,  title: 'Q1 Report',        content: "Alice's Q1 review.",         classification: 'internal' },
  2:  { id: 2,  owner_id: 2,  title: 'Project Roadmap',   content: "Bob's engineering roadmap.", classification: 'internal' },
  3:  { id: 3,  owner_id: 3,  title: 'Campaign Brief',    content: "Charlie's campaign brief.",  classification: 'internal' },
  42: { id: 42, owner_id: 99, title: 'Admin Credentials', content: `CONFIDENTIAL — ${process.env.IDOR_DOC_FLAG || 'FLAG{idor_docs_exposed_42}'}`, classification: 'top-secret' },
};

// ── Vulnerable endpoints (intentional IDOR for teaching) ─────────────────────
app.get('/api/vulnerable/users/:id',     (req, res) => {
  const u = users[+req.params.id];
  u ? res.json(u) : res.status(404).json({ error: 'Not found' });
});

app.get('/api/vulnerable/documents/:id', (req, res) => {
  const d = documents[+req.params.id];
  d ? res.json(d) : res.status(404).json({ error: 'Not found' });
});

app.get('/api/patched/users/:id', (req, res) => {
  const myId = +req.headers['x-user-id'];
  const tid  = +req.params.id;
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

// ── Lab UI (same HTML as before — unchanged for UX) ───────────────────────────
app.get('/', (req, res) => res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CorpPortal — IDOR Lab</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<style>body{font-family:'Inter',sans-serif;background:#f8fafc;} pre{background:#1e293b;color:#94a3b8;padding:1rem;border-radius:8px;font-size:0.75rem;overflow-x:auto;white-space:pre-wrap;} .flag{background:#fef9c3;border:2px solid #eab308;color:#713f12;padding:0.75rem;border-radius:8px;font-family:monospace;font-weight:700;font-size:0.85rem;}</style>
</head>
<body class="min-h-screen">
<nav class="bg-blue-700 text-white px-6 py-3 flex items-center justify-between shadow-lg">
  <div class="flex items-center gap-3">
    <div class="w-8 h-8 bg-white rounded flex items-center justify-center"><span class="text-blue-700 font-black text-sm">CP</span></div>
    <div><span class="font-bold">CorpPortal</span><span class="text-blue-300 text-sm ml-2">Employee Directory</span></div>
  </div>
  <div class="text-sm text-blue-200">Logged in as: <strong class="text-white">alice (ID: 1)</strong></div>
</nav>
<div class="max-w-5xl mx-auto px-4 py-8 space-y-6">
  <div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">
    <span class="text-2xl flex-shrink-0">⚠️</span>
    <div><p class="font-semibold text-amber-800 text-sm">IDOR Lab — Intentionally Vulnerable</p>
    <p class="text-amber-700 text-xs mt-1">You are logged in as Alice (ID: 1). Try fetching other users and documents by changing the ID.</p></div>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-white border border-gray-200 rounded-xl p-6 shadow-sm">
      <h2 class="font-bold text-gray-800 mb-1 flex items-center gap-2">👤 User Profile Viewer <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-normal">VULNERABLE</span></h2>
      <p class="text-xs text-gray-400 mb-4 font-mono">GET /api/vulnerable/users/:id</p>
      <div class="flex gap-2 mb-3">
        <input id="uid" type="number" value="1" class="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none">
        <button onclick="fetchUser()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">Fetch</button>
      </div>
      <div class="flex gap-2 mb-4 flex-wrap">
        <button onclick="setUid(1)" class="text-xs bg-gray-100 px-2 py-1 rounded">ID 1 (you)</button>
        <button onclick="setUid(2)" class="text-xs bg-gray-100 px-2 py-1 rounded">ID 2</button>
        <button onclick="setUid(99)" class="text-xs bg-red-100 text-red-700 px-2 py-1 rounded font-semibold">ID 99 🔴</button>
      </div>
      <pre id="user-out">// Click Fetch</pre>
      <div id="user-flag" class="flag hidden mt-3"></div>
    </div>
    <div class="bg-white border border-gray-200 rounded-xl p-6 shadow-sm">
      <h2 class="font-bold text-gray-800 mb-1 flex items-center gap-2">📄 Document Viewer <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded font-normal">VULNERABLE</span></h2>
      <p class="text-xs text-gray-400 mb-4 font-mono">GET /api/vulnerable/documents/:id</p>
      <div class="flex gap-2 mb-3">
        <input id="did" type="number" value="1" class="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none">
        <button onclick="fetchDoc()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">Fetch</button>
      </div>
      <div class="flex gap-2 mb-4 flex-wrap">
        <button onclick="setDid(1)" class="text-xs bg-gray-100 px-2 py-1 rounded">Doc 1</button>
        <button onclick="setDid(42)" class="text-xs bg-red-100 text-red-700 px-2 py-1 rounded font-semibold">Doc 42 🔴</button>
      </div>
      <pre id="doc-out">// Click Fetch</pre>
      <div id="doc-flag" class="flag hidden mt-3"></div>
    </div>
    <div class="bg-white border border-gray-200 rounded-xl p-6 shadow-sm lg:col-span-2">
      <h2 class="font-bold text-gray-800 mb-1 flex items-center gap-2">🛡️ Patched Endpoint Comparison <span class="text-xs bg-green-100 text-green-600 px-2 py-0.5 rounded">FIXED</span></h2>
      <p class="text-xs text-gray-400 mb-2">Try the same IDs here. Notice the ownership check blocks unauthorized access.</p>
      <p class="text-xs text-amber-600 mb-4">⚠️ Teaching note: x-user-id is still spoofable. Real auth uses a signed JWT — this demo shows <em>ownership checking</em>, not authentication.</p>
      <div class="grid grid-cols-3 gap-3 mb-3">
        <div><label class="text-xs text-gray-500 block mb-1">Your ID (x-user-id)</label><input id="my-id" type="number" value="1" class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"></div>
        <div><label class="text-xs text-gray-500 block mb-1">Target User ID</label><input id="p-uid" type="number" value="99" class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"></div>
        <div class="flex items-end"><button onclick="fetchPatched()" class="w-full bg-green-600 text-white px-4 py-2 rounded-lg text-sm">Try Patched</button></div>
      </div>
      <pre id="patch-out">// Try fetching user 99 with your-id=1</pre>
    </div>
  </div>
</div>
<script>
function setUid(v){document.getElementById('uid').value=v;fetchUser();}
function setDid(v){document.getElementById('did').value=v;fetchDoc();}
async function fetchUser(){
  const id=document.getElementById('uid').value,el=document.getElementById('user-out'),fl=document.getElementById('user-flag');
  try{const r=await fetch('/api/vulnerable/users/'+id),d=await r.json();el.textContent=JSON.stringify(d,null,2);const m=JSON.stringify(d).match(/FLAG\{[^}]+\}/);if(m){fl.textContent='🏁 Flag found: '+m[0];fl.classList.remove('hidden');}else fl.classList.add('hidden');}catch(e){el.textContent='Error: '+e.message;}
}
async function fetchDoc(){
  const id=document.getElementById('did').value,el=document.getElementById('doc-out'),fl=document.getElementById('doc-flag');
  try{const r=await fetch('/api/vulnerable/documents/'+id),d=await r.json();el.textContent=JSON.stringify(d,null,2);const m=JSON.stringify(d).match(/FLAG\{[^}]+\}/);if(m){fl.textContent='🏁 Flag: '+m[0];fl.classList.remove('hidden');}else fl.classList.add('hidden');}catch(e){el.textContent='Error: '+e.message;}
}
async function fetchPatched(){
  const myId=document.getElementById('my-id').value,tid=document.getElementById('p-uid').value,el=document.getElementById('patch-out');
  try{const r=await fetch('/api/patched/users/'+tid,{headers:{'x-user-id':myId}}),d=await r.json();el.textContent=(r.ok?'✅ ':'🚫 HTTP '+r.status+' — ')+JSON.stringify(d,null,2);}catch(e){el.textContent='Error: '+e.message;}
}
fetchUser();
<\/script>
</body></html>`));

app.listen(PORT, () => console.log(`🔓 IDOR Lab running on port ${PORT}`));