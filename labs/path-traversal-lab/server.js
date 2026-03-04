const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 5005;

app.use(cors());
app.use(express.json());

// Fake filesystem
const fakeFiles = {
  'reports/q1.pdf':       'Q1 Financial Report - Revenue: $1.2M, Expenses: $800K',
  'reports/q2.pdf':       'Q2 Financial Report - Revenue: $1.5M, Expenses: $900K',
  'reports/annual.pdf':   'Annual Report 2024 - Total Revenue: $5.4M',
  'public/about.txt':     'FileServer Corp — Secure Document Storage',
  'public/help.txt':      'Contact support@fileserver.corp for help.',
  '../etc/passwd':        'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh',
  '../../etc/passwd':     'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh',
  '../../../etc/passwd':  'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh',
  '../../../../etc/passwd':'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh',
  '../config/.env':       'DB_PASSWORD=sup3rs3cr3t\nAPI_KEY=sk-prod-FLAG{traversed_the_path}\nSECRET=hunter2',
  '../../config/.env':    'DB_PASSWORD=sup3rs3cr3t\nAPI_KEY=sk-prod-FLAG{traversed_the_path}\nSECRET=hunter2',
  '../.env':              'DB_PASSWORD=sup3rs3cr3t\nAPI_KEY=sk-prod-FLAG{traversed_the_path}',
};

// VULNERABLE — no path sanitization
app.get('/api/vulnerable/download', (req, res) => {
  const file = req.query.file;
  if (!file) return res.status(400).json({ error: 'file parameter required' });
  const content = fakeFiles[file];
  if (content) return res.json({ file, content, flag: content.includes('FLAG{') ? content.match(/FLAG\{[^}]+\}/)[0] : null });
  res.status(404).json({ error: `File not found: ${file}` });
});

// PATCHED — validates path stays within /reports/
app.get('/api/patched/download', (req, res) => {
  const file = req.query.file || '';
  if (file.includes('..') || file.includes('/etc') || file.startsWith('/')) {
    return res.status(400).json({ error: 'Invalid file path: directory traversal detected' });
  }
  const allowed = ['reports/q1.pdf', 'reports/q2.pdf', 'reports/annual.pdf', 'public/about.txt'];
  if (!allowed.includes(file)) return res.status(403).json({ error: 'Access denied: file not in allowed list' });
  const content = fakeFiles[file];
  res.json({ file, content });
});

app.get('/', (req, res) => res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FileServer — Path Traversal Lab</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
<style>body{font-family:'Inter',sans-serif;background:#f8fafc;} pre{background:#1e293b;color:#94a3b8;padding:1rem;border-radius:8px;font-size:0.75rem;overflow-x:auto;white-space:pre-wrap;} .mono{font-family:'JetBrains Mono',monospace;} .flag{background:#fef9c3;border:2px solid #eab308;color:#713f12;padding:0.75rem;border-radius:8px;font-family:monospace;font-weight:700;}</style>
</head>
<body>
<nav class="bg-gray-800 text-white px-6 py-3 flex items-center justify-between shadow-lg">
  <div class="flex items-center gap-2"><span class="text-xl">📁</span><span class="font-bold">FileServer Corp</span><span class="text-xs bg-red-500 text-white px-2 py-0.5 rounded ml-2">Path Traversal Lab</span></div>
  <span class="text-gray-400 text-xs">Secure Document Portal</span>
</nav>
<div class="max-w-5xl mx-auto px-4 py-8 space-y-6">
  <div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">
    <span class="text-2xl flex-shrink-0">⚠️</span>
    <div><p class="font-semibold text-amber-800 text-sm">Path Traversal Lab — Intentionally Vulnerable File Server</p><p class="text-amber-700 text-xs mt-1">The download endpoint uses the filename directly without sanitization. Use <code class="bg-amber-100 px-1 rounded mono">../</code> sequences to escape the web root and access sensitive files.</p></div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- File browser -->
    <div class="bg-white border border-gray-200 rounded-xl p-5 shadow-sm">
      <h2 class="font-bold text-gray-800 mb-3 text-sm">📂 Available Files</h2>
      <p class="text-xs text-gray-400 mb-3">These are the "intended" files you can download:</p>
      <div class="space-y-1">
        <button onclick="setFile('reports/q1.pdf')" class="w-full text-left text-xs bg-blue-50 hover:bg-blue-100 text-blue-700 px-3 py-2 rounded flex items-center gap-2 transition-colors">📄 reports/q1.pdf</button>
        <button onclick="setFile('reports/q2.pdf')" class="w-full text-left text-xs bg-blue-50 hover:bg-blue-100 text-blue-700 px-3 py-2 rounded flex items-center gap-2 transition-colors">📄 reports/q2.pdf</button>
        <button onclick="setFile('reports/annual.pdf')" class="w-full text-left text-xs bg-blue-50 hover:bg-blue-100 text-blue-700 px-3 py-2 rounded flex items-center gap-2 transition-colors">📄 reports/annual.pdf</button>
        <button onclick="setFile('public/about.txt')" class="w-full text-left text-xs bg-gray-50 hover:bg-gray-100 text-gray-600 px-3 py-2 rounded flex items-center gap-2 transition-colors">📄 public/about.txt</button>
      </div>
      <div class="border-t border-gray-100 mt-4 pt-3">
        <p class="text-xs text-red-500 font-semibold mb-2">🎯 Attack Payloads:</p>
        <div class="space-y-1">
          <button onclick="setFile('../etc/passwd')" class="w-full text-left text-xs bg-red-50 hover:bg-red-100 text-red-600 px-3 py-2 rounded mono transition-colors">../etc/passwd</button>
          <button onclick="setFile('../../../../etc/passwd')" class="w-full text-left text-xs bg-red-50 hover:bg-red-100 text-red-600 px-3 py-2 rounded mono transition-colors">../../../../etc/passwd</button>
          <button onclick="setFile('../config/.env')" class="w-full text-left text-xs bg-red-50 hover:bg-red-100 text-red-600 px-3 py-2 rounded mono transition-colors font-semibold">../config/.env 🏁</button>
          <button onclick="setFile('../../config/.env')" class="w-full text-left text-xs bg-red-50 hover:bg-red-100 text-red-600 px-3 py-2 rounded mono transition-colors">../../config/.env</button>
        </div>
      </div>
    </div>

    <!-- Main panel -->
    <div class="lg:col-span-2 space-y-4">
      <div class="bg-white border border-gray-200 rounded-xl p-5 shadow-sm">
        <h2 class="font-bold text-gray-800 mb-1 flex items-center gap-2">⬇️ File Download <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded">VULNERABLE</span></h2>
        <p class="text-xs text-gray-400 mb-4 mono">GET /api/vulnerable/download?file=...</p>
        <div class="flex gap-2 mb-4">
          <input id="file-path" type="text" value="reports/q1.pdf" class="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm mono focus:outline-none focus:ring-2 focus:ring-blue-400">
          <button onclick="fetchFile()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">Download</button>
        </div>
        <pre id="file-out">// Click a file or enter a path</pre>
        <div id="file-flag" class="flag hidden mt-3"></div>
      </div>

      <div class="bg-white border border-gray-200 rounded-xl p-5 shadow-sm">
        <h2 class="font-bold text-gray-800 mb-3 flex items-center gap-2 text-sm">✅ Patched Endpoint <span class="text-xs bg-green-100 text-green-600 px-2 py-0.5 rounded">Path validation</span></h2>
        <div class="flex gap-2 mb-3">
          <input id="p-file-path" type="text" placeholder="Try same traversal payloads..." class="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm mono focus:outline-none focus:ring-2 focus:ring-green-400">
          <button onclick="fetchPatched()" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">Try Patched</button>
        </div>
        <pre id="p-file-out">// Patched version detects and blocks traversal sequences</pre>
      </div>
    </div>
  </div>
</div>
<script>
function setFile(v){document.getElementById('file-path').value=v;fetchFile();}
async function fetchFile(){
  const f=document.getElementById('file-path').value,el=document.getElementById('file-out'),fl=document.getElementById('file-flag');
  try{const r=await fetch('/api/vulnerable/download?file='+encodeURIComponent(f));const d=await r.json();el.textContent=JSON.stringify(d,null,2);if(d.flag){fl.textContent='🏁 Flag found: '+d.flag;fl.classList.remove('hidden');}else fl.classList.add('hidden');}catch(e){el.textContent='Error: '+e.message;}
}
async function fetchPatched(){
  const f=document.getElementById('p-file-path').value,el=document.getElementById('p-file-out');
  try{const r=await fetch('/api/patched/download?file='+encodeURIComponent(f));const d=await r.json();el.textContent=(r.ok?'✅ ':'🚫 HTTP '+r.status+' — ')+JSON.stringify(d,null,2);}catch(e){el.textContent='Error: '+e.message;}
}
fetchFile();
<\/script>
</body></html>`));

app.listen(PORT, () => console.log(`📁 Path Traversal Lab running on http://localhost:${PORT}`));
