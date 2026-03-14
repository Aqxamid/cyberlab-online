const express = require('express');
const cors    = require('cors');
const jwt     = require('jsonwebtoken');
const https   = require('https');
const http    = require('http');

const app  = express();
const PORT = process.env.PORT || 5003;

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
    console.warn('[xss-lab] Backend unreachable for auth check:', err.message);
  }

  next();
}

app.use(requireLabAuth);
// ─────────────────────────────────────────────────────────────

let comments = [
  { id:1, author:'alice', text:'Great article! Really helpful content.', timestamp: new Date(Date.now()-3600000).toISOString() },
  { id:2, author:'bob',   text:'Thanks for sharing this.',               timestamp: new Date(Date.now()-1800000).toISOString() },
];
let nextId = 3;

app.get('/api/flag', (req, res) => res.json({ flag: 'FLAG{xss_reflected_pwned}' }));

app.get('/api/vulnerable/comments',  (req, res) => res.json(comments));
app.post('/api/vulnerable/comments', (req, res) => {
  const { author, text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const c = { id: nextId++, author: author || 'anonymous', text, timestamp: new Date().toISOString() };
  comments.push(c);
  res.status(201).json(c);
});
app.post('/api/vulnerable/comments/reset', (req, res) => {
  comments = [
    { id:1, author:'alice', text:'Great article! Really helpful content.', timestamp: new Date(Date.now()-3600000).toISOString() },
    { id:2, author:'bob',   text:'Thanks for sharing this.',               timestamp: new Date(Date.now()-1800000).toISOString() },
  ];
  nextId = 3;
  res.json({ ok: true });
});
app.get('/api/patched/search', (req, res) => {
  const q    = req.query.q || '';
  const safe = q.replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#x27;'}[c]));
  res.json({ reflected: safe });
});

app.get('/', (req, res) => {
  const token       = req.query.token || '';
  const backendUrl  = BACKEND_URL;
  const frontendUrl = FRONTEND_URL;

  const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TechBlog - XSS Lab</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  body { font-family: 'IBM Plex Sans', sans-serif; background: #0d1117; color: #e6edf3; }
  code, .font-mono, input.font-mono, textarea.font-mono { font-family: 'JetBrains Mono', monospace; }
  pre { background: #161b22; color: #8b949e; padding: 0.75rem; border-radius: 8px; font-size: 0.75rem; overflow-x: auto; white-space: pre-wrap; font-family: 'JetBrains Mono', monospace; border: 1px solid #30363d; }
  .flag-box { background: #2d2a00; border: 2px solid #eab308; color: #fef08a; padding: 0.75rem 1rem; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 0.9rem; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; }
  input, textarea { background: #0d1117 !important; color: #e6edf3 !important; border-color: #30363d !important; }
  input::placeholder, textarea::placeholder { color: #484f58 !important; }
  input:focus, textarea:focus { border-color: #58a6ff !important; box-shadow: 0 0 0 3px rgba(88,166,255,0.15) !important; }
  .search-result-area { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; }
  ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: #161b22; } ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
</style>
</head>
<body>
<nav class="border-b border-gray-800 px-6 py-3 flex items-center justify-between" style="background:#161b22">
  <div class="flex items-center gap-2">
    <span class="text-2xl">📰</span>
    <span class="font-bold text-white">TechBlog</span>
    <span class="text-xs px-2 py-0.5 rounded ml-2" style="background:#3d1a1a;color:#f85149">XSS Lab</span>
  </div>
  <div class="text-xs" style="color:#484f58">Intentionally Vulnerable Demo</div>
</nav>
<div class="max-w-4xl mx-auto px-4 py-8 space-y-6">
  <div class="rounded-xl p-4 flex gap-3" style="background:#271c00;border:1px solid #9e6a03">
    <span class="text-2xl flex-shrink-0">⚠️</span>
    <div>
      <p class="font-semibold text-sm" style="color:#d29922">XSS Lab — Reflected &amp; Stored XSS</p>
      <p class="text-xs mt-1" style="color:#b08800"><strong>To get the flag:</strong> inject a script that calls <code class="px-1 rounded" style="background:#3d2e00">fetch('/api/flag')</code> and displays the result. Use the hint buttons below if you get stuck.</p>
    </div>
  </div>
  <!-- Reflected XSS -->
  <div class="card p-6 shadow-sm">
    <h2 class="font-bold mb-1 flex items-center gap-2 text-white">🔍 Search Articles <span class="text-xs px-2 py-0.5 rounded" style="background:#3d1a1a;color:#f85149">REFLECTED XSS</span></h2>
    <p class="text-xs mb-4" style="color:#8b949e">Input is reflected directly into the page as raw HTML — no sanitization.</p>
    <div class="flex gap-2 mb-3">
      <input id="search-q" type="text" placeholder='Try: &lt;img src=x onerror=alert(1)&gt;' class="flex-1 border rounded-lg px-3 py-2 text-sm focus:outline-none font-mono">
      <button id="search-btn" class="text-white px-4 py-2 rounded-lg text-sm font-medium" style="background:#238636">Search</button>
    </div>
    <div class="flex gap-2 mb-4 flex-wrap items-center">
      <span class="text-xs" style="color:#8b949e">Hints:</span>
      <button id="hint-alert"  class="text-xs px-2 py-1 rounded font-mono" style="background:#2d1c00;color:#d29922">alert(1)</button>
      <button id="hint-cookie" class="text-xs px-2 py-1 rounded font-mono" style="background:#2d1c00;color:#d29922">steal cookie</button>
      <button id="hint-flag"   class="text-xs px-2 py-1 rounded font-semibold" style="background:#1b3a2a;color:#3fb950">🏁 get flag payload</button>
    </div>
    <div class="search-result-area p-3 text-sm mb-3">
      <p class="text-xs mb-2" style="color:#484f58">Page renders your input here (innerHTML):</p>
      <div id="search-result" class="min-h-8" style="color:#e6edf3"></div>
    </div>
    <div id="flag-display" class="hidden flag-box"></div>
  </div>
  <!-- Stored XSS -->
  <div class="card p-6 shadow-sm">
    <h2 class="font-bold mb-1 flex items-center gap-2 text-white">💬 Comments <span class="text-xs px-2 py-0.5 rounded" style="background:#3d1a1a;color:#f85149">STORED XSS</span></h2>
    <p class="text-xs mb-4" style="color:#8b949e">Comments are stored and rendered as raw HTML for every visitor.</p>
    <div id="comments-list" class="space-y-3 mb-4"></div>
    <div class="pt-4 space-y-2" style="border-top:1px solid #30363d">
      <p class="text-xs font-semibold" style="color:#8b949e">Leave a comment:</p>
      <input id="c-author" type="text" placeholder="Your name" class="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none">
      <textarea id="c-text" rows="3" placeholder="Try an XSS payload as your comment..." class="w-full border rounded-lg px-3 py-2 text-sm focus:outline-none font-mono resize-none"></textarea>
      <div class="flex gap-2 flex-wrap">
        <button id="cmnt-hint-alert" class="text-xs px-2 py-1 rounded font-mono" style="background:#2d1c00;color:#d29922">alert payload</button>
        <button id="cmnt-hint-flag"  class="text-xs px-2 py-1 rounded font-semibold" style="background:#1b3a2a;color:#3fb950">🏁 flag payload</button>
        <button id="cmnt-normal"     class="text-xs px-2 py-1 rounded" style="background:#21262d;color:#8b949e">normal comment</button>
        <button id="cmnt-clear"      class="text-xs px-2 py-1 rounded" style="background:#3d1a1a;color:#f85149">🗑 clear comments</button>
      </div>
      <button id="post-btn" class="text-white px-4 py-2 rounded-lg text-sm font-medium" style="background:#238636">Post Comment</button>
    </div>
  </div>
  <!-- Patched -->
  <div class="card p-6 shadow-sm">
    <h2 class="font-bold mb-3 flex items-center gap-2 text-white">✅ Patched Search <span class="text-xs px-2 py-0.5 rounded" style="background:#1b3a2a;color:#3fb950">HTML Escaped</span></h2>
    <div class="flex gap-2 mb-3">
      <input id="p-search" type="text" placeholder="Try same payloads here..." class="flex-1 border rounded-lg px-3 py-2 text-sm focus:outline-none font-mono">
      <button id="p-search-btn" class="text-white px-4 py-2 rounded-lg text-sm font-medium" style="background:#1f6feb">Search (Safe)</button>
    </div>
    <pre id="p-search-out">// Patched version escapes HTML — scripts won't execute</pre>
  </div>
</div>
<script>
  const PAYLOADS = {
    alertImg:     '<img src=x onerror=alert(1)>',
    cookieImg:    '<img src=x onerror=alert(document.cookie)>',
    flagScript:   '<img src=x onerror="fetch(\\'/api/flag\\').then(r=>r.json()).then(d=>{ document.getElementById(\\'flag-display\\').textContent=\\'🏁 \\'+d.flag; document.getElementById(\\'flag-display\\').classList.remove(\\'hidden\\'); })">',
    commentAlert: '<img src=x onerror=alert("Stored XSS!")>',
    commentFlag:  '<img src=x onerror="fetch(\\'/api/flag\\').then(r=>r.json()).then(d=>{ var b=document.createElement(\\'div\\'); b.style.cssText=\\'position:fixed;top:20px;right:20px;background:#2d2a00;border:3px solid #eab308;padding:15px;font-weight:bold;font-size:16px;border-radius:8px;z-index:9999;color:#fef08a\\'; b.textContent=\\'🏁 \\'+d.flag; document.body.appendChild(b); setTimeout(()=>b.remove(),8000); })">'
  };
  document.getElementById('hint-alert').addEventListener('click',  () => { document.getElementById('search-q').value = PAYLOADS.alertImg;     doSearch(); });
  document.getElementById('hint-cookie').addEventListener('click', () => { document.getElementById('search-q').value = PAYLOADS.cookieImg;    doSearch(); });
  document.getElementById('hint-flag').addEventListener('click',   () => { document.getElementById('search-q').value = PAYLOADS.flagScript;   doSearch(); });
  document.getElementById('cmnt-hint-alert').addEventListener('click', () => { document.getElementById('c-text').value = PAYLOADS.commentAlert; });
  document.getElementById('cmnt-hint-flag').addEventListener('click',  () => { document.getElementById('c-text').value = PAYLOADS.commentFlag;  });
  document.getElementById('cmnt-normal').addEventListener('click',     () => { document.getElementById('c-text').value = 'This is a normal comment, nothing suspicious here!'; });
  document.getElementById('cmnt-clear').addEventListener('click', async () => { await fetch('/api/vulnerable/comments/reset',{method:'POST'}); loadComments(); });
  document.getElementById('search-btn').addEventListener('click', doSearch);
  document.getElementById('search-q').addEventListener('keydown', e => { if(e.key==='Enter') doSearch(); });
  document.getElementById('post-btn').addEventListener('click', postComment);
  document.getElementById('p-search-btn').addEventListener('click', doPatchSearch);
  document.getElementById('p-search').addEventListener('keydown', e => { if(e.key==='Enter') doPatchSearch(); });
  function doSearch(){ document.getElementById('search-result').innerHTML = document.getElementById('search-q').value; }
  async function postComment(){
    const author=document.getElementById('c-author').value||'Anonymous', text=document.getElementById('c-text').value;
    if(!text) return;
    await fetch('/api/vulnerable/comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({author,text})});
    document.getElementById('c-text').value=''; loadComments();
  }
  async function loadComments(){
    const r=await fetch('/api/vulnerable/comments'), list=await r.json();
    document.getElementById('comments-list').innerHTML=list.map(c=>
      '<div class="p-3 rounded-lg" style="border:1px solid #30363d">'
      +'<div class="flex items-center gap-2 mb-1"><span class="text-xs font-semibold" style="color:#58a6ff">'+c.author+'</span>'
      +'<span class="text-xs" style="color:#484f58">'+new Date(c.timestamp).toLocaleString()+'</span></div>'
      +'<div class="text-sm" style="color:#c9d1d9">'+c.text+'</div></div>'
    ).join('');
  }
  async function doPatchSearch(){
    const q=document.getElementById('p-search').value;
    const r=await fetch('/api/patched/search?q='+encodeURIComponent(q)), d=await r.json();
    document.getElementById('p-search-out').textContent='Sanitized output: '+d.reflected+'\\n(HTML chars escaped — safe to render)';
  }
  loadComments();
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
</body></html>`;

  res.send(HTML);
});

app.listen(PORT, () => console.log('🕷️  XSS Lab running on http://localhost:' + PORT));