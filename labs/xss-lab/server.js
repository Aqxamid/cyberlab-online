const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 5003;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

let comments = [
  { id: 1, author: 'alice', text: 'Great article! Really helpful content.', timestamp: new Date(Date.now()-3600000).toISOString() },
  { id: 2, author: 'bob',   text: 'Thanks for sharing this.', timestamp: new Date(Date.now()-1800000).toISOString() },
];
let nextId = 3;

// Vulnerable — returns raw unsanitized HTML
app.get('/api/vulnerable/search', (req, res) => {
  const q = req.query.q || '';
  res.json({ query: q, results: [], reflected: q }); // reflects input back unsanitized
});
app.get('/api/vulnerable/comments', (req, res) => res.json(comments));
app.post('/api/vulnerable/comments', (req, res) => {
  const { author, text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const c = { id: nextId++, author: author || 'anonymous', text, timestamp: new Date().toISOString() };
  comments.push(c);
  res.status(201).json(c);
});

// Patched — sanitizes output
app.get('/api/patched/search', (req, res) => {
  const q = req.query.q || '';
  const safe = q.replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#x27;'}[c]));
  res.json({ query: safe, results: [], reflected: safe });
});

app.get('/', (req, res) => res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TechBlog — XSS Lab</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>body{font-family:'Inter',sans-serif;background:#f9fafb;} pre{background:#0f172a;color:#94a3b8;padding:0.75rem;border-radius:8px;font-size:0.75rem;overflow-x:auto;white-space:pre-wrap;}</style>
</head>
<body>
<nav class="bg-white border-b border-gray-200 px-6 py-3 flex items-center justify-between shadow-sm">
  <div class="flex items-center gap-2"><span class="text-2xl">📰</span><span class="font-bold text-gray-800">TechBlog</span><span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded ml-2">XSS Lab</span></div>
  <div class="text-xs text-gray-400">Intentionally Vulnerable Blog</div>
</nav>
<div class="max-w-4xl mx-auto px-4 py-8 space-y-6">
  <div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">
    <span class="text-2xl flex-shrink-0">⚠️</span>
    <div><p class="font-semibold text-amber-800 text-sm">XSS Lab — Stored & Reflected XSS</p><p class="text-amber-700 text-xs mt-1">This blog has two XSS vulnerabilities. Try injecting scripts in the search box (reflected XSS) and in the comment form (stored XSS).</p></div>
  </div>

  <!-- Reflected XSS -->
  <div class="bg-white rounded-xl border border-gray-200 p-6 shadow-sm">
    <h2 class="font-bold text-gray-800 mb-1 flex items-center gap-2">🔍 Search Articles <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded">REFLECTED XSS</span></h2>
    <p class="text-xs text-gray-400 mb-4">Search input is reflected directly into the page without sanitization.</p>
    <div class="flex gap-2 mb-3">
      <input id="search-q" type="text" placeholder='Try: &lt;script&gt;alert("XSS")&lt;/script&gt;' class="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 font-mono">
      <button onclick="doSearch()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium">Search</button>
    </div>
    <div class="flex gap-2 mb-3 flex-wrap">
      <button onclick="setSearch('<img src=x onerror=alert(1)>')" class="text-xs bg-red-100 text-red-600 hover:bg-red-200 px-2 py-1 rounded font-mono">&lt;img onerror&gt;</button>
      <button onclick="setSearch('<script>alert(document.cookie)<\/script>')" class="text-xs bg-red-100 text-red-600 hover:bg-red-200 px-2 py-1 rounded font-mono">cookie steal</button>
      <button onclick="setSearch('FLAG{xss_reflected_pwned}')" class="text-xs bg-yellow-100 text-yellow-700 hover:bg-yellow-200 px-2 py-1 rounded">get flag</button>
    </div>
    <div class="bg-gray-50 rounded-lg p-3 text-sm">
      <p class="text-gray-500 text-xs mb-1">Search results for:</p>
      <div id="search-result" class="font-medium text-gray-800"></div>
    </div>
    <div id="search-flag" class="hidden mt-3 bg-yellow-100 border-2 border-yellow-400 text-yellow-800 rounded-lg p-3 font-mono font-bold text-sm">🏁 FLAG{xss_reflected_pwned}</div>
  </div>

  <!-- Stored XSS -->
  <div class="bg-white rounded-xl border border-gray-200 p-6 shadow-sm">
    <h2 class="font-bold text-gray-800 mb-1 flex items-center gap-2">💬 Comments <span class="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded">STORED XSS</span></h2>
    <p class="text-xs text-gray-400 mb-4">Comments are stored and rendered without sanitization — scripts execute for every visitor.</p>
    <div id="comments-list" class="space-y-3 mb-4"></div>
    <div class="border-t border-gray-100 pt-4">
      <p class="text-xs font-semibold text-gray-600 mb-2">Leave a comment:</p>
      <input id="c-author" type="text" placeholder="Your name" class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-blue-400">
      <textarea id="c-text" placeholder='Try: <img src=x onerror="alert(document.cookie)">' rows="3" class="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm mb-2 focus:outline-none focus:ring-2 focus:ring-blue-400 font-mono resize-none"></textarea>
      <div class="flex gap-2 mb-2 flex-wrap">
        <button onclick="setComment('<script>alert(\"Stored XSS!\")<\/script>')" class="text-xs bg-red-100 text-red-600 hover:bg-red-200 px-2 py-1 rounded font-mono">script tag</button>
        <button onclick="setComment('<img src=x onerror=alert(1)>')" class="text-xs bg-red-100 text-red-600 hover:bg-red-200 px-2 py-1 rounded font-mono">img onerror</button>
        <button onclick="setComment('Normal comment here!')" class="text-xs bg-gray-100 hover:bg-gray-200 px-2 py-1 rounded">Normal</button>
      </div>
      <button onclick="postComment()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium">Post Comment</button>
    </div>
  </div>

  <!-- Patched -->
  <div class="bg-white rounded-xl border border-gray-200 p-6 shadow-sm">
    <h2 class="font-bold text-gray-800 mb-3 flex items-center gap-2">✅ Patched Search <span class="text-xs bg-green-100 text-green-600 px-2 py-0.5 rounded">HTML Escaped</span></h2>
    <div class="flex gap-2 mb-3">
      <input id="p-search" type="text" placeholder="Try same XSS payloads here..." class="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-green-400 font-mono">
      <button onclick="doPatchSearch()" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-medium">Search (Safe)</button>
    </div>
    <pre id="p-search-out">// Patched version escapes HTML characters</pre>
  </div>
</div>
<script>
function setSearch(v){document.getElementById('search-q').value=v;doSearch();}
function setComment(v){document.getElementById('c-text').value=v;}
async function doSearch(){
  const q=document.getElementById('search-q').value;
  // Directly inject into innerHTML to demonstrate reflected XSS
  document.getElementById('search-result').innerHTML=q;
  if(q.includes('FLAG{')){document.getElementById('search-flag').classList.remove('hidden');}
  else{document.getElementById('search-flag').classList.add('hidden');}
}
async function postComment(){
  const author=document.getElementById('c-author').value||'Anonymous',text=document.getElementById('c-text').value;
  if(!text)return;
  try{await fetch('/api/vulnerable/comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({author,text})});document.getElementById('c-text').value='';loadComments();}catch(e){alert('Error: '+e.message);}
}
async function loadComments(){
  const r=await fetch('/api/vulnerable/comments'),comments=await r.json();
  const el=document.getElementById('comments-list');
  el.innerHTML=comments.map(c=>'<div class="border border-gray-100 rounded-lg p-3"><div class="flex items-center gap-2 mb-1"><span class="text-xs font-semibold text-gray-700">'+c.author+'</span><span class="text-xs text-gray-400">'+new Date(c.timestamp).toLocaleString()+'</span></div><div class="text-sm text-gray-600">'+c.text+'</div></div>').join('');
  // NOTE: c.text is rendered as innerHTML intentionally for XSS demo
}
async function doPatchSearch(){
  const q=document.getElementById('p-search').value;
  const r=await fetch('/api/patched/search?q='+encodeURIComponent(q));
  const d=await r.json();
  document.getElementById('p-search-out').textContent='Sanitized output: '+d.reflected+'\n(Scripts are escaped and won\'t execute)';
}
loadComments();
<\/script>
</body></html>`));

app.listen(PORT, () => console.log(`🕷️  XSS Lab running on http://localhost:${PORT}`));
