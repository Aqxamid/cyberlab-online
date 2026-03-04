const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 5002;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const fakeDb = [
  { id:1, username:'alice', password:'alice123',    role:'user',  secret:null },
  { id:2, username:'bob',   password:'bob456',      role:'user',  secret:null },
  { id:3, username:'admin', password:'sup3rs3cr3t', role:'admin', secret:'FLAG{sql_injected_success}' },
];

app.post('/api/vulnerable/login', (req, res) => {
  const { username, password } = req.body;
  const simulatedQuery = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  const isBypass = /'\s*OR\s*['"]?1['"]?\s*=\s*['"]?1['"]?|'\s*OR\s*1\s*=\s*1\s*--|'\s*--/i.test(username + password);
  const exactMatch = fakeDb.find(u => u.username === username && u.password === password);
  if (isBypass) {
    return res.json({ success:true, bypassed:true, query:simulatedQuery, user:fakeDb[2], message:'SQLi bypass successful!', flag:'FLAG{sql_injected_success}' });
  }
  if (exactMatch) {
    return res.json({ success:true, bypassed:false, query:simulatedQuery, user:exactMatch, message:`Welcome back, ${exactMatch.username}!` });
  }
  res.status(401).json({ success:false, query:simulatedQuery, message:'Invalid username or password.' });
});

app.post('/api/patched/login', (req, res) => {
  const { username, password } = req.body;
  const user = fakeDb.find(u => u.username === username && u.password === password);
  if (user) return res.json({ success:true, user:{ id:user.id, username:user.username, role:user.role }, message:`Welcome, ${user.username}!` });
  res.status(401).json({ success:false, message:'Invalid username or password.' });
});

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BankSecure Login - SQLi Lab</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  body{font-family:'Inter',sans-serif;background:linear-gradient(135deg,#1e3a5f 0%,#0f2340 100%);min-height:100vh;}
  pre{background:#0f172a;color:#94a3b8;padding:1rem;border-radius:8px;font-size:0.75rem;overflow-x:auto;white-space:pre-wrap;}
  .flag{background:#fef9c3;border:2px solid #eab308;color:#713f12;padding:0.75rem;border-radius:8px;font-family:monospace;font-weight:700;}
</style>
</head>
<body class="flex items-center justify-center p-4 py-12">
<div class="w-full max-w-4xl space-y-6">

  <div class="bg-amber-50 border-l-4 border-amber-400 rounded-xl p-4 flex gap-3">
    <span class="text-2xl">⚠️</span>
    <div>
      <p class="font-semibold text-amber-800 text-sm">SQL Injection Lab — Intentionally Vulnerable Login</p>
      <p class="text-amber-700 text-xs mt-1">This login is vulnerable to SQL injection. Use the payload buttons to bypass authentication and get the admin flag.</p>
    </div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

    <div class="bg-white rounded-2xl shadow-2xl overflow-hidden">
      <div class="bg-gradient-to-r from-blue-800 to-blue-900 p-6 text-center">
        <div class="w-12 h-12 bg-white/20 rounded-full flex items-center justify-center mx-auto mb-3"><span class="text-2xl">🏦</span></div>
        <h1 class="text-white font-bold text-xl">BankSecure</h1>
        <p class="text-blue-300 text-xs mt-1">Online Banking Portal</p>
        <span class="inline-block mt-2 text-xs bg-red-500 text-white px-2 py-0.5 rounded">VULNERABLE</span>
      </div>
      <div class="p-6 space-y-4">
        <div>
          <label class="text-xs text-gray-500 uppercase tracking-wide block mb-1.5">Username</label>
          <input id="v-user" type="text" placeholder="Try a payload below" class="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 font-mono">
        </div>
        <div>
          <label class="text-xs text-gray-500 uppercase tracking-wide block mb-1.5">Password</label>
          <input id="v-pass" type="text" placeholder="anything" class="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 font-mono">
        </div>
        <div class="flex gap-2 flex-wrap">
          <button class="payload-btn text-xs bg-red-100 text-red-700 hover:bg-red-200 px-2 py-1 rounded font-mono" data-u="' OR 1=1--" data-p="x">' OR 1=1--</button>
          <button class="payload-btn text-xs bg-red-100 text-red-700 hover:bg-red-200 px-2 py-1 rounded font-mono" data-u="' OR '1'='1" data-p="' OR '1'='1">' OR '1'='1</button>
          <button class="payload-btn text-xs bg-gray-100 text-gray-600 hover:bg-gray-200 px-2 py-1 rounded" data-u="admin" data-p="wrongpassword">Wrong creds</button>
          <button class="payload-btn text-xs bg-green-100 text-green-700 hover:bg-green-200 px-2 py-1 rounded" data-u="alice" data-p="alice123">Valid creds</button>
        </div>
        <button id="login-btn" class="w-full bg-blue-700 hover:bg-blue-800 text-white py-2.5 rounded-lg text-sm font-semibold transition-colors">Sign In</button>
        <div id="v-result" class="hidden"></div>
      </div>
    </div>

    <div class="space-y-4">
      <div class="bg-white rounded-xl p-5 shadow">
        <h3 class="font-semibold text-gray-800 mb-3 text-sm">🔍 Simulated SQL Query</h3>
        <pre id="query-display">SELECT * FROM users WHERE username='?' AND password='?'</pre>
        <p class="text-xs text-gray-400 mt-2">Built by string concatenation — dangerous!</p>
      </div>
      <div class="bg-white rounded-xl p-5 shadow">
        <h3 class="font-semibold text-gray-800 mb-3 text-sm flex items-center gap-2">
          ✅ Patched Version
          <span class="text-xs bg-green-100 text-green-600 px-2 py-0.5 rounded font-normal">Parameterized Query</span>
        </h3>
        <div class="space-y-2 mb-3">
          <input id="p-user" type="text" placeholder="Username" class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-green-400 font-mono">
          <input id="p-pass" type="text" placeholder="Password" class="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-green-400 font-mono">
        </div>
        <button id="patch-btn" class="w-full bg-green-600 hover:bg-green-700 text-white py-2 rounded-lg text-sm font-semibold transition-colors">Try Patched Login</button>
        <pre id="p-result" class="mt-3">// Uses parameterized queries — SQLi won't work here</pre>
      </div>
    </div>
  </div>
</div>

<script>
  // Payload buttons - uses data attributes, no inline JS
  document.querySelectorAll('.payload-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('v-user').value = btn.dataset.u;
      document.getElementById('v-pass').value = btn.dataset.p;
      doVulnLogin();
    });
  });

  document.getElementById('login-btn').addEventListener('click', doVulnLogin);
  document.getElementById('patch-btn').addEventListener('click', doPatchLogin);

  async function doVulnLogin() {
    const u = document.getElementById('v-user').value;
    const p = document.getElementById('v-pass').value;
    document.getElementById('query-display').textContent = "SELECT * FROM users WHERE username='" + u + "' AND password='" + p + "'";
    try {
      const r = await fetch('/api/vulnerable/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p })
      });
      const d = await r.json();
      const el = document.getElementById('v-result');
      el.classList.remove('hidden');
      if (d.bypassed) {
        el.innerHTML = '<div class="bg-red-50 border border-red-300 rounded-lg p-3 text-sm">'
          + '<p class="font-bold text-red-700">🚨 SQLi Bypass Successful!</p>'
          + '<p class="text-red-600 text-xs mt-1">Logged in as: <strong>' + d.user.username + '</strong> (' + d.user.role + ')</p>'
          + '<div class="mt-2 bg-yellow-100 border border-yellow-400 text-yellow-800 rounded p-2 font-mono text-xs font-bold">🏁 ' + d.flag + '</div>'
          + '</div>';
      } else if (d.success) {
        el.innerHTML = '<div class="bg-green-50 border border-green-300 rounded-lg p-3 text-sm"><p class="text-green-700 font-semibold">✅ ' + d.message + '</p></div>';
      } else {
        el.innerHTML = '<div class="bg-gray-50 border border-gray-300 rounded-lg p-3 text-sm text-gray-600">❌ ' + d.message + '</div>';
      }
    } catch(e) {
      document.getElementById('v-result').innerHTML = '<p class="text-red-500 text-xs">Error: ' + e.message + '</p>';
    }
  }

  async function doPatchLogin() {
    const u = document.getElementById('p-user').value;
    const p = document.getElementById('p-pass').value;
    try {
      const r = await fetch('/api/patched/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p })
      });
      const d = await r.json();
      document.getElementById('p-result').textContent = (r.ok ? '✅ ' : '❌ ') + JSON.stringify(d, null, 2);
    } catch(e) {
      document.getElementById('p-result').textContent = 'Error: ' + e.message;
    }
  }
</script>
</body></html>`;

app.get('/', (req, res) => res.send(HTML));
app.listen(PORT, () => console.log(`💉 SQLi Lab running on http://localhost:${PORT}`));
