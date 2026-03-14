// CyberLab — Shared utilities loaded on every page

const API_BASE = window.CYBERLAB_API || 'https://cyberlab-backend-to2l.onrender.com';

// ── Auth ──────────────────────────────────────────────────────
const Auth = {
  getToken: () => sessionStorage.getItem('cl_token'),
  getUser:  () => { try { return JSON.parse(sessionStorage.getItem('cl_user')); } catch { return null; } },
  setSession(token, user) {
    sessionStorage.setItem('cl_token', token);
    sessionStorage.setItem('cl_user', JSON.stringify(user));
  },
  clear() {
    sessionStorage.removeItem('cl_token');
    sessionStorage.removeItem('cl_user');
  },
  isLoggedIn:  () => !!sessionStorage.getItem('cl_token'),
  requireAuth() {
    if (!Auth.isLoggedIn()) { window.location.href = '/login.html'; return false; }
    return true;
  },
  requireGuest() {
    if (Auth.isLoggedIn()) { window.location.href = '/dashboard.html'; return false; }
    return true;
  },
};

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ── API fetch wrapper ─────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const token   = Auth.getToken();
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res  = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));

  if (res.status === 401 || res.status === 403) {
    Auth.clear();
    window.location.href = '/login.html';
    return null;
  }

  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ── NavBar renderer ───────────────────────────────────────────
// username and role are escaped before going into innerHTML
function renderNavBar() {
  const user = Auth.getUser();
  const nav  = document.getElementById('navbar');
  if (!nav) return;

  const safeUsername = escapeHtml(user?.username || '');
  const safeRole     = escapeHtml(user?.role     || '');

  nav.innerHTML = `
    <div class="max-w-7xl mx-auto px-4 sm:px-6 flex items-center justify-between h-14">
      <a href="/dashboard.html" class="flex items-center gap-2 group">
        <div class="w-7 h-7 bg-cyan-500 rounded flex items-center justify-center text-black font-black text-xs group-hover:bg-cyan-400 transition-colors">CL</div>
        <span class="font-bold text-white tracking-widest text-sm uppercase">CyberLab</span>
      </a>
      <nav class="hidden md:flex items-center gap-6 text-sm">
        <a href="/dashboard.html" class="text-gray-400 hover:text-cyan-400 transition-colors">Dashboard</a>
        <a href="/labs.html"      class="text-gray-400 hover:text-cyan-400 transition-colors">Labs</a>
        ${user && ['instructor', 'admin'].includes(user.role)
          ? '<a href="/admin.html" class="text-gray-400 hover:text-cyan-400 transition-colors">Admin</a>'
          : ''}
      </nav>
      <div class="flex items-center gap-3">
        <span class="text-xs text-gray-500 hidden sm:block">${safeUsername}</span>
        <span class="text-xs px-2 py-0.5 rounded border ${roleBadge(user?.role)}">${safeRole}</span>
        <button onclick="logout()" class="text-xs text-gray-500 hover:text-red-400 transition-colors ml-1">Logout</button>
      </div>
    </div>
  `;
}

function roleBadge(role) {
  if (role === 'admin')      return 'border-red-500 text-red-400 bg-red-500/10';
  if (role === 'instructor') return 'border-yellow-500 text-yellow-400 bg-yellow-500/10';
  return 'border-cyan-700 text-cyan-500 bg-cyan-500/10';
}

// ── Logout — calls backend to blacklist the token first ───────
// This makes logout immediate: the token is invalidated server-side so
// the 5-second lab re-check will hit /api/auth/me, get a 401, and redirect.
async function logout() {
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' });
  } catch {
    // Fail silently — still clear local session regardless
  }
  Auth.clear();
  window.location.href = '/index.html';
}

function difficultyBadge(diff) {
  if (diff === 'advanced')     return 'border-red-600 text-red-400 bg-red-500/10';
  if (diff === 'intermediate') return 'border-yellow-600 text-yellow-400 bg-yellow-500/10';
  return 'border-green-700 text-green-400 bg-green-500/10';
}

function showToast(msg, type = 'info') {
  const toast  = document.createElement('div');
  const colors = {
    info:    'bg-cyan-900 border-cyan-600 text-cyan-200',
    success: 'bg-green-900 border-green-600 text-green-200',
    error:   'bg-red-900 border-red-600 text-red-300',
  };
  toast.className = `fixed bottom-5 right-5 z-50 px-4 py-3 rounded border text-sm font-mono max-w-sm ${colors[type] || colors.info} animate-pulse`;
  toast.textContent = msg; // textContent not innerHTML
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}