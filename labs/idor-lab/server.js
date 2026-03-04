const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// ==========================================
// FAKE DATA
// ==========================================
const users = {
  1:  { id: 1, username: 'alice',   email: 'alice@example.com',   role: 'student' },
  2:  { id: 2, username: 'bob',     email: 'bob@example.com',     role: 'student' },
  3:  { id: 3, username: 'charlie', email: 'charlie@example.com', role: 'student' },
  99: { id: 99, username: 'admin',  email: 'admin@example.com',   role: 'admin', secret: 'FLAG{idor_is_dangerous_123}' }
};

const documents = {
  1:  { id: 1,  owner_id: 1, title: 'My Notes',       content: 'These are Alice\'s personal notes.', owner: 'alice' },
  2:  { id: 2,  owner_id: 2, title: 'Study Guide',     content: 'Bob\'s cybersecurity study guide.', owner: 'bob' },
  42: { id: 42, owner_id: 99, title: 'Admin Handbook', content: 'CONFIDENTIAL — FLAG{idor_docs_exposed}', owner: 'admin' }
};

// ==========================================
// VULNERABLE ENDPOINTS — No auth check!
// ==========================================

// GET /api/vulnerable/users/:id — IDOR: Any ID accessible
app.get('/api/vulnerable/users/:id', (req, res) => {
  const user = users[parseInt(req.params.id)];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// GET /api/vulnerable/documents/:id — IDOR: Any doc accessible
app.get('/api/vulnerable/documents/:id', (req, res) => {
  const doc = documents[parseInt(req.params.id)];
  if (!doc) return res.status(404).json({ error: 'Document not found' });
  res.json(doc);
});

// ==========================================
// PATCHED ENDPOINTS — Ownership enforced
// ==========================================

// GET /api/patched/users/:id — requires x-user-id header & ownership
app.get('/api/patched/users/:id', (req, res) => {
  const requesterId = parseInt(req.headers['x-user-id']);
  const targetId = parseInt(req.params.id);

  if (!requesterId) return res.status(401).json({ error: 'x-user-id header required' });
  if (requesterId !== targetId) return res.status(403).json({ error: 'Access denied: you can only view your own profile' });

  const user = users[targetId];
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Strip sensitive fields from patched endpoint
  const { secret, ...safeUser } = user;
  res.json(safeUser);
});

// GET /api/patched/documents/:id — requires ownership
app.get('/api/patched/documents/:id', (req, res) => {
  const requesterId = parseInt(req.headers['x-user-id']);
  const docId = parseInt(req.params.id);

  if (!requesterId) return res.status(401).json({ error: 'x-user-id header required' });

  const doc = documents[docId];
  if (!doc) return res.status(404).json({ error: 'Document not found' });
  if (doc.owner_id !== requesterId) return res.status(403).json({ error: 'Access denied: this document belongs to another user' });

  res.json(doc);
});

// Info endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'IDOR Lab',
    description: 'Intentionally vulnerable API for learning IDOR attacks',
    vulnerable_endpoints: [
      'GET /api/vulnerable/users/:id — Try ID 99 for admin flag!',
      'GET /api/vulnerable/documents/:id — Try ID 42 for bonus flag!'
    ],
    patched_endpoints: [
      'GET /api/patched/users/:id — Requires x-user-id header (ownership enforced)',
      'GET /api/patched/documents/:id — Requires x-user-id header (ownership enforced)'
    ]
  });
});

app.listen(PORT, () => {
  console.log(`🔓 IDOR Lab running on http://localhost:${PORT}`);
  console.log(`   Try: GET /api/vulnerable/users/99`);
});
