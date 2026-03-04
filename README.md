# 🛡️ CyberLab — Interactive Cybersecurity Training Platform

A full-stack, hands-on vulnerability training platform inspired by TryHackMe.  
Built with **plain HTML + Tailwind CSS**, **Node.js/Express**, **Supabase**, and **Docker**.

> ⚡ This is a re-implementation of the original React-based CyberLab, replacing React with vanilla HTML/Tailwind and replacing local PostgreSQL with Supabase.

---

## 🚀 Quick Start

### 1. Set up Supabase

1. Create a free project at [supabase.com](https://supabase.com)
2. Go to **SQL Editor** and run the contents of `backend/db/schema.sql`
3. Copy your project URL and service role key from **Settings → API**

### 2. Configure environment

```bash
cp .env.example .env
# Fill in SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
```

### 3. Run with Docker

```bash
docker compose up --build

# Frontend:    http://localhost:3000
# Backend API: http://localhost:4000
# IDOR Lab:    http://localhost:5000
```

### 4. Run locally (without Docker)

```bash
# Backend
cd backend && npm install && npm start

# Frontend
cd frontend && npm install && npm start

# IDOR Lab
cd labs/idor-lab && npm install && npm start
```

---

## 👤 Demo Accounts (pre-seeded via schema.sql)

| Username     | Password     | Role        |
|--------------|-------------|-------------|
| alice        | password123  | student     |
| bob          | password123  | student     |
| instructor1  | password123  | instructor  |
| admin        | password123  | admin       |

---

## 🏗️ Architecture

```
cyberlab/
├── docker-compose.yml
├── .env.example
├── frontend/                  # Vanilla HTML + Tailwind CSS SPA
│   ├── server.js              # Express static file server
│   └── pages/
│       ├── app.js             # Shared auth/API utilities
│       ├── index.html         # Landing page
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html     # Student + instructor dashboard
│       ├── labs.html          # Lab cards listing
│       ├── labroom.html       # Theory + flag submit
│       ├── idor.html          # Interactive IDOR console
│       └── admin.html         # Instructor/admin panel
├── backend/                   # Node.js + Express API
│   ├── server.js
│   ├── db/
│   │   ├── supabase.js        # Supabase client
│   │   └── schema.sql         # Run in Supabase SQL editor
│   ├── middleware/auth.js     # JWT + role guards
│   └── routes/
│       ├── auth.js
│       ├── labs.js
│       ├── stats.js
│       └── users.js
└── labs/
    └── idor-lab/              # Isolated vulnerable Express app
        └── server.js
```

---

## 🔑 API Reference

### Auth
- `POST /api/auth/register` — Register (returns JWT)
- `POST /api/auth/login` — Login (returns JWT)
- `GET /api/auth/me` — Current user

### Labs
- `GET /api/labs` — List labs (with completion status)
- `GET /api/labs/:slug` — Single lab
- `PATCH /api/labs/:id/toggle` — Enable/disable (instructor/admin)
- `POST /api/labs/:slug/attempt` — Submit flag
- `GET /api/labs/:slug/progress` — User progress

### Stats
- `GET /api/stats/student` — Personal stats
- `GET /api/stats/admin` — Platform-wide (instructor/admin)

---

## 🧪 IDOR Lab (port 5000)

| Endpoint | Vulnerable? | Notes |
|----------|------------|-------|
| `GET /api/vulnerable/users/:id` | ❌ Yes | Try ID 99 for admin flag! |
| `GET /api/vulnerable/documents/:id` | ❌ Yes | Try ID 42 |
| `GET /api/patched/users/:id` | ✅ Fixed | Requires x-user-id header |
| `GET /api/patched/documents/:id` | ✅ Fixed | Ownership check enforced |

---

## 🔒 Security Notes

- JWT stored in `sessionStorage` (cleared on tab close), not localStorage
- All secrets via `.env` environment variables  
- Supabase service role key only used server-side (never exposed to frontend)
- Vulnerable labs isolated in separate Docker containers
- `express-validator` on all auth endpoints
- bcrypt password hashing (rounds: 10)

---

## ➕ Adding Labs

1. Add row to `backend/db/schema.sql` (re-run in Supabase SQL editor)
2. Create `labs/your-lab/` with a vulnerable Express app
3. Add service to `docker-compose.yml`
4. Enable via instructor dashboard
