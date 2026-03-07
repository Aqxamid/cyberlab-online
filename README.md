# 🛡️ CyberLab‑Online — Interactive Cybersecurity Training Platform

**CyberLab‑Online** is a full‑stack, hands‑on cybersecurity training platform inspired by TryHackMe, built using plain HTML/Tailwind CSS, Node.js/Express, and Supabase for the database.

🌐 **Try it out live:** [CyberLab Online](https://cyberlab-frontend.onrender.com)

This platform delivers interactive vulnerability labs, role‑based dashboards, and an extensible API — making it a practical foundation for learning real-world cybersecurity concepts.

---

## 🔍 Features

* ✅ User authentication (JWT‑based login & registration)
* ✅ Role‑based access control: **student**, **instructor**, **admin**
* ✅ Dashboard with personal lab completion metrics and progress tracking
* ✅ Interactive lab cards with difficulty badges and point rewards
* ✅ Flag submission system with attempt tracking
* ✅ Admin panel — manage labs and user roles
* ✅ Instructor panel — view platform-wide stats
* ✅ Backend API for labs, stats, users, and authentication
* ✅ Supabase integration for persistent database storage
* ✅ Docker/Docker‑Compose support for local development
* ⭐ Extensible lab architecture using isolated containers

> ⚠️ **Note:** JWT tokens are stored in **sessionStorage** rather than HttpOnly cookies intentionally, to allow labs to simulate real-world XSS/JS-based attacks and practice session handling.

---

## 🧱 Tech Stack

| Layer            | Technology                  |
| ---------------- | --------------------------- |
| Frontend         | Vanilla HTML + Tailwind CSS |
| Backend          | Node.js + Express.js        |
| Database         | Supabase (PostgreSQL)       |
| Containerization | Docker & Docker Compose     |
| Hosting          | Render                      |

---

## 🧪 Labs

Each lab runs as its own isolated service and teaches a specific vulnerability class:

| Lab | Vulnerability | Description |
|-----|--------------|-------------|
| IDOR Lab | Insecure Direct Object Reference | Access other users' data by manipulating object IDs |
| JWT Lab | JWT Alg:None Attack | Forge admin tokens by exploiting algorithm confusion |
| SQLi Lab | SQL Injection | Bypass authentication using injection payloads |
| XSS Lab | Cross-Site Scripting | Execute reflected and stored XSS attacks |
| Path Traversal Lab | Directory Traversal | Escape the web root to access sensitive files |

Each lab includes a **vulnerable endpoint** to exploit and a **patched endpoint** to compare against, so students can see both the attack and the fix side by side.

---

## 🗂 Project Structure

```
cyberlab-online/
├─ backend/                 # Express API & Supabase client
│  ├─ middleware/            # JWT authentication
│  ├─ routes/               # Auth, Labs, Stats, Users
│  └─ server.js
├─ frontend/                # Static pages + scripts
│  ├─ pages/                # HTML (login, register, dashboard, labs, admin)
│  └─ app.js                # Shared utilities, auth, API fetch wrapper
├─ labs/                    # Individual lab containers
│  ├─ idor-lab/
│  ├─ jwt-lab/
│  ├─ sqli-lab/
│  ├─ xss-lab/
│  └─ path-traversal-lab/
├─ db/                      # SQL migration scripts
├─ docker‑compose.yml       # Local dev orchestration
├─ .env.example
└─ README.md
```

---

## 🚀 Quick Start

### 1. Set Up Supabase

1. Create a free Supabase project at [supabase.com](https://supabase.com)
2. Run the SQL in `backend/db/schema.sql` to set up tables
3. Run `db/migration_add_uuids.sql` to add UUID support
4. Copy your **Supabase URL** and **anon key**

---

### 2. Configure Environment

```bash
cp .env.example .env
```

Fill in your `.env`:

```env
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_anon_key
JWT_SECRET=your_generated_secret
FRONTEND_URL=http://localhost:3000
NODE_ENV=development
```

Generate a secure JWT secret:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

---

### 3. Install Dependencies

```bash
cd backend && npm install
cd ../labs/idor-lab && npm install
cd ../jwt-lab && npm install
cd ../sqli-lab && npm install
cd ../xss-lab && npm install
cd ../path-traversal-lab && npm install
```

---

### 4. Run with Docker

From the repository root:

```bash
docker compose up --build
```

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:4000 |
| IDOR Lab | http://localhost:5001 |
| SQLi Lab | http://localhost:5002 |
| XSS Lab | http://localhost:5003 |
| JWT Lab | http://localhost:5004 |
| Path Traversal Lab | http://localhost:5005 |

---

### 5. Run Locally (without Docker)

**Backend:**
```bash
cd backend
npm install
npm start
```

**Frontend:**
```bash
cd frontend
npm install
npm start
```

**Lab (example):**
```bash
cd labs/idor-lab
npm install
npm start
```

---

## 🧠 API Overview

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/auth/register` | POST | — | Create account |
| `/api/auth/login` | POST | — | Login & return JWT |
| `/api/auth/me` | GET | ✅ | Get current user |
| `/api/labs` | GET | ✅ | List all labs |
| `/api/labs/:slug` | GET | ✅ | Get single lab |
| `/api/labs/:slug/attempt` | POST | ✅ | Submit a flag |
| `/api/labs/:slug/progress` | GET | ✅ | Get attempt history |
| `/api/labs/:uuid/toggle` | PATCH | ✅ Instructor+ | Enable/disable a lab |
| `/api/stats/student` | GET | ✅ | Personal stats |
| `/api/stats/admin` | GET | ✅ Instructor+ | Platform-wide stats |
| `/api/users` | GET | ✅ Admin | List all users |
| `/api/users/:uuid/role` | PATCH | ✅ Admin | Change a user's role |

---

## 🔒 Security

- JWT authentication with HS256 algorithm pinning (prevents alg:none attacks)
- Rate limiting on auth endpoints (5 attempts / 15 min) and all API routes
- bcrypt password hashing at cost factor 12
- UUIDs on all public-facing API endpoints (no sequential integer IDs)
- HTTP security headers via Helmet
- XSS protection on all user-supplied data rendered in the frontend
- Request body size limits to prevent memory exhaustion
- Generic error messages to prevent username enumeration
- Timing-safe login to prevent user existence detection

---

## ❤️ Acknowledgements

Inspired by **TryHackMe‑style interactive cybersecurity labs** — a proven model for hands‑on security education.