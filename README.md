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
* ✅ Token blacklist — logout immediately invalidates JWT across all open tabs and lab sessions
* ✅ Lab access control — live lab environments require a valid session token to access
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

> 🔒 All lab environments require an active CyberLab session. Accessing a lab URL directly without being logged in redirects to the login page. Logging out invalidates access within 5 seconds across all open lab tabs.

---

## 🗂 Project Structure

```
cyberlab-online/
├─ backend/                 # Express API & Supabase client
│  ├─ middleware/            # JWT authentication + token blacklist check
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

## 🧠 API Overview

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/auth/register` | POST | — | Create account |
| `/api/auth/login` | POST | — | Login & return JWT |
| `/api/auth/me` | GET | ✅ | Get current user |
| `/api/auth/logout` | POST | ✅ | Invalidate token (blacklist) |
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
- Token blacklist on logout — tokens are invalidated server-side so stolen tokens and open lab tabs are rejected within 5 seconds
- Rate limiting on auth endpoints and all API routes
- bcrypt password hashing (12 rounds)
- UUIDs on all public-facing API endpoints (no sequential integer IDs)
- HTTP security headers via Helmet
- XSS protection on all user-supplied data rendered in the frontend
- Request body size limits to prevent memory exhaustion
- Generic error messages to prevent username enumeration
- Timing-safe login to prevent user existence detection
- Lab environments protected by server-side JWT verification — direct URL access without a valid session is blocked

---

## ❤️ Acknowledgements

Inspired by **TryHackMe‑style interactive cybersecurity labs** — a proven model for hands‑on security education.