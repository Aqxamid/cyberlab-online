---

# 🚀 CyberLab‑Online — Interactive Cybersecurity Training Platform

**CyberLab‑Online** is a full‑stack, hands‑on cybersecurity training platform inspired by TryHackMe, built using **plain HTML/Tailwind CSS** with a Node.js/Express backend, Supabase as the database, and Docker support for local lab execution. 

This project delivers interactive vulnerability labs, role‑based dashboards, and an extensible API, making it a practical foundation for learning cybersecurity concepts. 

---

# 🚀 CyberLab‑Online — Interactive Cybersecurity Training Platform

**CyberLab‑Online** is a full‑stack, hands‑on cybersecurity training platform inspired by TryHackMe, built in a **vibecoded** style using plain HTML/Tailwind CSS, Node.js/Express backend, and Supabase for the database.

🌐 **Try it out live:** [CyberLab Online Live Demo](https://cyberlab-frontend.onrender.com)

This platform delivers interactive vulnerability labs, role‑based dashboards, and an extensible API, making it a practical foundation for learning cybersecurity concepts.

---

## 🔍 Features

* ✅ User authentication (JWT‑based login & registration) 
* ✅ Role‑based access control: **student**, **instructor**, **admin** 
* ✅ Dashboard with lab completion metrics 
* ✅ Interactive lab cards & difficulty badges 
* ✅ Backend API for labs, stats, users, and authentication 
* ✅ Supabase integration for database storage 
* ✅ Docker/Docker‑Compose support for local lab execution 
* ⭐ Extensible lab architecture using isolated containers 

> ⚠️ **Important:** JWT tokens are stored in **localStorage** rather than HttpOnly cookies intentionally, to allow labs to simulate real-world XSS/JS-based attacks and practice session handling. 

---

## 🧱 Tech Stack

| Layer            | Technology                  |
| ---------------- | --------------------------- |
| Frontend         | Vanilla HTML + Tailwind CSS |
| Backend          | Node.js + Express.js        |
| Database         | Supabase (PostgreSQL)       |
| Containerization | Docker & Docker Compose     |
| Hosting          | Render / Local Docker       |

> This project purposefully avoids React for simplicity and performance while using Tailwind CSS for modern styling. 

---

## 🚀 Quick Start

### 1. Set Up Supabase

1. Create a free Supabase project at **supabase.com**.
2. Run the SQL in `backend/db/schema.sql` to set up tables.
3. Copy your **Supabase URL** and **service role key**. 

---

### 2. Configure Environment

```bash
cp .env.example .env
# Fill in SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
```

---

### 3. Run with Docker

From the repository root:

```bash
docker compose up --build
```

* Frontend → [http://localhost:3000](http://localhost:3000)
* Backend API → [http://localhost:4000](http://localhost:4000)
* Labs (e.g., IDOR) → [http://localhost:5000](http://localhost:5000) 

---

### 4. Run Locally (without Docker)

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

**Lab Service (e.g., IDOR):**

```bash
cd labs/idor-lab
npm install
npm start
```

---

## 👤 Demo Accounts (pre‑seeded)

| Username    | Password    | Role       |                                                            |
| ----------- | ----------- | ---------- | ---------------------------------------------------------- |
| alice       | password123 | student    |                                                            |
| bob         | password123 | student    |                                                            |
| instructor1 | password123 | instructor |                                                            |
| admin       | password123 | admin      |  |

---

## 🗂 Project Structure

````
cyberlab-online/
├─ backend/           # Express API & Supabase client
│  ├─ routes/         # Auth, Labs, Stats, Users
│  └─ server.js
├─ frontend/          # Static pages + scripts
│  ├─ pages/          # HTML (login, dashboard, labs, admin)
│  └─ app.js
├─ labs/              # Individual lab containers
├─ docker‑compose.yml # Local dev orchestration
├─ .env.example
└─ README.md
``` 

---

## 🧠 API Overview

**Key endpoints (Express)**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /api/auth/login` | POST | Login & return JWT |
| `POST /api/auth/register` | POST | Create user |
| `GET /api/labs` | GET | List labs |
| `GET /api/labs/:slug` | GET | Get single lab |
| `POST /api/labs/:slug/attempt` | POST | Submit a flag |
| `GET /api/stats/student` | GET | Personal stats |
| `GET /api/stats/admin` | GET | Admin stats | 

---

---

## ❤️ Acknowledgements

This project is inspired by **TryHackMe‑style interactive cybersecurity labs** — a proven model for hands‑on learning.

---