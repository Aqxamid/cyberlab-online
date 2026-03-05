---

# 🛡️ CyberLab — Interactive Cybersecurity Training Platform

CyberLab is a full-stack, hands-on platform for learning and practicing cybersecurity skills. It provides virtual labs, user dashboards, and instructor/admin features for tracking lab completions.

---

## **🌐 Live Deployment**

* **Frontend (Web App):** [https://securitylabs-gghn.onrender.com](https://securitylabs-gghn.onrender.com)
* **Backend (API):** [https://cyberlab-backend-to2l.onrender.com](https://cyberlab-backend-to2l.onrender.com)

> ⚠️ Labs are fully functional locally via Docker. On the live deployment, lab environments do **not spawn dynamically**, so “Go To Lab” buttons show metadata only.

---

## **💻 Features**

* User authentication (JWT-based login/register)
* Role-based access: user, instructor, admin
* Dashboard with lab completion stats
* Interactive lab cards with difficulty badges
* Admin interface for managing labs and users
* Backend API for labs, stats, users, and auth
* Supabase integration for database storage
* Docker support for local lab execution

---

## **🛠 Tech Stack**

* **Frontend:** HTML, Tailwind CSS, Vanilla JS
* **Backend:** Node.js, Express.js
* **Database:** Supabase (PostgreSQL)
* **Containerization:** Docker & Docker Compose (for local labs)
* **Hosting:** Render (frontend and backend)

---

## **⚙️ Environment Variables**

### Backend (`backend/.env` or Render service environment)

```env
PORT=4000
FRONTEND_URL=http://localhost:3000       # Or your deployed frontend URL
SUPABASE_URL=<your-supabase-url>
SUPABASE_SERVICE_ROLE_KEY=<your-supabase-service-role-key>
```

### Frontend (`frontend/.env` or HTML global variable)

```html
<script>
  window.CYBERLAB_API = "https://cyberlab-backend-to2l.onrender.com";
</script>
```

---

## **🚀 Local Development with Docker**

1. Clone the repo:

```bash
git clone https://github.com/Aqxamid/cyberlab-online.git
cd cyberlab-online
```

2. Make sure Docker & Docker Compose are installed.

3. Create `docker-compose.yml` in the repo root (example):

```yaml
version: "3.9"
services:
  backend:
    build: ./backend
    ports:
      - "4000:4000"
    environment:
      PORT: 4000
      FRONTEND_URL: http://localhost:3000
      SUPABASE_URL: <your-supabase-url>
      SUPABASE_SERVICE_ROLE_KEY: <your-service-role-key>
    command: npm start

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      CYBERLAB_API: http://localhost:4000
    command: npx serve -s pages
```

4. Run all services:

```bash
docker-compose up --build
```

* Frontend: [http://localhost:3000](http://localhost:3000)
* Backend API: [http://localhost:4000](http://localhost:4000)

> This allows labs to be fully spawned locally via Docker containers.

---

## **📝 Notes**

* **Lab Execution:** Currently, the deployed Render backend does not spawn lab containers dynamically. Labs are interactive only in your local Docker setup.
* **CORS:** The backend is configured to allow requests from the frontend URL. If testing locally, set `FRONTEND_URL=http://localhost:3000`.
* **API_BASE:** All frontend requests go through `window.CYBERLAB_API` or the default backend URL.

---

## **📂 Project Structure**

```
cyberlab-online/
├─ backend/           # Node.js Express API
│  ├─ routes/         # Auth, Labs, Stats, Users
│  └─ server.js
├─ frontend/          # Static pages & JS
│  ├─ pages/          # HTML pages (index, dashboard, labs, admin)
│  └─ app.js
├─ docker-compose.yml # Local dev setup
└─ README.md
```

---

## **🔗 Useful Links**

* GitHub Repo: [https://github.com/Aqxamid/cyberlab-online](https://github.com/Aqxamid/cyberlab-online)
* Render Frontend: [https://securitylabs-gghn.onrender.com](https://securitylabs-gghn.onrender.com)

---
