# SwiftShield v3 — Security Awareness & Access Monitoring

A web-based security audit platform that monitors employee access to Google Drive. Employees check in before accessing Drive, their location is detected, justification is required for remote access, and admins receive real-time alerts for high-risk activity.

Built as a college major project demonstrating location-aware access control, audit logging, and security awareness.

---

## Pages

| Page | URL | Description |
|------|-----|-------------|
| Check-In | `/` | Employee check-in before accessing Google Drive |
| Admin Dashboard | `/admin.html` | View logs, filter, export CSV, manage allowlist |
| Security Awareness | `/awareness.html` | Security awareness module for employees |

---

## Features

- **3-step check-in flow** — identity → location detection → justification
- **Geofencing** — detects if employee is inside or outside office using Haversine formula
- **Risk scoring** — LOW / MEDIUM / HIGH based on location + justification quality
- **Email alerts** — instant email to admin when HIGH risk access is detected
- **Admin dashboard** — filterable log table, CSV export, allowlist management
- **Security awareness page** — infographic-style module covering insider threats, safe remote work, and why logging matters
- **Works on all devices** — phones, tablets, personal laptops, no extension required
- **MongoDB audit log** — persistent storage of all access events

---

## Quick Start

```bash
cp .env.example .env       # fill in your values
npm install
npm start                  # http://localhost:3000
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MONGO_URI` | MongoDB Atlas connection string |
| `MONGO_DB` | Database name (default: `swiftshield`) |
| `ADMIN_API_KEY` | Secret key for admin dashboard access |
| `OFFICE_LAT` | Office latitude for geofencing |
| `OFFICE_LON` | Office longitude for geofencing |
| `OFFICE_RADIUS` | Geofence radius in metres (default: `2000`) |
| `ALLOWED_ORIGINS` | CORS allowed origins (e.g. `https://swiftshield.in`) |
| `ALERT_EMAIL_USER` | Gmail / Google Workspace email to send alerts from |
| `ALERT_EMAIL_PASS` | App Password (from Google Account → Security → App Passwords) |
| `ALERT_EMAIL_TO` | Admin email to receive high-risk alerts |
| `PORT` | Server port (default: `3000`) |

---

## API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/log` | — | Log a check-in / login event |
| `POST` | `/log/action` | — | Log an upload or download |
| `GET` | `/api/logs` | Admin Key | Fetch logs with filters |
| `GET` | `/api/stats` | Admin Key | Aggregate stats |
| `DELETE` | `/api/logs/:id` | Admin Key | Delete a single log |
| `DELETE` | `/api/logs` | Admin Key | Bulk delete logs |
| `GET` | `/api/allowlist` | Admin Key | List allowlist entries |
| `POST` | `/api/allowlist` | Admin Key | Add allowlist entry |
| `DELETE` | `/api/allowlist/:id` | Admin Key | Remove allowlist entry |
| `GET` | `/config` | — | Office geofence config |
| `GET` | `/api/admin/verify` | Admin Key | Verify admin key |

---

## Risk Scoring

| Condition | Risk Level |
|-----------|------------|
| Inside office perimeter | LOW |
| Outside + justification ≥ 20 chars | LOW |
| Outside + justification < 20 chars | MEDIUM |
| Outside + no justification | HIGH |
| Automated / bot user agent | HIGH |

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend | Node.js, Express.js |
| Database | MongoDB Atlas |
| Security | Helmet.js, express-rate-limit, validator.js |
| Email | Nodemailer (Gmail / Google Workspace SMTP) |
| Deployment | Vercel + GoDaddy (`swiftshield.in`) |
| Fonts | Space Mono, Syne (Google Fonts) |

---

## Deployment (Vercel)

1. Push this repo to GitHub
2. Connect to Vercel → import the repo
3. Add all environment variables in Vercel → Settings → Environment Variables
4. Vercel auto-deploys on every push to `main`

---

## Project Structure

```
swiftshield/
├── server.js              # Express backend, all API routes, email alerts
├── package.json
├── vercel.json
├── .env.example
└── public/
    ├── index.html         # Employee check-in page
    ├── checkin.js         # Check-in page logic
    ├── admin.html         # Admin dashboard
    ├── admin.js           # Admin dashboard logic
    ├── awareness.html     # Security awareness module
    ├── awareness.js       # Scroll reveal animations
    ├── styles.css         # Shared dark theme styles
    └── logo.jpeg
```