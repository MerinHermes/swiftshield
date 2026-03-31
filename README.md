# SwiftShield v2 — Hardened Edition

Location-aware cloud access monitoring system. Tracks logins, uploads, and downloads with geo-fencing, risk scoring, and admin auditing.

## What's New in v2

| Area | Change |
|------|--------|
| **Database** | Replaced PostgreSQL with MongoDB |
| **Security** | Helmet headers, CORS restriction, rate limiting |
| **Auth** | Admin API key required for `/api/logs` and `/api/stats` |
| **Input** | All inputs sanitised + validated with `validator` |
| **Risk Engine** | Server-side risk scoring (not just UI) |
| **Bug Fix** | Upload/download actions log via dedicated `/log/action` endpoint |
| **XSS** | All log output HTML-escaped in the dashboard |
| **Pagination** | `/api/logs` supports `limit`, `skip`, `risk`, `user_id`, `action` filters |
| **Stats API** | New `/api/stats` endpoint |
| **Delete** | `DELETE /api/logs/:id` to remove individual records |
| **Design** | Redesigned UI with Space Mono + Syne, tactical dark theme |

## Quick Start

```bash
cp .env.example .env       # edit MONGO_URI, ADMIN_API_KEY
npm install
npm start                  # http://localhost:3000
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGO_DB` | `swiftshield` | Database name |
| `ADMIN_API_KEY` | `changeme-in-production` | Key for admin dashboard |
| `OFFICE_LAT` | `19.0219594` | Office latitude |
| `OFFICE_LON` | `73.0934445` | Office longitude |
| `OFFICE_RADIUS` | `2000` | Geofence radius (metres) |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | CORS allowed origins |
| `PORT` | `3000` | Server port |

## API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/log` | — | Log a login event |
| `POST` | `/log/action` | — | Log upload / download |
| `GET` | `/api/logs` | Admin Key | Fetch logs (filterable) |
| `GET` | `/api/stats` | Admin Key | Aggregate stats |
| `DELETE` | `/api/logs/:id` | Admin Key | Delete a log entry |
| `GET` | `/config` | — | Office geofence config |

### Admin Key Header
```
x-admin-key: <your ADMIN_API_KEY>
```

## Security Weaknesses Fixed

1. **No auth on admin API** → Added API key middleware
2. **No rate limiting** → 30 req/min on log endpoints, 60/min on admin
3. **No input validation** → All fields sanitised with `validator.escape()`
4. **SQL/NoSQL injection** → Parameterised queries + length limits
5. **Missing security headers** → `helmet` adds CSP, HSTS, X-Frame, etc.
6. **CORS open to all** → Restricted to `ALLOWED_ORIGINS`
7. **XSS in admin table** → HTML-escaped before DOM insertion
8. **Risk only in UI** → Risk level now computed server-side and stored
9. **IP spoofing via X-Forwarded-For** → Only first IP in chain is used
10. **Upload/download never logged** → Fixed with `/log/action` endpoint
