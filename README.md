# SwiftShield v3 — Cloud Access Monitoring System

> A location-aware security audit platform that monitors employee access to Google Drive in real time — built as a college major project demonstrating geofencing, risk scoring, anomaly detection, and admin auditing.

**Live:** [https://swiftshield.in](https://swiftshield.in)

---

## What is SwiftShield?

SwiftShield is a web-based access monitoring system designed to detect and log suspicious file activity in a shared Google Drive environment. When an employee accesses, uploads, or downloads files, SwiftShield captures their location, device, IP address, and justification — then scores the risk automatically and alerts the admin if anything looks suspicious.

No mobile app or browser extension is required. It runs entirely in the browser and on the server.

---

## Why This Project Matters

Insider threats and unauthorized remote access are among the leading causes of data breaches in organizations. Most companies use Google Drive or similar cloud storage without any visibility into *who* is accessing files, *from where*, and *why*.

SwiftShield solves this by:

- Requiring employees to **check in** before accessing shared files, providing a justification if they are outside the office
- Automatically **detecting location** using the browser's Geolocation API and comparing it against a configurable office geofence
- **Logging every access event** — login, upload, download, and view — to a persistent audit database
- **Scoring risk** automatically based on location, justification quality, device fingerprint, and behavior patterns
- Sending **instant email alerts** to the admin when high-risk activity is detected
- Providing an **admin dashboard** with live maps, analytics charts, and full audit logs

---

## Pages

| Page | URL | Description |
|------|-----|-------------|
| Employee Check-In | `/` | 3-step flow before accessing Google Drive |
| Admin Dashboard | `/admin.html` | Live logs, map, analytics, allowlist, settings |
| Security Awareness | `/awareness.html` | Security education module for employees |

---

## Features

### Employee Side
- **3-step check-in flow** — identity → GPS location detection → justification
- **Geofencing** — detects if the employee is inside or outside the office using the Haversine formula
- **Justification enforcement** — outside-office access requires a written reason (minimum 20 characters)
- **Risk feedback** — employee sees their risk level immediately after check-in
- **Works on all devices** — phones, tablets, laptops — no extension or app required

### Detection & Intelligence
- **Risk scoring engine** — LOW / MEDIUM / HIGH based on location, justification quality, and user agent
- **New device detection** — flags and alerts when a known user logs in from an unrecognized browser or device
- **Bulk download alert** — automatically flags HIGH risk if a user downloads 5+ files within 10 minutes
- **Google Drive webhook** — real-time upload detection via Google Drive Push Notifications
- **Admin Reports API polling** — polls Google Workspace Admin SDK every 5 minutes to detect downloads and views from Drive
- **IP geolocation** — resolves IP addresses to coordinates for Drive activity, falling back to last known check-in location
- **Location inference** — cross-references Drive activity timestamps with the user's last SwiftShield check-in

### Admin Dashboard
- **Live access map** — Leaflet.js world map with color-coded risk markers and office perimeter overlay
- **Analytics charts** — risk trend over 7 days, peak access hours, action breakdown, top users by activity (Chart.js)
- **Real-time auto-refresh** — dashboard updates every 15/30/60 seconds (configurable)
- **Full audit log** — filterable by user, risk level, and action type with pagination
- **CSV export** — download filtered logs as a CSV file
- **Google Drive export** — push log exports directly to Google Drive as a CSV file
- **Allowlist management** — whitelist trusted users, emails, or IP addresses
- **Weekly email report** — automated HTML summary sent every Monday at 8AM, with manual trigger
- **Danger zone** — bulk delete high-risk logs or all logs with double confirmation

### Google Drive Integration
- **OAuth2 authentication** — connects to Google Drive using your Google Workspace account
- **Token stored in MongoDB** — persists across Vercel serverless deployments
- **Drive webhook** — Google Drive notifies SwiftShield instantly when files are uploaded to the shared folder
- **Auto-renew webhook** — checks every 6 hours and renews before the 7-day expiry
- **Admin Reports API** — fetches download and view events from Google Workspace audit logs
- **Cron jobs** — Vercel cron triggers the poll every 5 minutes and renews the webhook weekly

### Security
- **Helmet.js** — sets secure HTTP headers including CSP, HSTS, X-Frame-Options
- **CORS restriction** — only allows requests from configured origins
- **Rate limiting** — 30 req/min on log endpoints, 60 req/min on admin endpoints
- **Input sanitisation** — all inputs validated and escaped with validator.js
- **Admin API key auth** — all admin routes protected by a secret key sent as a header
- **Session storage** — admin session persists across page refreshes without re-authentication
- **No SQL/NoSQL injection** — parameterised queries and length-limited inputs throughout

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Backend | Node.js 22, Express.js 4 |
| Database | MongoDB Atlas (via official MongoDB Node.js driver) |
| Maps | Leaflet.js 1.9 with CartoDB dark tiles |
| Charts | Chart.js 4.4 |
| Security | Helmet.js, express-rate-limit, validator.js |
| Email | Nodemailer with Gmail / Google Workspace SMTP |
| Google APIs | googleapis (Drive v3, Admin Reports v1, OAuth2) |
| IP Geolocation | ip-api.com (free tier) |
| Deployment | Vercel (serverless Node.js) |
| Domain | GoDaddy → `swiftshield.in` |
| Fonts | Space Mono, Syne (Google Fonts) |
| Version Control | Git + GitHub |

---

## API Reference

### Public Endpoints
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/config` | Office geofence config (lat, lon, radius) |
| `POST` | `/log` | Log a check-in / login event |
| `POST` | `/log/action` | Log an upload or download action |
| `POST` | `/api/drive/webhook` | Receive Google Drive push notifications |
| `GET` | `/auth/google` | Start Google OAuth2 flow (admin key required) |
| `GET` | `/auth/google/callback` | OAuth2 callback — saves token to MongoDB |

### Admin Endpoints (require `x-admin-key` header)
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/verify` | Verify admin key |
| `GET` | `/api/logs` | Fetch logs (filterable by user, risk, action) |
| `GET` | `/api/stats` | Aggregate stats (total, high risk, external) |
| `DELETE` | `/api/logs/:id` | Delete a single log entry |
| `DELETE` | `/api/logs` | Bulk delete logs (filter by risk or date) |
| `GET` | `/api/allowlist` | List allowlist entries |
| `POST` | `/api/allowlist` | Add allowlist entry |
| `DELETE` | `/api/allowlist/:id` | Remove allowlist entry |
| `PATCH` | `/api/allowlist/:id` | Update allowlist entry note |
| `GET` | `/api/analytics` | Risk trends, hourly distribution, top users, locations |
| `GET` | `/api/drive/status` | Check if Google Drive is connected |
| `POST` | `/api/drive/watch` | Register Drive webhook |
| `POST` | `/api/drive/poll` | Manually trigger Admin Reports API poll |
| `POST` | `/api/export-to-drive` | Export logs CSV to Google Drive |
| `POST` | `/api/weekly-report` | Send weekly email report |

---

## Risk Scoring

| Condition | Risk Level |
|-----------|------------|
| Inside office perimeter | LOW |
| Outside + justification ≥ 20 chars | LOW |
| Outside + justification < 20 chars | MEDIUM |
| Outside + no justification | HIGH |
| Automated / bot user agent | HIGH |
| New device detected | HIGH (alert sent) |
| 5+ downloads in 10 minutes | HIGH (bulk alert) |
| Google Drive activity, inside office | LOW |
| Google Drive activity, outside office | MEDIUM–HIGH |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MONGO_URI` | MongoDB Atlas connection string |
| `MONGO_DB` | Database name (default: `swiftshield`) |
| `ADMIN_API_KEY` | Secret key for admin dashboard |
| `OFFICE_LAT` | Office latitude for geofencing |
| `OFFICE_LON` | Office longitude for geofencing |
| `OFFICE_RADIUS` | Geofence radius in metres (default: `2000`) |
| `ALLOWED_ORIGINS` | CORS allowed origins |
| `ALERT_EMAIL_USER` | Gmail/Workspace email for sending alerts |
| `ALERT_EMAIL_PASS` | Google App Password |
| `ALERT_EMAIL_TO` | Admin email to receive alerts |
| `GOOGLE_CLIENT_ID` | Google OAuth2 Client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth2 Client Secret |
| `GOOGLE_REDIRECT_URI` | OAuth2 callback URL |
| `GOOGLE_DRIVE_FOLDER_ID` | Shared Drive folder to monitor |
| `PORT` | Server port (default: `3000`) |

---

## Quick Start (Local)

```bash
git clone https://github.com/your-repo/swiftshield
cd swiftshield
cp .env.example .env       # fill in your values
npm install
npm start                  # http://localhost:3000
```

---

## Deployment (Vercel)

1. Push this repo to GitHub
2. Connect to Vercel → import the repo
3. Add all environment variables in **Vercel → Settings → Environment Variables**
4. Vercel auto-deploys on every push to `main`
5. Cron jobs run automatically — no manual commands needed after deploy

### One-time Google Drive Setup
```bash
# 1. Visit in browser to authorize Google Drive
https://swiftshield.in/auth/google?adminKey=YOUR_KEY

# 2. Register the Drive webhook
curl -X POST https://swiftshield.in/api/drive/watch \
  -H "x-admin-key: YOUR_KEY"
```

---

## Project Structure

```
swiftshield/
├── server.js              # Express backend — all API routes, risk engine,
│                          # Google Drive integration, email alerts, analytics
├── package.json
├── vercel.json            # Vercel config + cron jobs
├── .env.example
└── public/
    ├── index.html         # Employee check-in page
    ├── checkin.js         # Check-in flow logic (3 steps)
    ├── admin.html         # Admin dashboard (structure only)
    ├── admin.js           # Admin dashboard logic — logs, map, charts, Drive
    ├── awareness.html     # Security awareness module
    ├── awareness.js       # Scroll reveal animations
    ├── styles.css         # Shared dark theme (Space Mono + Syne)
    └── logo.jpeg
```

---

## MongoDB Collections

| Collection | Description |
|------------|-------------|
| `logs` | All access events (login, upload, download, view) |
| `allowlist` | Trusted users, emails, and IP addresses |
| `devices` | Known device fingerprints per user (for new device detection) |
| `config` | Google OAuth token, Drive webhook state, poll timestamps |

---

## Future Scope

The following features could be added in future versions to make SwiftShield production-ready:

**Security Enhancements**
- TOTP-based 2FA for the admin dashboard (Google Authenticator)
- Admin session timeout after inactivity
- Brute-force lockout after repeated failed admin key attempts
- End-to-end encryption for stored log data

**Detection Improvements**
- Machine learning anomaly detection — flag access patterns that deviate from a user's normal behavior
- Time-based anomaly alerts — flag access at unusual hours (e.g., 2AM logins)
- Velocity detection — alert when the same user appears in two geographically distant locations within minutes
- File sensitivity tagging — higher risk for specific file types (e.g., `.pdf`, `.xlsx`)

**Integration**
- Slack / Microsoft Teams webhook alerts for high-risk events
- WhatsApp Business API alerts
- SIEM integration (Splunk, Elastic) for enterprise environments
- Active Directory / LDAP user sync
- Mobile app (React Native) for employee check-in

**Infrastructure**
- Role-based access control (RBAC) — multiple admin tiers
- Log retention policies — auto-archive logs older than 90 days
- Multi-tenant support — one deployment serving multiple organizations
- Self-hosted option with Docker Compose

**Compliance**
- GDPR-compliant data handling with user data export and deletion
- Audit trail for admin actions (who deleted what, when)
- Automated compliance reports (ISO 27001, SOC 2 style)

---

## Limitations

- Google Drive API does not expose download events natively — downloads are detected via the Google Workspace Admin Reports API, which requires a Workspace account and may have up to 1-hour delay
- IP geolocation accuracy depends on the ISP and may not pinpoint exact location
- Vercel serverless functions are stateless — `setInterval` polling is supplemented by Vercel cron jobs
- The Drive webhook expires every 7 days (auto-renewed by the system)

---

## Academic Context

This project was built as a **Major Project** for a Computer Engineering degree, demonstrating practical application of:

- Web application security principles
- RESTful API design
- Real-time data processing and webhooks
- Cloud deployment and serverless architecture
- Geospatial computing (Haversine formula)
- OAuth2 authentication flow
- NoSQL database design
- Security awareness and insider threat mitigation

---

## License

MIT — free to use for educational purposes.