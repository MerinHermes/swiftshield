/**
 * SwiftShield v3 — Web-only edition
 * Check-in page + admin dashboard + email alerts + Google Drive export
 */

const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const validator  = require('validator');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Google OAuth2 Setup (token stored in MongoDB — works on Vercel) ───────────
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI || 'https://swiftshield.in/auth/google/callback';
const DRIVE_FOLDER_ID      = process.env.GOOGLE_DRIVE_FOLDER_ID || null;

function getOAuth2Client() {
  return new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
}

// Save token to MongoDB (works on Vercel serverless)
async function saveToken(token) {
  const db = client.db(DB_NAME);
  await db.collection('config').updateOne(
    { _id: 'google_token' },
    { $set: { token, updatedAt: new Date() } },
    { upsert: true }
  );
}

// Load token from MongoDB
async function loadToken() {
  try {
    const db  = client.db(DB_NAME);
    const doc = await db.collection('config').findOne({ _id: 'google_token' });
    return doc?.token || null;
  } catch { return null; }
}

// Returns an authorized OAuth2 client, or null if not connected
async function getAuthorizedClient() {
  const token = await loadToken();
  if (!token) return null;
  const oauth2Client = getOAuth2Client();
  oauth2Client.setCredentials(token);
  // Auto-save refreshed tokens back to MongoDB
  oauth2Client.on('tokens', async (newTokens) => {
    const merged = { ...token, ...newTokens };
    await saveToken(merged);
  });
  return oauth2Client;
}

// ── Helmet / CORS / Body Parser ───────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:"],
      connectSrc: ["'self'"]
    }
  }
}));

const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://swiftshield.in').split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  }
}));

app.use(bodyParser.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const logLimiter   = rateLimit({ windowMs: 60_000, max: 30,  standardHeaders: true, legacyHeaders: false, message: { error: 'too_many_requests' } });
const adminLimiter = rateLimit({ windowMs: 60_000, max: 60,  standardHeaders: true, legacyHeaders: false });
const authLimiter  = rateLimit({ windowMs: 60_000, max: 10,  standardHeaders: true, legacyHeaders: false });

// ── MongoDB ───────────────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME   = process.env.MONGO_DB  || 'swiftshield';
const ADMIN_KEY = process.env.ADMIN_API_KEY || 'changeme-in-production';

const client = new MongoClient(MONGO_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

let logsCol, allowlistCol;

(async () => {
  try {
    await client.connect();
    const db = client.db(DB_NAME);
    logsCol      = db.collection('logs');
    allowlistCol = db.collection('allowlist');
    await logsCol.createIndex({ timestamp: -1 });
    await logsCol.createIndex({ user_id: 1 });
    await logsCol.createIndex({ risk: 1 });
    await allowlistCol.createIndex({ value: 1 }, { unique: true });
    await allowlistCol.createIndex({ type: 1 });
    console.log('✅  MongoDB connected →', DB_NAME);
  } catch (err) {
    console.error('❌  MongoDB failed:', err.message);
    process.exit(1);
  }
})();

// ── Email alerts ──────────────────────────────────────────────────────────────
let mailer = null;
if (process.env.ALERT_EMAIL_USER && process.env.ALERT_EMAIL_PASS) {
  mailer = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.ALERT_EMAIL_USER, pass: process.env.ALERT_EMAIL_PASS }
  });
  mailer.verify(err => {
    if (err) console.warn('⚠  Email not ready:', err.message);
    else     console.log('✅  Email alerts →', process.env.ALERT_EMAIL_USER);
  });
}

async function sendAlert(log) {
  if (!mailer || !process.env.ALERT_EMAIL_TO) return;
  const dashUrl = (process.env.ALLOWED_ORIGINS || 'https://swiftshield.in').split(',')[0];
  try {
    await mailer.sendMail({
      from:    `"SwiftShield Alerts" <${process.env.ALERT_EMAIL_USER}>`,
      to:      process.env.ALERT_EMAIL_TO,
      subject: `🚨 HIGH RISK — ${(log.action||'access').toUpperCase()} by ${log.user_id || 'unknown'}`,
      text: [
        'SwiftShield Security Alert',
        '─'.repeat(40),
        `User:           ${log.user_id    || '—'}`,
        `Action:         ${log.action     || '—'}`,
        `File:           ${log.file_name  || '—'}`,
        `Risk Level:     HIGH`,
        `Outside Office: ${log.outside_office ? 'YES' : 'No'}`,
        `Justification:  ${log.justification  || 'NONE PROVIDED'}`,
        `Location:       ${log.latitude && log.longitude ? `${log.latitude.toFixed(4)}, ${log.longitude.toFixed(4)}` : 'Unknown'}`,
        `IP Address:     ${log.ip         || '—'}`,
        `Device:         ${(log.user_agent||'—').slice(0,120)}`,
        `Time:           ${new Date().toLocaleString()}`,
        '─'.repeat(40),
        `Review at: ${dashUrl}/admin.html`
      ].join('\n')
    });
  } catch (e) { console.error('Alert email failed:', e.message); }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function haversineDist(lat1, lon1, lat2, lon2) {
  const r = x => x * Math.PI / 180, R = 6371e3;
  const a = Math.sin(r(lat2-lat1)/2)**2 + Math.cos(r(lat1))*Math.cos(r(lat2))*Math.sin(r(lon2-lon1)/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

function computeRisk(outsideOffice, justification, userAgent) {
  if (!outsideOffice) return 'low';
  if (!justification || justification.trim().length === 0) return 'high';
  const ua = (userAgent||'').toLowerCase();
  if (['curl','wget','python','go-http','java/','axios','postman'].some(h => ua.includes(h))) return 'high';
  if (justification.trim().length < 20) return 'medium';
  return 'low';
}

function sanitise(val, max=500) {
  if (typeof val !== 'string') return null;
  return validator.escape(val.trim()).slice(0, max);
}

function validCoord(lat, lon) {
  return lat != null && lon != null && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

async function insertLog(doc) {
  if (!logsCol) throw new Error('DB not ready');
  const r = await logsCol.insertOne({ ...doc, timestamp: new Date() });
  return r.insertedId;
}

const OFFICE = {
  latitude:  parseFloat(process.env.OFFICE_LAT    || '19.0219594'),
  longitude: parseFloat(process.env.OFFICE_LON    || '73.0934445'),
  radius:    parseInt(process.env.OFFICE_RADIUS   || '2000', 10)
};

app.get('/config', (_req, res) => res.json({ office: OFFICE }));

function requireAdminKey(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.adminKey;
  if (!key || key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' });
  next();
}

// ── Google OAuth2 Routes ──────────────────────────────────────────────────────

// Step 1: Admin visits this URL to connect Google Drive
// Protected by admin key: GET /auth/google?adminKey=YOUR_KEY
app.get('/auth/google', authLimiter, requireAdminKey, (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.status(500).json({ error: 'Google OAuth not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env' });
  }
  const oauth2Client = getOAuth2Client();
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',   // gets refresh_token so it works long-term
    prompt: 'consent',        // forces refresh_token even if already authorized
    scope: ['https://www.googleapis.com/auth/drive.file']
  });
  res.redirect(url);
});

// Step 2: Google redirects here after user approves
app.get('/auth/google/callback', authLimiter, async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.status(400).send(`Google auth error: ${error}`);
  if (!code)  return res.status(400).send('No authorization code received.');

  try {
    const oauth2Client = getOAuth2Client();
    const { tokens } = await oauth2Client.getToken(code);
    await saveToken(tokens);
    console.log('✅  Google Drive token saved → MongoDB');
    res.send(`
      <html><body style="font-family:monospace;background:#0d1117;color:#58d68d;padding:40px">
        <h2>✅ Google Drive Connected!</h2>
        <p>SwiftShield can now export logs to your Google Drive.</p>
        <p>You can now use <strong>POST /api/export-to-drive</strong> from the admin dashboard.</p>
        <p><a href="/admin.html" style="color:#58a6ff">← Back to Dashboard</a></p>
      </body></html>
    `);
  } catch (err) {
    console.error('Token exchange failed:', err.message);
    res.status(500).send('Failed to exchange token: ' + err.message);
  }
});

// Check if Drive is connected
app.get('/api/drive/status', adminLimiter, requireAdminKey, async (_req, res) => {
  const token = await loadToken();
  res.json({
    connected: !!token,
    authUrl: `/auth/google?adminKey=${ADMIN_KEY}`
  });
});

// ── POST /api/export-to-drive ─────────────────────────────────────────────────
// Exports all logs as a CSV file and uploads it to Google Drive
app.post('/api/export-to-drive', adminLimiter, requireAdminKey, async (req, res) => {
  const oauth2Client = await getAuthorizedClient();
  if (!oauth2Client) {
    return res.status(401).json({
      error: 'Google Drive not connected. Visit /auth/google to connect.',
      authUrl: `/auth/google?adminKey=${ADMIN_KEY}`
    });
  }

  try {
    // Fetch logs from MongoDB
    const filter = {};
    if (req.query.risk)    filter.risk    = req.query.risk;
    if (req.query.user_id) filter.user_id = req.query.user_id;
    if (req.query.action)  filter.action  = req.query.action;

    const logs = await logsCol.find(filter).sort({ timestamp: -1 }).limit(5000).toArray();

    // Build CSV
    const headers = ['id','timestamp','action','user_id','risk','outside_office','file_name','file_size','ip','latitude','longitude','justification','device_info'];
    const csvRows = [
      headers.join(','),
      ...logs.map(log => headers.map(h => {
        let val = h === 'id' ? log._id.toString() : log[h];
        if (val === undefined || val === null) val = '';
        val = String(val).replace(/"/g, '""');
        return `"${val}"`;
      }).join(','))
    ];
    const csvContent = csvRows.join('\n');

    // Upload to Google Drive
    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    const fileName = `swiftshield-logs-${new Date().toISOString().slice(0,10)}.csv`;

    const fileMetadata = { name: fileName, mimeType: 'text/csv' };
    if (DRIVE_FOLDER_ID) fileMetadata.parents = [DRIVE_FOLDER_ID];

    const { Readable } = require('stream');
    const response = await drive.files.create({
      requestBody: fileMetadata,
      media: { mimeType: 'text/csv', body: Readable.from([csvContent]) },
      fields: 'id, name, webViewLink'
    });

    console.log(`✅  Drive export: ${response.data.name} (${logs.length} rows)`);
    res.json({
      success: true,
      fileName: response.data.name,
      fileId:   response.data.id,
      viewLink: response.data.webViewLink,
      rows:     logs.length
    });

  } catch (err) {
    console.error('Drive export failed:', err.message);
    // If token expired and refresh failed
    if (err.message?.includes('invalid_grant') || err.message?.includes('Token has been expired')) {
      await saveToken(null);
      return res.status(401).json({
        error: 'Google token expired. Please reconnect.',
        authUrl: `/auth/google?adminKey=${ADMIN_KEY}`
      });
    }
    res.status(500).json({ error: 'drive_export_failed', detail: err.message });
  }
});

// ── POST /log ─────────────────────────────────────────────────────────────────
app.post('/log', logLimiter, async (req, res) => {
  const b = req.body || {};
  const userId        = sanitise(b.userId, 100);
  const justification = sanitise(b.justification, 500);
  const deviceInfo    = sanitise(b.deviceInfo, 300);
  const latitude      = typeof b.latitude  === 'number' ? b.latitude  : null;
  const longitude     = typeof b.longitude === 'number' ? b.longitude : null;
  const user_agent    = req.headers['user-agent'] || '';
  const ip            = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const outsideOffice = validCoord(latitude, longitude)
    ? haversineDist(latitude, longitude, OFFICE.latitude, OFFICE.longitude) > OFFICE.radius
    : true;

  if (outsideOffice && (!justification || !justification.trim())) return res.json({ needsJustification: true });

  const risk = computeRisk(outsideOffice, justification, user_agent);
  try {
    const doc = { action:'login', user_id:userId, ip, user_agent, device_info:deviceInfo, latitude, longitude, outside_office:outsideOffice, justification, risk };
    const id  = await insertLog(doc);
    if (risk === 'high') sendAlert({ ...doc, id });
    res.json({ logged: true, id: id.toString(), risk });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'db_error' });
  }
});

// ── POST /log/action ──────────────────────────────────────────────────────────
app.post('/log/action', logLimiter, async (req, res) => {
  const b = req.body || {};
  if (!['upload','download'].includes(b.action)) return res.status(400).json({ error: 'invalid_action' });
  const userId        = sanitise(b.userId, 100);
  const fileName      = sanitise(b.fileName, 260);
  const justification = sanitise(b.justification, 500);
  const deviceInfo    = sanitise(b.deviceInfo, 300);
  const fileSize      = typeof b.fileSize === 'number' ? b.fileSize : null;
  const latitude      = typeof b.latitude  === 'number' ? b.latitude  : null;
  const longitude     = typeof b.longitude === 'number' ? b.longitude : null;
  const user_agent    = req.headers['user-agent'] || '';
  const ip            = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const outsideOffice = validCoord(latitude, longitude)
    ? haversineDist(latitude, longitude, OFFICE.latitude, OFFICE.longitude) > OFFICE.radius
    : true;

  if (outsideOffice && (!justification || !justification.trim())) return res.json({ needsJustification: true });

  const risk = computeRisk(outsideOffice, justification, user_agent);
  try {
    const doc = { action:b.action, user_id:userId, ip, user_agent, device_info:deviceInfo, file_name:fileName, file_size:fileSize, latitude, longitude, outside_office:outsideOffice, justification, risk };
    const id  = await insertLog(doc);
    if (risk === 'high') sendAlert({ ...doc, id });
    res.json({ logged: true, id: id.toString(), risk });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'db_error' });
  }
});

// ── GET /api/logs ─────────────────────────────────────────────────────────────
app.get('/api/logs', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit||'200',10), 1000);
    const skip  = parseInt(req.query.skip||'0', 10);
    const f = {};
    if (req.query.risk)    f.risk    = req.query.risk;
    if (req.query.user_id) f.user_id = req.query.user_id;
    if (req.query.action)  f.action  = req.query.action;
    const [rows, total] = await Promise.all([
      logsCol.find(f).sort({ timestamp:-1 }).skip(skip).limit(limit).toArray(),
      logsCol.countDocuments(f)
    ]);
    res.json({ total, rows: rows.map(({ _id, ...r }) => ({ id: _id.toString(), ...r })) });
  } catch { res.status(500).json({ error:'db_error' }); }
});

// ── GET /api/stats ────────────────────────────────────────────────────────────
app.get('/api/stats', adminLimiter, requireAdminKey, async (_req, res) => {
  try {
    const [total, highRisk, externalAccess, byAction] = await Promise.all([
      logsCol.countDocuments({}),
      logsCol.countDocuments({ risk:'high' }),
      logsCol.countDocuments({ outside_office:true }),
      logsCol.aggregate([{ $group:{ _id:'$action', count:{ $sum:1 } } }]).toArray()
    ]);
    res.json({ total, highRisk, externalAccess, byAction });
  } catch { res.status(500).json({ error:'db_error' }); }
});

// ── DELETE /api/logs/:id ──────────────────────────────────────────────────────
app.delete('/api/logs/:id', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error:'invalid_id' });
    await logsCol.deleteOne({ _id: new ObjectId(id) });
    res.json({ deleted: true });
  } catch { res.status(500).json({ error:'db_error' }); }
});

// ── DELETE /api/logs (bulk) ───────────────────────────────────────────────────
app.delete('/api/logs', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const f = {};
    if (req.query.risk)   f.risk      = req.query.risk;
    if (req.query.before) f.timestamp = { $lt: new Date(req.query.before) };
    const r = await logsCol.deleteMany(f);
    res.json({ deleted: r.deletedCount });
  } catch { res.status(500).json({ error:'db_error' }); }
});

// ── Allowlist ─────────────────────────────────────────────────────────────────
app.get('/api/allowlist', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const f = req.query.type ? { type: req.query.type } : {};
    const rows = await allowlistCol.find(f).sort({ createdAt:-1 }).toArray();
    res.json({ rows: rows.map(({ _id,...r }) => ({ id:_id.toString(),...r })), total: rows.length });
  } catch { res.status(500).json({ error:'db_error' }); }
});

app.post('/api/allowlist', adminLimiter, requireAdminKey, async (req, res) => {
  const { type } = req.body||{};
  const value = sanitise(req.body?.value, 200);
  const note  = sanitise(req.body?.note,  300);
  if (!['username','email','ip'].includes(type)) return res.status(400).json({ error:'invalid_type' });
  if (!value?.trim()) return res.status(400).json({ error:'missing_value' });
  if (type==='email' && !validator.isEmail(validator.unescape(value))) return res.status(400).json({ error:'invalid_email' });
  if (type==='ip'    && !validator.isIP(validator.unescape(value)))    return res.status(400).json({ error:'invalid_ip' });
  try {
    const r = await allowlistCol.insertOne({ type, value, note:note||null, createdAt:new Date(), addedBy: req.headers['x-admin-user']||'admin' });
    res.json({ created:true, id:r.insertedId.toString() });
  } catch (err) {
    if (err.code===11000) return res.status(409).json({ error:'already_exists' });
    res.status(500).json({ error:'db_error' });
  }
});

app.delete('/api/allowlist/:id', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error:'invalid_id' });
    const r = await allowlistCol.deleteOne({ _id:new ObjectId(id) });
    if (!r.deletedCount) return res.status(404).json({ error:'not_found' });
    res.json({ deleted:true });
  } catch { res.status(500).json({ error:'db_error' }); }
});

app.patch('/api/allowlist/:id', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const { id } = req.params;
    const note = sanitise(req.body?.note, 300);
    if (!ObjectId.isValid(id)) return res.status(400).json({ error:'invalid_id' });
    await allowlistCol.updateOne({ _id:new ObjectId(id) }, { $set:{ note } });
    res.json({ updated:true });
  } catch { res.status(500).json({ error:'db_error' }); }
});

app.get('/api/admin/verify', adminLimiter, requireAdminKey, (_req, res) => res.json({ ok:true }));

app.use((err, _req, res, _next) => { console.error(err.message); res.status(500).json({ error:'internal_error' }); });

const shutdown = () => client.close().then(() => { console.log('MongoDB closed'); process.exit(0); });
process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);

app.listen(PORT, () => console.log(`SwiftShield v3 → http://localhost:${PORT}`));
