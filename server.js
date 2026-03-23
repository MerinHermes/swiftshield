/**
 * SwiftShield v2 — Hardened Server
 * Fixes: MongoDB, rate limiting, input validation, auth on /api/logs,
 *        helmet headers, action logging, graceful shutdown.
 */

const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const validator  = require('validator');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Security Headers (Helmet) ────────────────────────────────────────────────
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

// ─── CORS — restrict in production ────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  }
}));

app.use(bodyParser.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate Limiting ─────────────────────────────────────────────────────────────
const logLimiter = rateLimit({
  windowMs: 60 * 1000,     // 1 minute
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_requests' }
});
const adminLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });

// ─── MongoDB ───────────────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME   = process.env.MONGO_DB  || 'swiftshield';
const ADMIN_KEY = process.env.ADMIN_API_KEY || 'changeme-in-production';

const client = new MongoClient(MONGO_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

let logsCol;
let allowlistCol;

(async () => {
  try {
    await client.connect();
    const db = client.db(DB_NAME);
    logsCol = db.collection('logs');
    await logsCol.createIndex({ timestamp: -1 });
    await logsCol.createIndex({ user_id: 1 });
    await logsCol.createIndex({ risk: 1 });

    allowlistCol = db.collection('allowlist');
    await allowlistCol.createIndex({ value: 1 }, { unique: true });
    await allowlistCol.createIndex({ type: 1 });
    console.log(`✅  MongoDB connected → db: ${DB_NAME}`);
  } catch (err) {
    console.error('❌  MongoDB connection failed:', err.message);
    process.exit(1);
  }
})();

// ─── Helpers ──────────────────────────────────────────────────────────────────
function haversineDist(lat1, lon1, lat2, lon2) {
  const toRad = x => x * Math.PI / 180;
  const R  = 6371e3;
  const φ1 = toRad(lat1), φ2 = toRad(lat2);
  const Δφ = toRad(lat2 - lat1);
  const Δλ = toRad(lon2 - lon1);
  const a  = Math.sin(Δφ/2)**2 + Math.cos(φ1)*Math.cos(φ2)*Math.sin(Δλ/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

function computeRisk(outsideOffice, justification, userAgent) {
  if (!outsideOffice) return 'low';
  if (!justification || justification.trim().length === 0) return 'high';
  // Suspicious UA hints
  const ua = (userAgent || '').toLowerCase();
  const botHints = ['curl', 'wget', 'python', 'go-http', 'java/', 'axios', 'postman'];
  if (botHints.some(h => ua.includes(h))) return 'high';
  if (justification.trim().length < 20) return 'medium';
  return 'low';
}

function sanitiseString(val, maxLen = 500) {
  if (typeof val !== 'string') return null;
  return validator.escape(val.trim()).slice(0, maxLen);
}

function validateCoord(lat, lon) {
  if (lat == null || lon == null) return false;
  return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

async function insertLog(doc) {
  if (!logsCol) throw new Error('DB not ready');
  const r = await logsCol.insertOne({ ...doc, timestamp: new Date() });
  return r.insertedId;
}

// ─── Office Config ─────────────────────────────────────────────────────────────
const OFFICE = {
  latitude:  parseFloat(process.env.OFFICE_LAT  || '19.0219594'),
  longitude: parseFloat(process.env.OFFICE_LON  || '73.0934445'),
  radius:    parseInt(process.env.OFFICE_RADIUS || '2000', 10)
};

app.get('/config', (_req, res) => res.json({ office: OFFICE }));

// ─── Simple API key middleware for admin routes ────────────────────────────────
function requireAdminKey(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.adminKey;
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// ─── POST /log  (login simulation) ────────────────────────────────────────────
app.post('/log', logLimiter, async (req, res) => {
  const body        = req.body || {};
  const userId      = sanitiseString(body.userId, 100);
  const justification = sanitiseString(body.justification, 500);
  const deviceInfo  = sanitiseString(body.deviceInfo, 300);
  const latitude    = typeof body.latitude  === 'number' ? body.latitude  : null;
  const longitude   = typeof body.longitude === 'number' ? body.longitude : null;
  const user_agent  = req.headers['user-agent'] || '';
  const ip          = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;

  const coordsValid    = validateCoord(latitude, longitude);
  const outsideOffice  = coordsValid
    ? haversineDist(latitude, longitude, OFFICE.latitude, OFFICE.longitude) > OFFICE.radius
    : true; // treat unknown location as outside

  if (outsideOffice && (!justification || justification.trim().length === 0)) {
    return res.json({ needsJustification: true });
  }

  const risk = computeRisk(outsideOffice, justification, user_agent);

  try {
    const id = await insertLog({
      action:        'login',
      user_id:       userId,
      ip,
      user_agent,
      device_info:   deviceInfo,
      latitude,
      longitude,
      outside_office: outsideOffice,
      justification,
      risk
    });
    res.json({ logged: true, id: id.toString(), risk });
  } catch (err) {
    console.error('DB insert error', err.message);
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── POST /log/action  (upload / download) ─────────────────────────────────────
// BUG FIX: actions have their own endpoint — no login simulation required
app.post('/log/action', logLimiter, async (req, res) => {
  const body        = req.body || {};
  const action      = body.action;
  if (!['upload', 'download'].includes(action)) {
    return res.status(400).json({ error: 'invalid_action' });
  }

  const userId        = sanitiseString(body.userId, 100);
  const fileName      = sanitiseString(body.fileName, 260);
  const justification = sanitiseString(body.justification, 500);
  const deviceInfo    = sanitiseString(body.deviceInfo, 300);
  const fileSize      = typeof body.fileSize === 'number' ? body.fileSize : null;
  const latitude      = typeof body.latitude  === 'number' ? body.latitude  : null;
  const longitude     = typeof body.longitude === 'number' ? body.longitude : null;
  const user_agent    = req.headers['user-agent'] || '';
  const ip            = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;

  const coordsValid   = validateCoord(latitude, longitude);
  const outsideOffice = coordsValid
    ? haversineDist(latitude, longitude, OFFICE.latitude, OFFICE.longitude) > OFFICE.radius
    : true;

  if (outsideOffice && (!justification || justification.trim().length === 0)) {
    return res.json({ needsJustification: true });
  }

  const risk = computeRisk(outsideOffice, justification, user_agent);

  try {
    const id = await insertLog({
      action,
      user_id:       userId,
      ip,
      user_agent,
      device_info:   deviceInfo,
      file_name:     fileName,
      file_size:     fileSize,
      latitude,
      longitude,
      outside_office: outsideOffice,
      justification,
      risk
    });
    res.json({ logged: true, id: id.toString(), risk });
  } catch (err) {
    console.error('DB insert error', err.message);
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── GET /api/logs  (protected) ────────────────────────────────────────────────
app.get('/api/logs', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit || '200', 10), 1000);
    const skip   = parseInt(req.query.skip || '0', 10);
    const filter = {};
    if (req.query.risk)    filter.risk    = req.query.risk;
    if (req.query.user_id) filter.user_id = req.query.user_id;
    if (req.query.action)  filter.action  = req.query.action;

    const [rows, total] = await Promise.all([
      logsCol.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).toArray(),
      logsCol.countDocuments(filter)
    ]);

    const normalised = rows.map(({ _id, ...rest }) => ({ id: _id.toString(), ...rest }));
    res.json({ total, rows: normalised });
  } catch (err) {
    console.error('DB fetch error', err.message);
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── GET /api/stats  (protected) ───────────────────────────────────────────────
app.get('/api/stats', adminLimiter, requireAdminKey, async (_req, res) => {
  try {
    const [total, highRisk, externalAccess, byAction] = await Promise.all([
      logsCol.countDocuments({}),
      logsCol.countDocuments({ risk: 'high' }),
      logsCol.countDocuments({ outside_office: true }),
      logsCol.aggregate([
        { $group: { _id: '$action', count: { $sum: 1 } } }
      ]).toArray()
    ]);
    res.json({ total, highRisk, externalAccess, byAction });
  } catch (err) {
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── DELETE /api/logs/:id  (protected) ─────────────────────────────────────────
app.delete('/api/logs/:id', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'invalid_id' });
    await logsCol.deleteOne({ _id: new ObjectId(id) });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── GET /api/allowlist  (protected) ───────────────────────────────────────────
app.get('/api/allowlist', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const filter = {};
    if (req.query.type) filter.type = req.query.type;
    const rows = await allowlistCol.find(filter).sort({ createdAt: -1 }).toArray();
    const normalised = rows.map(({ _id, ...rest }) => ({ id: _id.toString(), ...rest }));
    res.json({ rows: normalised, total: normalised.length });
  } catch (err) {
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── POST /api/allowlist  (protected) ──────────────────────────────────────────
app.post('/api/allowlist', adminLimiter, requireAdminKey, async (req, res) => {
  const body  = req.body || {};
  const type  = body.type;
  const value = sanitiseString(body.value, 200);
  const note  = sanitiseString(body.note, 300);

  if (!['username', 'email', 'ip'].includes(type)) {
    return res.status(400).json({ error: 'invalid_type' });
  }
  if (!value || value.trim().length === 0) {
    return res.status(400).json({ error: 'missing_value' });
  }
  if (type === 'email' && !validator.isEmail(validator.unescape(value))) {
    return res.status(400).json({ error: 'invalid_email' });
  }
  if (type === 'ip' && !validator.isIP(validator.unescape(value))) {
    return res.status(400).json({ error: 'invalid_ip' });
  }

  try {
    const r = await allowlistCol.insertOne({
      type,
      value,
      note:      note || null,
      createdAt: new Date(),
      addedBy:   req.headers['x-admin-user'] || 'admin'
    });
    res.json({ created: true, id: r.insertedId.toString() });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: 'already_exists' });
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── DELETE /api/allowlist/:id  (protected) ────────────────────────────────────
app.delete('/api/allowlist/:id', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'invalid_id' });
    const r = await allowlistCol.deleteOne({ _id: new ObjectId(id) });
    if (r.deletedCount === 0) return res.status(404).json({ error: 'not_found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── PATCH /api/allowlist/:id  (update note) ───────────────────────────────────
app.patch('/api/allowlist/:id', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const id   = req.params.id;
    const note = sanitiseString(req.body?.note, 300);
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'invalid_id' });
    await allowlistCol.updateOne({ _id: new ObjectId(id) }, { $set: { note } });
    res.json({ updated: true });
  } catch (err) {
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── DELETE /api/logs  (bulk clear, protected) ─────────────────────────────────
app.delete('/api/logs', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    const filter = {};
    if (req.query.risk)   filter.risk   = req.query.risk;
    if (req.query.before) filter.timestamp = { $lt: new Date(req.query.before) };
    const r = await logsCol.deleteMany(filter);
    res.json({ deleted: r.deletedCount });
  } catch (err) {
    res.status(500).json({ error: 'db_error' });
  }
});

// ─── GET /api/admin/verify  (check key is valid) ───────────────────────────────
app.get('/api/admin/verify', adminLimiter, requireAdminKey, (_req, res) => {
  res.json({ ok: true });
});

// ─── Global error handler ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error(err.message);
  res.status(500).json({ error: 'internal_error' });
});

// ─── Graceful shutdown ─────────────────────────────────────────────────────────
const shutdown = () => client.close().then(() => { console.log('MongoDB closed'); process.exit(0); });
process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);

app.listen(PORT, () => console.log(`SwiftShield v2 → http://localhost:${PORT}`));
