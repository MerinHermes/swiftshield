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
  await ensureDb();
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
    await ensureDb();
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
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
  serverSelectionTimeoutMS: 8000,
  connectTimeoutMS: 8000
});

let logsCol, allowlistCol;
let dbReady = false;

async function ensureDb() {
  if (dbReady) return;
  await client.connect();
  const db = client.db(DB_NAME);
  logsCol      = db.collection('logs');
  allowlistCol = db.collection('allowlist');
  await logsCol.createIndex({ timestamp: -1 });
  await logsCol.createIndex({ user_id: 1 });
  await logsCol.createIndex({ risk: 1 });
  await allowlistCol.createIndex({ value: 1 }, { unique: true });
  await allowlistCol.createIndex({ type: 1 });
  dbReady = true;
  console.log('✅  MongoDB connected →', DB_NAME);
}

// Pre-warm on startup
ensureDb().catch(err => console.error('⚠  MongoDB pre-warm failed:', err.message));

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
  await ensureDb();
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
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/drive.file',
      'https://www.googleapis.com/auth/drive.readonly',
      'https://www.googleapis.com/auth/drive.metadata.readonly',
      'https://www.googleapis.com/auth/admin.reports.audit.readonly'
    ]
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

// ── POST /api/drive/watch — Register webhook with Google Drive ────────────────
// Call this once after connecting Google to start watching the shared folder.
// Google Drive webhooks expire after 1 week — call again to renew.
app.post('/api/drive/watch', adminLimiter, requireAdminKey, async (req, res) => {
  const oauth2Client = await getAuthorizedClient();
  if (!oauth2Client) return res.status(401).json({ error: 'Google Drive not connected.' });
  if (!DRIVE_FOLDER_ID) return res.status(400).json({ error: 'GOOGLE_DRIVE_FOLDER_ID not set in env.' });

  try {
    const drive = google.drive({ version: 'v3', auth: oauth2Client });

    // Get current folder pageToken (so we only get NEW changes, not historical)
    const startPageToken = await drive.changes.getStartPageToken({});
    const pageToken = startPageToken.data.startPageToken;

    // Save pageToken to MongoDB so webhook handler can use it
    const db = client.db(DB_NAME);
    await db.collection('config').updateOne(
      { _id: 'drive_watch' },
      { $set: { pageToken, folderId: DRIVE_FOLDER_ID, updatedAt: new Date() } },
      { upsert: true }
    );

    // Register the webhook channel with Google
    const channelId = `swiftshield-${Date.now()}`;
    const webhookUrl = `${process.env.ALLOWED_ORIGINS?.split(',')[0] || 'https://swiftshield.in'}/api/drive/webhook`;

    const response = await drive.changes.watch({
      pageToken,
      requestBody: {
        id:      channelId,
        type:    'web_hook',
        address: webhookUrl,
        expiration: String(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      }
    });

    // Save channel info so we can stop/renew it later
    await db.collection('config').updateOne(
      { _id: 'drive_channel' },
      { $set: { channelId, resourceId: response.data.resourceId, expiration: response.data.expiration, updatedAt: new Date() } },
      { upsert: true }
    );

    console.log('✅  Drive webhook registered:', webhookUrl);
    res.json({
      success:    true,
      channelId,
      webhookUrl,
      expiration: new Date(parseInt(response.data.expiration)).toISOString(),
      note:       'Webhook expires in 7 days. Call POST /api/drive/watch again to renew.'
    });
  } catch (err) {
    console.error('Drive watch failed:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/drive/webhook — Receive push notifications from Google Drive ────
// Google pings this every time any file in Drive changes.
// We then look up what changed and log it to SwiftShield.
app.post('/api/drive/webhook', async (req, res) => {
  // Always respond 200 immediately — Google will retry if we don't
  res.sendStatus(200);

  // Ignore sync/heartbeat messages
  const state = req.headers['x-goog-resource-state'];
  if (!state || state === 'sync') return;

  try {
    const oauth2Client = await getAuthorizedClient();
    if (!oauth2Client) return;

    const drive = google.drive({ version: 'v3', auth: oauth2Client });
    const db    = client.db(DB_NAME);

    // Get saved pageToken
    const watchDoc = await db.collection('config').findOne({ _id: 'drive_watch' });
    if (!watchDoc?.pageToken) return;

    // Fetch what changed since last pageToken
    const changesRes = await drive.changes.list({
      pageToken:                watchDoc.pageToken,
      fields:                   'nextPageToken, newStartPageToken, changes(type, changeType, fileId, file(id, name, size, mimeType, owners, lastModifyingUser, modifiedTime, parents, trashed))',
      includeItemsFromAllDrives: true,
      supportsAllDrives:         true,
      pageSize:                  50
    });

    const changes = changesRes.data.changes || [];

    // Save updated pageToken for next time
    const newPageToken = changesRes.data.newStartPageToken || changesRes.data.nextPageToken;
    if (newPageToken) {
      await db.collection('config').updateOne(
        { _id: 'drive_watch' },
        { $set: { pageToken: newPageToken, updatedAt: new Date() } }
      );
    }

    for (const change of changes) {
      const file = change.file;
      if (!file || file.trashed) continue;

      // Only care about files inside our watched folder
      const inFolder = file.parents && file.parents.includes(DRIVE_FOLDER_ID);
      if (!inFolder) continue;

      // Determine action: 'upload' for new/modified files
      const action = 'upload';

      // Who did it — use lastModifyingUser email as user_id
      const user_id   = file.lastModifyingUser?.emailAddress || file.owners?.[0]?.emailAddress || 'unknown';
      const file_name = file.name || 'unknown';
      const file_size = file.size ? parseInt(file.size) : null;

      // Log it to SwiftShield
      const doc = {
        action,
        user_id,
        file_name,
        file_size,
        source:        'google_drive',
        drive_file_id: file.id,
        ip:            null,
        user_agent:    'Google Drive',
        device_info:   `Drive: ${file.mimeType || 'unknown type'}`,
        latitude:      null,
        longitude:     null,
        outside_office: true,  // Drive activity is always remote
        justification: null,
        risk:          'medium' // Drive uploads without justification = medium risk
      };

      await insertLog(doc);
      console.log(`📁  Drive activity logged: ${action} "${file_name}" by ${user_id}`);

      // Send high-risk alert if it's an unknown user
      if (!['admin@swiftshield.in', process.env.ALERT_EMAIL_USER].includes(user_id)) {
        sendAlert({ ...doc, risk: 'high' });
      }
    }
  } catch (err) {
    console.error('Drive webhook error:', err.message);
  }
});

// ── Admin Reports API — Poll Drive download/view events ───────────────────────
const POLL_EVENTS = ['download', 'view']; // event names from Admin SDK

async function pollDriveReports() {
  try {
    const oauth2Client = await getAuthorizedClient();
    if (!oauth2Client) return;

    await ensureDb();
    const db = client.db(DB_NAME);

    // Load last poll time from MongoDB (default: 6 minutes ago)
    const stateDoc = await db.collection('config').findOne({ _id: 'reports_poll' });
    const lastPoll = stateDoc?.lastPoll || new Date(Date.now() - 6 * 60 * 1000);

    const reports = google.admin({ version: 'reports_v1', auth: oauth2Client });

    const response = await reports.activities.list({
      userKey:         'all',
      applicationName: 'drive',
      startTime:       new Date(lastPoll).toISOString(),
      maxResults:      200
    });

    const activities = response.data.items || [];
    let logged = 0;

    for (const activity of activities) {
      const actor    = activity.actor?.email || 'unknown';
      const events   = activity.events || [];
      const time     = activity.id?.time ? new Date(activity.id.time) : new Date();

      for (const event of events) {
        const eventName = (event.name || '').toLowerCase();
        if (!POLL_EVENTS.includes(eventName)) continue;

        // Extract file details from event parameters
        const params    = {};
        (event.parameters || []).forEach(p => { params[p.name] = p.value || p.boolValue || p.intValue || null; });

        const fileName  = params['doc_title'] || params['doc_id'] || 'unknown';
        const fileId    = params['doc_id'] || null;
        const ownerEmail = params['owner'] || null;

        // Skip if already logged (dedup by fileId + actor + time)
        const dupKey = fileId + '-' + actor + '-' + time.toISOString() + '-' + eventName;
        const exists = await db.collection('config').findOne({ _id: 'report_seen_' + dupKey });
        if (exists) continue;

        // Mark as seen
        await db.collection('config').insertOne({
          _id: 'report_seen_' + dupKey,
          createdAt: new Date()
        });

        const action = eventName === 'download' ? 'download' : 'view';

        // Cross-reference last known location from SwiftShield check-ins (within 24h)
        const lastCheckin = await logsCol.findOne(
          {
            user_id: actor,
            action: 'login',
            latitude: { $ne: null },
            timestamp: { $gte: new Date(time.getTime() - 24 * 60 * 60 * 1000) }
          },
          { sort: { timestamp: -1 } }
        );

        const latitude       = lastCheckin ? lastCheckin.latitude  : null;
        const longitude      = lastCheckin ? lastCheckin.longitude : null;
        const outside_office = lastCheckin ? lastCheckin.outside_office : true;
        const risk           = outside_office ? 'high' : 'medium';
        const location_note  = lastCheckin
          ? 'Location inferred from check-in at ' + new Date(lastCheckin.timestamp).toLocaleTimeString()
          : 'Location unknown - no recent check-in';

        const doc = {
          action,
          user_id:       actor,
          file_name:     fileName,
          file_size:     null,
          source:        'google_drive',
          drive_file_id: fileId,
          drive_owner:   ownerEmail,
          ip:            lastCheckin ? lastCheckin.ip : null,
          user_agent:    'Google Drive',
          device_info:   'Drive: ' + eventName + ' | ' + location_note,
          latitude,
          longitude,
          outside_office,
          justification: null,
          risk
        };

        await insertLog(doc);
        logged++;
        console.log('📥  Drive ' + eventName + ' logged: "' + fileName + '" by ' + actor + ' | outside=' + outside_office);
      }
    }

    // Save last poll time
    await db.collection('config').updateOne(
      { _id: 'reports_poll' },
      { $set: { lastPoll: new Date(), logged, updatedAt: new Date() } },
      { upsert: true }
    );

    if (logged > 0) console.log('✅  Reports poll: ' + logged + ' new events logged');

  } catch (err) {
    console.error('Reports poll error:', err.message);
  }
}

// Poll every 5 minutes
setInterval(pollDriveReports, 5 * 60 * 1000);

// Manual trigger endpoint (admin only)
app.post('/api/drive/poll', adminLimiter, requireAdminKey, async (_req, res) => {
  try {
    await pollDriveReports();
    res.json({ success: true, message: 'Poll complete. Check /api/logs for new download/view events.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    await ensureDb();
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
    await ensureDb();
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
    await ensureDb();
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error:'invalid_id' });
    await logsCol.deleteOne({ _id: new ObjectId(id) });
    res.json({ deleted: true });
  } catch { res.status(500).json({ error:'db_error' }); }
});

// ── DELETE /api/logs (bulk) ───────────────────────────────────────────────────
app.delete('/api/logs', adminLimiter, requireAdminKey, async (req, res) => {
  try {
    await ensureDb();
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
    await ensureDb();
    const f = req.query.type ? { type: req.query.type } : {};
    const rows = await allowlistCol.find(f).sort({ createdAt:-1 }).toArray();
    res.json({ rows: rows.map(({ _id,...r }) => ({ id:_id.toString(),...r })), total: rows.length });
  } catch { res.status(500).json({ error:'db_error' }); }
});

app.post('/api/allowlist', adminLimiter, requireAdminKey, async (req, res) => {
  await ensureDb();
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

// Graceful shutdown (no-op on Vercel serverless)

app.listen(PORT, () => console.log(`SwiftShield v3 → http://localhost:${PORT}`));
