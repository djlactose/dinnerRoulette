const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const { Server } = require('socket.io');
const webpush = require('web-push');
const nodemailer = require('nodemailer');

// ── Environment Validation ─────────────────────────────────────────────────────
let API_KEY = process.env.GOOGLE_API_KEY;
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 8080;
let JWT_SECRET = process.env.JWT_SECRET;

if (!API_KEY) {
  console.error('ERROR: GOOGLE_API_KEY is required');
  process.exit(1);
}

if (!JWT_SECRET) {
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('WARNING: JWT_SECRET not set — using random value. Sessions will not persist across restarts.');
}

// ── VAPID Keys for Web Push ────────────────────────────────────────────────────
// NOTE: VAPID keys are loaded later after DB is initialized (see initVapid below)
let VAPID_PUBLIC, VAPID_PRIVATE, VAPID_SOURCE;

console.log(`Environment: ${NODE_ENV}`);
console.log(`Port: ${PORT}`);
console.log(`Database: ./data/db.sqlite`);

// ── Express App & Middleware ────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-eval'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdn.socket.io", "https://maps.googleapis.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https://maps.gstatic.com", "https://maps.googleapis.com", "https://*.ggpht.com", "https://*.googleusercontent.com", "https://*.giphy.com", "https://media.giphy.com", "https://media0.giphy.com", "https://media1.giphy.com", "https://media2.giphy.com", "https://media3.giphy.com", "https://media4.giphy.com", "https://i.giphy.com"],
      connectSrc: ["'self'", "ws:", "wss:", "https://maps.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      upgradeInsecureRequests: null,
    }
  }
}));
app.use(compression());
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('CDN-Cache-Control', 'no-store');
  }
}));

// Rate limiting (disabled in test mode)
const noopLimiter = (req, res, next) => next();
const authLimiter = NODE_ENV === 'test' ? noopLimiter : rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, try again later' },
});
const apiLimiter = NODE_ENV === 'test' ? noopLimiter : rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' },
});
if (NODE_ENV !== 'test') app.use('/api', apiLimiter);

// HTTPS redirect in production (only when behind a reverse proxy)
if (NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] === 'http') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// ── Database ────────────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || './data/db.sqlite';
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
  );
  CREATE TABLE IF NOT EXISTS friends (
    user_id INTEGER,
    friend_id INTEGER,
    UNIQUE(user_id, friend_id)
  );
  CREATE TABLE IF NOT EXISTS likes (
    user_id INTEGER,
    place TEXT,
    place_id TEXT,
    restaurant_type TEXT
  );
  CREATE TABLE IF NOT EXISTS dislikes (
    user_id INTEGER,
    place TEXT,
    place_id TEXT,
    restaurant_type TEXT
  );
  CREATE TABLE IF NOT EXISTS want_to_try (
    user_id INTEGER,
    place TEXT,
    place_id TEXT,
    restaurant_type TEXT,
    UNIQUE(user_id, place)
  );
  CREATE TABLE IF NOT EXISTS places (
    user_id INTEGER,
    place TEXT,
    place_id TEXT,
    restaurant_type TEXT,
    UNIQUE(user_id, place)
  );
  CREATE TABLE IF NOT EXISTS suggestions (
    user_id INTEGER,
    place TEXT,
    place_id TEXT,
    restaurant_type TEXT,
    UNIQUE(user_id, place)
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    code TEXT UNIQUE,
    creator_id INTEGER,
    name TEXT,
    status TEXT DEFAULT 'open',
    winner_place TEXT,
    picked_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS session_members (
    session_id INTEGER,
    user_id INTEGER,
    UNIQUE(session_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS session_suggestions (
    id INTEGER PRIMARY KEY,
    session_id INTEGER,
    user_id INTEGER,
    place TEXT,
    place_id TEXT,
    restaurant_type TEXT,
    lat REAL,
    lng REAL,
    UNIQUE(session_id, place)
  );
  CREATE TABLE IF NOT EXISTS session_votes (
    session_id INTEGER,
    user_id INTEGER,
    suggestion_id INTEGER,
    UNIQUE(session_id, user_id, suggestion_id)
  );
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    endpoint TEXT UNIQUE NOT NULL,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS session_messages (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    message_type TEXT DEFAULT 'text',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS message_reactions (
    id INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    emoji TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (message_id) REFERENCES session_messages(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(message_id, user_id, emoji)
  );
  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
  );
`);

// Migrate existing tables (add columns if missing)
try { db.exec('ALTER TABLE likes ADD COLUMN place_id TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE dislikes ADD COLUMN place_id TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE places ADD COLUMN place_id TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE suggestions ADD COLUMN place_id TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE likes ADD COLUMN restaurant_type TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE dislikes ADD COLUMN restaurant_type TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE places ADD COLUMN restaurant_type TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE suggestions ADD COLUMN restaurant_type TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE session_suggestions ADD COLUMN restaurant_type TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE friends ADD COLUMN status TEXT DEFAULT \'accepted\''); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE likes ADD COLUMN visited_at TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE likes ADD COLUMN notes TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE session_suggestions ADD COLUMN price_level INTEGER'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE sessions ADD COLUMN voting_deadline TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN email TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN created_at TEXT'); } catch (e) { /* already exists */ }
try { db.exec("UPDATE users SET created_at = datetime('now') WHERE created_at IS NULL"); } catch (e) { /* ignore */ }
try { db.exec('ALTER TABLE likes ADD COLUMN starred INTEGER DEFAULT 0'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE want_to_try ADD COLUMN starred INTEGER DEFAULT 0'); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE session_votes ADD COLUMN vote_type TEXT DEFAULT 'up'"); } catch (e) { /* already exists */ }
try { db.exec("ALTER TABLE session_messages ADD COLUMN message_type TEXT DEFAULT 'text'"); } catch (e) { /* already exists */ }

// Deduplicate likes and add unique index to prevent future duplicates
try {
  db.exec(`
    DELETE FROM likes WHERE rowid NOT IN (
      SELECT MIN(rowid) FROM likes GROUP BY user_id, place
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_likes_user_place ON likes(user_id, place);
  `);
} catch (e) { /* index already exists */ }

// ── App Settings Helpers ──────────────────────────────────────────────────────
function getSetting(key) {
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(key, value) {
  db.prepare(`
    INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
  `).run(key, value);
}

// ── Encryption Helpers (for SMTP password at rest) ───────────────────────────
function encryptSetting(plaintext) {
  const key = crypto.scryptSync(JWT_SECRET, 'smtp-salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + tag + ':' + encrypted;
}

function decryptSetting(ciphertext) {
  const [ivHex, tagHex, encrypted] = ciphertext.split(':');
  const key = crypto.scryptSync(JWT_SECRET, 'smtp-salt', 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ── SMTP Transport Helper ────────────────────────────────────────────────────
function getSmtpTransport() {
  const host = getSetting('smtp_host');
  const port = getSetting('smtp_port');
  if (!host || !port) return null;
  const user = getSetting('smtp_user');
  const passEnc = getSetting('smtp_password');
  const opts = {
    host,
    port: parseInt(port, 10),
    secure: getSetting('smtp_secure') === 'true',
  };
  if (user && passEnc) {
    try {
      opts.auth = { user, pass: decryptSetting(passEnc) };
    } catch (e) {
      console.error('Failed to decrypt SMTP password:', e.message);
      return null;
    }
  } else if (user) {
    opts.auth = { user, pass: '' };
  }
  return nodemailer.createTransport(opts);
}

// ── VAPID Key Initialization (DB → env → ephemeral) ─────────────────────────
function initVapid() {
  const dbPub = getSetting('vapid_public_key');
  const dbPriv = getSetting('vapid_private_key');
  if (dbPub && dbPriv) {
    VAPID_PUBLIC = dbPub;
    VAPID_PRIVATE = dbPriv;
    VAPID_SOURCE = 'db';
  } else if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY;
    VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;
    VAPID_SOURCE = 'env';
  } else {
    const keys = webpush.generateVAPIDKeys();
    VAPID_PUBLIC = keys.publicKey;
    VAPID_PRIVATE = keys.privateKey;
    VAPID_SOURCE = 'ephemeral';
    console.warn('WARNING: VAPID keys not set — generated ephemeral keys. Push subscriptions will break on restart.');
  }
  const email = getSetting('vapid_email') || process.env.VAPID_EMAIL || 'mailto:noreply@example.com';
  webpush.setVapidDetails(email, VAPID_PUBLIC, VAPID_PRIVATE);
}
initVapid();

// ── Admin Initialization ─────────────────────────────────────────────────────
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
if (ADMIN_USERNAME) {
  db.prepare('UPDATE users SET is_admin = 1 WHERE LOWER(username) = LOWER(?)').run(ADMIN_USERNAME);
}
// If no admin exists, make the first registered user admin
const adminExists = db.prepare('SELECT 1 FROM users WHERE is_admin = 1').get();
if (!adminExists) {
  const firstUser = db.prepare('SELECT id FROM users ORDER BY id ASC LIMIT 1').get();
  if (firstUser) {
    db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(firstUser.id);
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────────
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username, is_admin: !!user.is_admin }, JWT_SECRET, { expiresIn: getSetting('jwt_expiry') || '12h' });
}

const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';

function cookieOpts(remember) {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: COOKIE_SECURE,
    maxAge: remember ? 12 * 60 * 60 * 1000 : undefined,
  };
}

function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    res.clearCookie('token');
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.user.id);
  if (!user || !user.is_admin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ── Push Notification Helpers ──────────────────────────────────────────────────
async function sendPushToUser(userId, payload) {
  const subs = db.prepare('SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = ?').all(userId);
  for (const sub of subs) {
    try {
      await webpush.sendNotification(
        { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
        JSON.stringify(payload)
      );
    } catch (err) {
      if (err.statusCode === 410 || err.statusCode === 404) {
        db.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?').run(sub.endpoint);
      }
    }
  }
}

async function sendPushToPlanMembers(planId, payload, excludeUserId = null) {
  const members = db.prepare('SELECT user_id FROM session_members WHERE session_id = ?').all(planId);
  for (const m of members) {
    if (m.user_id !== excludeUserId) {
      sendPushToUser(m.user_id, payload);
    }
  }
}

function generatePlanCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function haversine(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// ── Health Check ────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ status: 'ok', uptime: process.uptime() });
  } catch (err) {
    res.status(503).json({ status: 'error', error: 'Database unavailable' });
  }
});

// ── Auth Routes ─────────────────────────────────────────────────────────────────
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password, email, remember } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const trimmedUser = username.trim();
  const trimmedEmail = email ? email.trim().toLowerCase() : null;
  if (trimmedUser.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!trimmedEmail) return res.status(400).json({ error: 'Email is required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) return res.status(400).json({ error: 'Invalid email format' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const existing = db.prepare('SELECT 1 FROM users WHERE LOWER(username) = LOWER(?)').get(trimmedUser);
    if (existing) return res.status(400).json({ error: 'Username taken' });
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const isAdmin = userCount === 0 ? 1 : 0;
    const result = db.prepare("INSERT INTO users (username, password, email, is_admin, created_at) VALUES (?, ?, ?, ?, datetime('now'))").run(trimmedUser, hash, trimmedEmail, isAdmin);
    const token = generateToken({ id: result.lastInsertRowid, username: trimmedUser, is_admin: isAdmin });
    res.cookie('token', token, cookieOpts(remember));
    res.json({ username: trimmedUser, is_admin: !!isAdmin });
  } catch (err) {
    res.status(400).json({ error: 'Username taken' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password, remember } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?)').get(username.trim());
  if (!user) return res.status(401).json({ error: 'User not found' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Bad password' });

  const token = generateToken(user);
  res.cookie('token', token, cookieOpts(remember));
  res.json({ username: user.username, is_admin: !!user.is_admin });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, username, email, is_admin FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, email: user.email || null, is_admin: !!user.is_admin });
});

app.post('/api/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const valid = await bcrypt.compare(currentPassword, user.password);
  if (!valid) return res.status(401).json({ error: 'Incorrect current password' });

  const hash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, req.user.id);
  res.json({ success: true });
});

app.post('/api/delete-account', auth, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required for confirmation' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Incorrect password' });

  const uid = req.user.id;
  const deleteAll = db.transaction(() => {
    db.prepare('DELETE FROM message_reactions WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM session_votes WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM session_suggestions WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM session_members WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM likes WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM dislikes WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM want_to_try WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM places WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM suggestions WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM friends WHERE user_id = ? OR friend_id = ?').run(uid, uid);
    db.prepare('DELETE FROM session_messages WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM push_subscriptions WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM password_reset_tokens WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM users WHERE id = ?').run(uid);
  });
  deleteAll();

  res.clearCookie('token');
  res.json({ success: true });
});

// ── Email Update ─────────────────────────────────────────────────────────────────
app.post('/api/update-email', auth, (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  const trimmed = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return res.status(400).json({ error: 'Invalid email format' });
  db.prepare('UPDATE users SET email = ? WHERE id = ?').run(trimmed, req.user.id);
  res.json({ success: true, email: trimmed });
});

// ── Password Reset ───────────────────────────────────────────────────────────────
app.post('/api/forgot-password', authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const transport = getSmtpTransport();
  if (!transport) return res.status(400).json({ error: 'Password reset is not available. Contact the administrator.' });

  const user = db.prepare('SELECT id, username FROM users WHERE LOWER(email) = LOWER(?)').get(email.trim());
  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    db.prepare('INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, token, expiresAt);
    const from = getSetting('smtp_from') || getSetting('smtp_user');
    try {
      await transport.sendMail({
        from,
        to: email.trim(),
        subject: 'Dinner Roulette — Password Reset',
        text: `Hi ${user.username},\n\nClick the link below to reset your password (valid for 1 hour):\n\n${req.protocol}://${req.get('host')}/reset/${token}\n\nIf you did not request this, you can ignore this email.`,
      });
    } catch (e) {
      console.error('Failed to send reset email:', e.message);
    }
  }
  res.json({ success: true, message: 'If that email is associated with an account, a reset link has been sent.' });
});

app.get('/api/reset-password/:token', (req, res) => {
  const row = db.prepare(`
    SELECT prt.user_id, u.username FROM password_reset_tokens prt
    JOIN users u ON u.id = prt.user_id
    WHERE prt.token = ? AND prt.used = 0 AND prt.expires_at > datetime('now')
  `).get(req.params.token);
  if (!row) return res.json({ valid: false });
  res.json({ valid: true, username: row.username });
});

app.post('/api/reset-password', authLimiter, async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const row = db.prepare(`
    SELECT user_id FROM password_reset_tokens
    WHERE token = ? AND used = 0 AND expires_at > datetime('now')
  `).get(token);
  if (!row) return res.status(400).json({ error: 'Invalid or expired reset link' });

  const hash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, row.user_id);
  db.prepare('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ?').run(row.user_id);
  res.json({ success: true });
});

// ── Admin Routes ─────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const users = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const plans = db.prepare('SELECT COUNT(*) as c FROM sessions').get().c;
  const active_plans = db.prepare("SELECT COUNT(*) as c FROM sessions WHERE status = 'open'").get().c;
  const places = db.prepare('SELECT COUNT(*) as c FROM likes').get().c;
  const smtp_configured = !!(getSetting('smtp_host') && getSetting('smtp_port'));
  const vapid_source = VAPID_SOURCE || 'none';
  res.json({ users, plans, active_plans, places, smtp_configured, vapid_source });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const users = db.prepare('SELECT id, username, email, is_admin, created_at FROM users ORDER BY id ASC').all();
  res.json({ users });
});

app.post('/api/admin/users/:id/edit', adminAuth, (req, res) => {
  const targetId = Number(req.params.id);
  const target = db.prepare('SELECT id, username FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const { username, email } = req.body;
  if (username !== undefined) {
    const trimmed = username.trim();
    if (trimmed.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    const existing = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?').get(trimmed, targetId);
    if (existing) return res.status(400).json({ error: 'Username already taken' });
    db.prepare('UPDATE users SET username = ? WHERE id = ?').run(trimmed, targetId);
  }
  if (email !== undefined) {
    const trimmedEmail = email ? email.trim().toLowerCase() : null;
    if (trimmedEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(trimmedEmail, targetId);
  }
  res.json({ success: true });
});

app.post('/api/admin/users/:id/reset-password', adminAuth, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const hash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, target.id);
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  const targetId = Number(req.params.id);
  if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account from admin panel' });
  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const deleteAll = db.transaction(() => {
    db.prepare('DELETE FROM message_reactions WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM session_votes WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM session_suggestions WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM session_members WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM likes WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM dislikes WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM want_to_try WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM places WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM suggestions WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM friends WHERE user_id = ? OR friend_id = ?').run(targetId, targetId);
    db.prepare('DELETE FROM session_messages WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM push_subscriptions WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM password_reset_tokens WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM users WHERE id = ?').run(targetId);
  });
  deleteAll();
  res.json({ success: true });
});

app.post('/api/admin/users/:id/toggle-admin', adminAuth, (req, res) => {
  const targetId = Number(req.params.id);
  if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot modify your own admin status' });
  const target = db.prepare('SELECT id, is_admin FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const newStatus = target.is_admin ? 0 : 1;
  db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(newStatus, targetId);
  res.json({ success: true, is_admin: !!newStatus });
});

app.get('/api/admin/smtp', adminAuth, (req, res) => {
  res.json({
    host: getSetting('smtp_host') || '',
    port: getSetting('smtp_port') || '587',
    user: getSetting('smtp_user') || '',
    from: getSetting('smtp_from') || '',
    secure: getSetting('smtp_secure') === 'true',
    configured: !!(getSetting('smtp_host') && getSetting('smtp_port')),
  });
});

app.post('/api/admin/smtp', adminAuth, (req, res) => {
  const { host, port, user, password, from, secure } = req.body;
  if (host !== undefined) setSetting('smtp_host', host);
  if (port !== undefined) setSetting('smtp_port', String(port));
  if (user !== undefined) setSetting('smtp_user', user);
  if (password) setSetting('smtp_password', encryptSetting(password));
  if (from !== undefined) setSetting('smtp_from', from);
  if (secure !== undefined) setSetting('smtp_secure', secure ? 'true' : 'false');
  res.json({ success: true });
});

app.post('/api/admin/smtp/test', adminAuth, async (req, res) => {
  const to = req.body.to || req.body.email;
  if (!to) return res.status(400).json({ error: 'Recipient email required' });
  const transport = getSmtpTransport();
  if (!transport) return res.status(400).json({ error: 'SMTP not configured' });
  try {
    await transport.sendMail({
      from: getSetting('smtp_from') || getSetting('smtp_user'),
      to,
      subject: 'Dinner Roulette — SMTP Test',
      text: 'If you received this email, your SMTP configuration is working correctly!',
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: `Failed to send: ${e.message}` });
  }
});

app.get('/api/admin/vapid', adminAuth, (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC, hasPrivateKey: !!VAPID_PRIVATE, source: VAPID_SOURCE });
});

app.post('/api/admin/vapid/generate', adminAuth, (req, res) => {
  const keys = webpush.generateVAPIDKeys();
  setSetting('vapid_public_key', keys.publicKey);
  setSetting('vapid_private_key', keys.privateKey);
  VAPID_PUBLIC = keys.publicKey;
  VAPID_PRIVATE = keys.privateKey;
  VAPID_SOURCE = 'db';
  const email = getSetting('vapid_email') || process.env.VAPID_EMAIL || 'mailto:noreply@example.com';
  webpush.setVapidDetails(email, VAPID_PUBLIC, VAPID_PRIVATE);
  res.json({ publicKey: keys.publicKey });
});

app.get('/api/admin/google-api-key', adminAuth, (req, res) => {
  const key = API_KEY || '';
  const masked = key.length > 7 ? key.slice(0, 4) + '...' + key.slice(-3) : '(not set)';
  res.json({ key: masked, hasKey: !!key });
});

app.post('/api/admin/google-api-key', adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'API key is required' });
  setSetting('google_api_key', key);
  API_KEY = key;
  res.json({ success: true });
});

app.get('/api/admin/giphy-api-key', adminAuth, (req, res) => {
  const key = GIPHY_API_KEY || '';
  const masked = key.length > 7 ? key.slice(0, 4) + '...' + key.slice(-3) : '(not set)';
  res.json({ key: masked, hasKey: !!key });
});

app.post('/api/admin/giphy-api-key', adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'API key is required' });
  setSetting('giphy_api_key', key);
  GIPHY_API_KEY = key;
  res.json({ success: true });
});

app.get('/api/admin/settings', adminAuth, (req, res) => {
  res.json({
    jwt_expiry: getSetting('jwt_expiry') || '12h',
    cookie_secure: (getSetting('cookie_secure') || String(COOKIE_SECURE)) === 'true' ? 'true' : 'false',
  });
});

app.post('/api/admin/settings', adminAuth, (req, res) => {
  const { jwt_expiry, cookie_secure } = req.body;
  if (jwt_expiry !== undefined) setSetting('jwt_expiry', jwt_expiry);
  if (cookie_secure !== undefined) setSetting('cookie_secure', cookie_secure === 'true' ? 'true' : 'false');
  res.json({ success: true });
});

// ── Admin Plan Management ────────────────────────────────────────────────────────
app.get('/api/admin/plans', adminAuth, (req, res) => {
  const plans = db.prepare(`
    SELECT s.id, s.name, s.code, s.status, s.created_at, s.winner_place, s.picked_at,
           u.username as creator_name,
           (SELECT COUNT(*) FROM session_members WHERE session_id = s.id) as member_count,
           (SELECT COUNT(*) FROM session_suggestions WHERE session_id = s.id) as suggestion_count
    FROM sessions s
    LEFT JOIN users u ON s.creator_id = u.id
    ORDER BY s.created_at DESC
  `).all();
  res.json({ plans });
});

app.post('/api/admin/plans/:id/close', adminAuth, (req, res) => {
  const planId = req.params.id;
  const plan = db.prepare('SELECT * FROM sessions WHERE id = ?').get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  if (plan.status === 'closed') return res.status(400).json({ error: 'Plan is already closed' });
  db.prepare("UPDATE sessions SET status = 'closed' WHERE id = ?").run(planId);
  io.to(`plan:${planId}`).emit('plan:closed', { planId });
  res.json({ success: true });
});

app.delete('/api/admin/plans/:id', adminAuth, (req, res) => {
  const planId = req.params.id;
  const plan = db.prepare('SELECT * FROM sessions WHERE id = ?').get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  const deleteAll = db.transaction(() => {
    db.prepare('DELETE FROM session_messages WHERE session_id = ?').run(planId);
    db.prepare('DELETE FROM session_votes WHERE session_id = ?').run(planId);
    db.prepare('DELETE FROM session_suggestions WHERE session_id = ?').run(planId);
    db.prepare('DELETE FROM session_members WHERE session_id = ?').run(planId);
    db.prepare('DELETE FROM sessions WHERE id = ?').run(planId);
  });
  deleteAll();
  io.to(`plan:${planId}`).emit('plan:deleted', { planId: Number(planId) });
  res.json({ success: true });
});

// ── Places Routes ───────────────────────────────────────────────────────────────
app.get('/api/autocomplete', auth, async (req, res) => {
  try {
    const { input } = req.query;
    if (!input) return res.status(400).json({ error: 'Missing input' });
    const url = new URL('https://maps.googleapis.com/maps/api/place/autocomplete/json');
    url.searchParams.set('input', input);
    url.searchParams.set('types', 'establishment');
    url.searchParams.set('key', API_KEY);
    const r = await fetch(url);
    res.json(await r.json());
  } catch (e) {
    res.status(500).json({ error: 'Proxy error' });
  }
});

app.get('/api/place-details', auth, async (req, res) => {
  try {
    const { place_id } = req.query;
    if (!place_id) return res.status(400).json({ error: 'Missing place_id' });
    const url = new URL('https://maps.googleapis.com/maps/api/place/details/json');
    url.searchParams.set('place_id', place_id);
    url.searchParams.set('fields', 'geometry,name,formatted_address');
    url.searchParams.set('key', API_KEY);
    const r = await fetch(url);
    res.json(await r.json());
  } catch (e) {
    res.status(500).json({ error: 'Proxy error' });
  }
});

app.post('/api/place', auth, (req, res) => {
  const { place, place_id, restaurant_type } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  db.prepare('INSERT OR IGNORE INTO places (user_id, place, place_id, restaurant_type) VALUES (?, ?, ?, ?)').run(req.user.id, place, place_id || null, restaurant_type || null);
  res.json({ success: true });
});

app.get('/api/places', auth, (req, res) => {
  const uid = req.user.id;
  const likes = db.prepare('SELECT place, place_id, restaurant_type, visited_at, notes, starred FROM likes WHERE user_id = ?').all(uid);
  const dislikes = db.prepare('SELECT place, place_id, restaurant_type FROM dislikes WHERE user_id = ?').all(uid);
  const wantToTry = db.prepare('SELECT place, place_id, restaurant_type, starred FROM want_to_try WHERE user_id = ?').all(uid);
  const all = db.prepare('SELECT place, place_id, restaurant_type FROM places WHERE user_id = ?').all(uid);
  res.json({
    likes: likes.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type, visited_at: r.visited_at || null, notes: r.notes || null, starred: !!r.starred })),
    dislikes: dislikes.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type })),
    want_to_try: wantToTry.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type, starred: !!r.starred })),
    all: all.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type })),
  });
});

app.post('/api/places/:type/star', auth, (req, res) => {
  const { place } = req.body;
  const type = req.params.type;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  if (type !== 'likes' && type !== 'want_to_try') return res.status(400).json({ error: 'Invalid type' });
  const row = db.prepare(`SELECT starred FROM ${type} WHERE user_id = ? AND place = ?`).get(req.user.id, place);
  if (!row) return res.status(404).json({ error: 'Place not found in your list' });
  const newVal = row.starred ? 0 : 1;
  db.prepare(`UPDATE ${type} SET starred = ? WHERE user_id = ? AND place = ?`).run(newVal, req.user.id, place);
  res.json({ success: true, starred: !!newVal });
});

app.post('/api/places/notes', auth, (req, res) => {
  const { place, notes } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  const row = db.prepare('SELECT 1 FROM likes WHERE user_id = ? AND place = ?').get(req.user.id, place);
  if (!row) return res.status(404).json({ error: 'Place not in your likes' });
  db.prepare('UPDATE likes SET notes = ? WHERE user_id = ? AND place = ?').run(notes || null, req.user.id, place);
  res.json({ success: true });
});

app.post('/api/places', auth, (req, res) => {
  const { type, place, place_id, remove, restaurant_type } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  const uid = req.user.id;
  let movedFrom = null;

  if (remove) {
    if (type === 'likes') {
      db.prepare('DELETE FROM likes WHERE user_id = ? AND place = ?').run(uid, place);
    } else if (type === 'want_to_try') {
      db.prepare('DELETE FROM want_to_try WHERE user_id = ? AND place = ?').run(uid, place);
    } else {
      db.prepare('DELETE FROM dislikes WHERE user_id = ? AND place = ?').run(uid, place);
    }
  } else {
    db.prepare('INSERT OR IGNORE INTO places (user_id, place, place_id, restaurant_type) VALUES (?, ?, ?, ?)').run(uid, place, place_id || null, restaurant_type || null);
    if (type === 'likes') {
      const del = db.prepare('DELETE FROM dislikes WHERE user_id = ? AND place = ?').run(uid, place);
      if (del.changes > 0) movedFrom = 'dislikes';
      db.prepare('INSERT OR IGNORE INTO likes (user_id, place, place_id, restaurant_type) VALUES (?, ?, ?, ?)').run(uid, place, place_id || null, restaurant_type || null);
    } else if (type === 'want_to_try') {
      const del = db.prepare('DELETE FROM dislikes WHERE user_id = ? AND place = ?').run(uid, place);
      if (del.changes > 0) movedFrom = 'dislikes';
      db.prepare('INSERT OR IGNORE INTO want_to_try (user_id, place, place_id, restaurant_type) VALUES (?, ?, ?, ?)').run(uid, place, place_id || null, restaurant_type || null);
    } else {
      const del = db.prepare('DELETE FROM likes WHERE user_id = ? AND place = ?').run(uid, place);
      if (del.changes > 0) movedFrom = 'likes';
      db.prepare('INSERT OR IGNORE INTO dislikes (user_id, place, place_id, restaurant_type) VALUES (?, ?, ?, ?)').run(uid, place, place_id || null, restaurant_type || null);
    }
  }
  res.json({ success: true, movedFrom });
});

// ── Friends Routes ──────────────────────────────────────────────────────────────
app.post('/api/invite', auth, (req, res) => {
  const { friendUsername } = req.body;
  if (!friendUsername) return res.status(400).json({ error: 'Missing friend username' });
  const friend = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get(friendUsername.trim());
  if (!friend) return res.status(404).json({ error: 'User not found' });
  if (friend.id === req.user.id) return res.status(400).json({ error: 'Cannot add yourself' });

  // Check if request already exists in either direction
  const existing = db.prepare('SELECT status FROM friends WHERE user_id = ? AND friend_id = ?').get(req.user.id, friend.id);
  if (existing) return res.json({ success: true });

  // Check if the other user already sent a pending request to us — auto-accept both
  const reverse = db.prepare('SELECT status FROM friends WHERE user_id = ? AND friend_id = ?').get(friend.id, req.user.id);
  if (reverse && reverse.status === 'pending') {
    db.prepare("UPDATE friends SET status = 'accepted' WHERE user_id = ? AND friend_id = ?").run(friend.id, req.user.id);
    db.prepare("INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, 'accepted')").run(req.user.id, friend.id);
    return res.json({ success: true, autoAccepted: true });
  }

  db.prepare("INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, 'pending')").run(req.user.id, friend.id);
  sendPushToUser(friend.id, { title: 'Friend Request', body: `${req.user.username} sent you a friend request`, tag: 'friend-request' });
  res.json({ success: true });
});

app.get('/api/friend-requests', auth, (req, res) => {
  const requests = db.prepare(`
    SELECT u.id, u.username FROM friends f
    JOIN users u ON u.id = f.user_id
    WHERE f.friend_id = ? AND f.status = 'pending'
  `).all(req.user.id);
  res.json({ requests });
});

app.post('/api/friend-requests/:id/accept', auth, (req, res) => {
  const requesterId = req.params.id;
  const pending = db.prepare("SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'pending'").get(requesterId, req.user.id);
  if (!pending) return res.status(404).json({ error: 'No pending request from this user' });

  const accept = db.transaction(() => {
    db.prepare("UPDATE friends SET status = 'accepted' WHERE user_id = ? AND friend_id = ?").run(requesterId, req.user.id);
    db.prepare("INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, 'accepted')").run(req.user.id, requesterId);
  });
  accept();
  sendPushToUser(Number(requesterId), { title: 'Friend Accepted', body: `${req.user.username} accepted your friend request`, tag: 'friend-accept' });
  res.json({ success: true });
});

app.post('/api/friend-requests/:id/reject', auth, (req, res) => {
  const requesterId = req.params.id;
  db.prepare("DELETE FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'pending'").run(requesterId, req.user.id);
  res.json({ success: true });
});

app.get('/api/friends', auth, (req, res) => {
  const friends = db.prepare(`
    SELECT u.id, u.username FROM friends f
    JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ? AND f.status = 'accepted'
  `).all(req.user.id);
  res.json({ friends });
});

app.get('/api/friends/:id/likes', auth, (req, res) => {
  const friendId = req.params.id;
  const friendship = db.prepare("SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'accepted'").get(req.user.id, friendId);
  if (!friendship) return res.status(403).json({ error: 'Not friends with this user' });
  const likes = db.prepare('SELECT DISTINCT place, place_id, restaurant_type FROM likes WHERE user_id = ?').all(friendId);
  res.json({ likes: likes.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type })) });
});

app.delete('/api/friends/:id', auth, (req, res) => {
  const friendId = Number(req.params.id);
  const friendship = db.prepare("SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'accepted'").get(req.user.id, friendId);
  if (!friendship) return res.status(404).json({ error: 'Friendship not found' });
  const removeBoth = db.transaction(() => {
    db.prepare('DELETE FROM friends WHERE user_id = ? AND friend_id = ?').run(req.user.id, friendId);
    db.prepare('DELETE FROM friends WHERE user_id = ? AND friend_id = ?').run(friendId, req.user.id);
  });
  removeBoth();
  res.json({ success: true });
});

app.get('/api/common-places', auth, (req, res) => {
  const friendUsername = req.query.friendUsername;
  if (!friendUsername) return res.status(400).json({ error: 'Missing friendUsername' });
  const friend = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get(friendUsername.trim());
  if (!friend) return res.status(404).json({ error: 'User not found' });
  const friendship = db.prepare("SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'accepted'").get(req.user.id, friend.id);
  if (!friendship) return res.status(403).json({ error: 'Not friends with this user' });
  const common = db.prepare(`
    SELECT DISTINCT l1.place FROM likes l1
    JOIN likes l2 ON l2.place = l1.place
    WHERE l1.user_id = ? AND l2.user_id = ?
  `).all(req.user.id, friend.id);
  res.json({ common: common.map(r => r.place) });
});

// ── Push Notification Routes ──────────────────────────────────────────────────
app.get('/api/push/vapid-key', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC });
});

app.post('/api/push/subscribe', auth, (req, res) => {
  const { endpoint, keys } = req.body;
  if (!endpoint || !keys?.p256dh || !keys?.auth) {
    return res.status(400).json({ error: 'Invalid subscription data' });
  }
  db.prepare(`
    INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth
  `).run(req.user.id, endpoint, keys.p256dh, keys.auth);
  res.json({ success: true });
});

app.delete('/api/push/subscribe', auth, (req, res) => {
  const { endpoint } = req.body;
  if (!endpoint) return res.status(400).json({ error: 'Missing endpoint' });
  db.prepare('DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?').run(req.user.id, endpoint);
  res.json({ success: true });
});

// ── Suggestions Routes ──────────────────────────────────────────────────────────
app.get('/api/suggestions/recent', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT DISTINCT ss.place, ss.place_id, ss.restaurant_type
    FROM session_suggestions ss
    WHERE ss.user_id = ?
    ORDER BY ss.id DESC
    LIMIT 5
  `).all(req.user.id);
  res.json({ recent: rows.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type })) });
});

// ── Plan Routes ──────────────────────────────────────────────────────────────
app.post('/api/plans', auth, (req, res) => {
  const { name } = req.body;
  const code = generatePlanCode();
  try {
    const result = db.prepare('INSERT INTO sessions (code, creator_id, name) VALUES (?, ?, ?)').run(code, req.user.id, name || 'Dinner Plan');
    const planId = result.lastInsertRowid;
    db.prepare('INSERT INTO session_members (session_id, user_id) VALUES (?, ?)').run(planId, req.user.id);
    res.json({ id: planId, code, name: name || 'Dinner Plan' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create plan' });
  }
});

app.post('/api/plans/join', auth, (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Missing code' });
  const plan = db.prepare("SELECT * FROM sessions WHERE code = ? AND status = 'open'").get(code.toUpperCase());
  if (!plan) return res.status(404).json({ error: 'Plan not found or closed' });
  db.prepare('INSERT OR IGNORE INTO session_members (session_id, user_id) VALUES (?, ?)').run(plan.id, req.user.id);
  io.to(`plan:${plan.id}`).emit('plan:member-joined', { username: req.user.username, userId: req.user.id });
  sendPushToPlanMembers(plan.id, { title: 'Member Joined', body: `${req.user.username} joined ${plan.name}`, tag: `plan-${plan.id}` }, req.user.id);
  res.json({ id: plan.id, code: plan.code, name: plan.name });
});

app.post('/api/plans/:id/invite', auth, (req, res) => {
  const planId = req.params.id;
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Missing username' });
  const plan = db.prepare("SELECT * FROM sessions WHERE id = ? AND status = 'open'").get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found or closed' });
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });
  const target = db.prepare('SELECT id, username FROM users WHERE LOWER(username) = LOWER(?)').get(username.trim());
  if (!target) return res.status(404).json({ error: 'User not found' });
  const alreadyMember = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, target.id);
  if (alreadyMember) return res.json({ success: true, alreadyMember: true });
  db.prepare('INSERT OR IGNORE INTO session_members (session_id, user_id) VALUES (?, ?)').run(planId, target.id);
  io.to(`plan:${planId}`).emit('plan:member-joined', { username: target.username, userId: target.id });
  sendPushToUser(target.id, { title: 'Plan Invite', body: `You've been invited to ${plan.name}`, tag: `plan-invite-${planId}` });
  res.json({ success: true });
});

app.get('/api/plans/:id/dislikes', auth, (req, res) => {
  const planId = req.params.id;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });
  const dislikes = db.prepare(`
    SELECT DISTINCT d.place FROM dislikes d
    JOIN session_members sm ON sm.user_id = d.user_id
    WHERE sm.session_id = ?
  `).all(planId);
  res.json({ dislikes: dislikes.map(r => r.place) });
});

app.get('/api/plans', auth, (req, res) => {
  const plans = db.prepare(`
    SELECT s.id, s.code, s.name, s.status, s.winner_place, s.picked_at, s.created_at, s.creator_id, s.voting_deadline,
           u.username AS creator_username,
           (SELECT COUNT(*) FROM session_members WHERE session_id = s.id) AS member_count,
           (SELECT COUNT(*) FROM session_suggestions WHERE session_id = s.id) AS suggestion_count
    FROM sessions s
    JOIN session_members sm ON sm.session_id = s.id
    JOIN users u ON u.id = s.creator_id
    WHERE sm.user_id = ?
    ORDER BY s.created_at DESC
  `).all(req.user.id);
  res.json({ plans });
});

app.get('/api/plans/:id', auth, (req, res) => {
  const planId = req.params.id;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });

  const plan = db.prepare('SELECT * FROM sessions WHERE id = ?').get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });

  const members = db.prepare(`
    SELECT u.id, u.username FROM session_members sm
    JOIN users u ON u.id = sm.user_id
    WHERE sm.session_id = ?
  `).all(planId);

  const suggestions = db.prepare(`
    SELECT ss.id, ss.place, ss.place_id, ss.restaurant_type, ss.lat, ss.lng, ss.price_level, ss.user_id,
           u.username AS suggested_by,
           (SELECT COUNT(*) FROM session_votes sv WHERE sv.suggestion_id = ss.id AND sv.vote_type = 'up') AS vote_count,
           (SELECT COUNT(*) FROM session_votes sv WHERE sv.suggestion_id = ss.id AND sv.vote_type = 'down') AS downvote_count
    FROM session_suggestions ss
    JOIN users u ON u.id = ss.user_id
    WHERE ss.session_id = ?
  `).all(planId);

  const userVotes = db.prepare('SELECT suggestion_id, vote_type FROM session_votes WHERE session_id = ? AND user_id = ?').all(planId, req.user.id);
  const votedIds = new Set(userVotes.filter(v => v.vote_type === 'up').map(v => v.suggestion_id));
  const downvotedIds = new Set(userVotes.filter(v => v.vote_type === 'down').map(v => v.suggestion_id));

  // Fetch voters for each suggestion
  const allVotes = db.prepare(`
    SELECT sv.suggestion_id, sv.vote_type, u.username
    FROM session_votes sv
    JOIN users u ON u.id = sv.user_id
    WHERE sv.session_id = ?
  `).all(planId);
  const votersMap = {};
  const downvotersMap = {};
  allVotes.forEach(v => {
    if (v.vote_type === 'up') {
      if (!votersMap[v.suggestion_id]) votersMap[v.suggestion_id] = [];
      votersMap[v.suggestion_id].push(v.username);
    } else {
      if (!downvotersMap[v.suggestion_id]) downvotersMap[v.suggestion_id] = [];
      downvotersMap[v.suggestion_id].push(v.username);
    }
  });

  // Find which session suggestions are on members' want-to-try lists
  const memberIds = members.map(m => m.id);
  const wantToTryMap = {};
  if (memberIds.length > 0 && suggestions.length > 0) {
    const placeholders = memberIds.map(() => '?').join(',');
    const wantToTryRows = db.prepare(`
      SELECT wt.place, wt.user_id, u.username
      FROM want_to_try wt
      JOIN users u ON u.id = wt.user_id
      WHERE wt.user_id IN (${placeholders})
        AND wt.place IN (SELECT place FROM session_suggestions WHERE session_id = ?)
    `).all(...memberIds, planId);
    wantToTryRows.forEach(row => {
      if (!wantToTryMap[row.place]) wantToTryMap[row.place] = [];
      wantToTryMap[row.place].push({ user_id: row.user_id, username: row.username });
    });
  }

  res.json({
    plan,
    members,
    suggestions: suggestions.map(s => ({ ...s, user_voted: votedIds.has(s.id), user_downvoted: downvotedIds.has(s.id), voters: votersMap[s.id] || [], downvoters: downvotersMap[s.id] || [] })),
    want_to_try: wantToTryMap,
  });
});

app.post('/api/plans/:id/suggest', auth, async (req, res) => {
  const planId = req.params.id;
  const { place, place_id, restaurant_type } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const plan = db.prepare("SELECT status, name FROM sessions WHERE id = ?").get(planId);
  if (!plan || plan.status !== 'open') return res.status(400).json({ error: 'Plan is closed' });

  let lat = null, lng = null, priceLevel = null;
  if (place_id) {
    try {
      const url = new URL('https://maps.googleapis.com/maps/api/place/details/json');
      url.searchParams.set('place_id', place_id);
      url.searchParams.set('fields', 'geometry,price_level');
      url.searchParams.set('key', API_KEY);
      const r = await fetch(url);
      const data = await r.json();
      if (data.result?.geometry?.location) {
        lat = data.result.geometry.location.lat;
        lng = data.result.geometry.location.lng;
      }
      if (data.result?.price_level != null) {
        priceLevel = data.result.price_level;
      }
    } catch (e) {
      console.error('Failed to fetch place details:', e.message);
    }
  }

  try {
    const result = db.prepare('INSERT OR IGNORE INTO session_suggestions (session_id, user_id, place, place_id, restaurant_type, lat, lng, price_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(planId, req.user.id, place, place_id || null, restaurant_type || null, lat, lng, priceLevel);
    if (result.changes === 0) return res.status(409).json({ error: 'Already suggested' });
    io.to(`plan:${planId}`).emit('plan:suggestion-added', {
      id: result.lastInsertRowid, place, place_id: place_id || null,
      restaurant_type: restaurant_type || null,
      lat, lng, price_level: priceLevel, suggested_by: req.user.username, vote_count: 0, user_voted: false,
    });
    sendPushToPlanMembers(planId, { title: 'New Suggestion', body: `${req.user.username} suggested ${place}`, tag: `plan-${planId}` }, req.user.id);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (err) {
    res.status(500).json({ error: 'Failed to suggest' });
  }
});

app.delete('/api/plans/:id/suggestion/:suggestionId', auth, (req, res) => {
  const planId = req.params.id;
  const suggestionId = req.params.suggestionId;

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const plan = db.prepare("SELECT status FROM sessions WHERE id = ?").get(planId);
  if (!plan || plan.status !== 'open') return res.status(400).json({ error: 'Plan is closed' });

  const suggestion = db.prepare('SELECT id, user_id FROM session_suggestions WHERE id = ? AND session_id = ?').get(suggestionId, planId);
  if (!suggestion) return res.status(404).json({ error: 'Suggestion not found' });
  if (suggestion.user_id !== req.user.id) return res.status(403).json({ error: 'You can only remove your own suggestions' });

  db.prepare('DELETE FROM session_votes WHERE suggestion_id = ?').run(suggestionId);
  db.prepare('DELETE FROM session_suggestions WHERE id = ?').run(suggestionId);

  io.to(`plan:${planId}`).emit('plan:suggestion-removed', { suggestion_id: Number(suggestionId) });
  res.json({ success: true });
});

app.post('/api/plans/:id/vote', auth, (req, res) => {
  const planId = req.params.id;
  const { suggestion_id } = req.body;
  if (!suggestion_id) return res.status(400).json({ error: 'Missing suggestion_id' });

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  db.prepare('DELETE FROM session_votes WHERE session_id = ? AND user_id = ? AND suggestion_id = ?').run(planId, req.user.id, suggestion_id);
  db.prepare("INSERT INTO session_votes (session_id, user_id, suggestion_id, vote_type) VALUES (?, ?, ?, 'up')").run(planId, req.user.id, suggestion_id);
  const voteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'up'").get(suggestion_id).c;
  const downvoteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'down'").get(suggestion_id).c;
  io.to(`plan:${planId}`).emit('plan:vote-updated', { suggestion_id, vote_count: voteCount, downvote_count: downvoteCount, user_id: req.user.id, username: req.user.username, action: 'vote' });
  res.json({ success: true });
});

app.post('/api/plans/:id/unvote', auth, (req, res) => {
  const planId = req.params.id;
  const { suggestion_id } = req.body;
  if (!suggestion_id) return res.status(400).json({ error: 'Missing suggestion_id' });

  db.prepare("DELETE FROM session_votes WHERE session_id = ? AND user_id = ? AND suggestion_id = ? AND vote_type = 'up'").run(planId, req.user.id, suggestion_id);
  const voteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'up'").get(suggestion_id).c;
  const downvoteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'down'").get(suggestion_id).c;
  io.to(`plan:${planId}`).emit('plan:vote-updated', { suggestion_id, vote_count: voteCount, downvote_count: downvoteCount, user_id: req.user.id, username: req.user.username, action: 'unvote' });
  res.json({ success: true });
});

app.post('/api/plans/:id/downvote', auth, (req, res) => {
  const planId = req.params.id;
  const { suggestion_id } = req.body;
  if (!suggestion_id) return res.status(400).json({ error: 'Missing suggestion_id' });

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  db.prepare('DELETE FROM session_votes WHERE session_id = ? AND user_id = ? AND suggestion_id = ?').run(planId, req.user.id, suggestion_id);
  db.prepare("INSERT INTO session_votes (session_id, user_id, suggestion_id, vote_type) VALUES (?, ?, ?, 'down')").run(planId, req.user.id, suggestion_id);
  const voteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'up'").get(suggestion_id).c;
  const downvoteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'down'").get(suggestion_id).c;
  io.to(`plan:${planId}`).emit('plan:vote-updated', { suggestion_id, vote_count: voteCount, downvote_count: downvoteCount, user_id: req.user.id, username: req.user.username, action: 'downvote' });
  res.json({ success: true });
});

app.post('/api/plans/:id/undownvote', auth, (req, res) => {
  const planId = req.params.id;
  const { suggestion_id } = req.body;
  if (!suggestion_id) return res.status(400).json({ error: 'Missing suggestion_id' });

  db.prepare("DELETE FROM session_votes WHERE session_id = ? AND user_id = ? AND suggestion_id = ? AND vote_type = 'down'").run(planId, req.user.id, suggestion_id);
  const voteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'up'").get(suggestion_id).c;
  const downvoteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'down'").get(suggestion_id).c;
  io.to(`plan:${planId}`).emit('plan:vote-updated', { suggestion_id, vote_count: voteCount, downvote_count: downvoteCount, user_id: req.user.id, username: req.user.username, action: 'undownvote' });
  res.json({ success: true });
});

app.post('/api/plans/:id/pick', auth, (req, res) => {
  const planId = req.params.id;
  const { mode, lat, lng } = req.body;

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const suggestions = db.prepare(`
    SELECT ss.id, ss.place, ss.place_id, ss.lat, ss.lng,
           (SELECT COUNT(*) FROM session_votes sv WHERE sv.suggestion_id = ss.id AND sv.vote_type = 'up') AS vote_count,
           (SELECT COUNT(*) FROM session_votes sv WHERE sv.suggestion_id = ss.id AND sv.vote_type = 'down') AS downvote_count
    FROM session_suggestions ss
    WHERE ss.session_id = ?
  `).all(planId);

  if (suggestions.length === 0) return res.status(400).json({ error: 'No suggestions yet' });

  let winner;

  if (mode === 'closest') {
    if (lat == null || lng == null) return res.status(400).json({ error: 'Location required for closest pick' });
    const withCoords = suggestions.filter(s => s.lat != null && s.lng != null);
    if (withCoords.length === 0) return res.status(400).json({ error: 'No suggestions have location data' });
    withCoords.forEach(s => { s.distance = haversine(lat, lng, s.lat, s.lng); });
    withCoords.sort((a, b) => a.distance - b.distance);
    winner = withCoords[0];
  } else {
    // Get want-to-try counts for weight boost (+1 per member who wants to try)
    const wantToTryCounts = {};
    const wttRows = db.prepare(`
      SELECT ss.place, COUNT(*) as cnt FROM want_to_try wt
      JOIN session_suggestions ss ON ss.place = wt.place AND ss.session_id = ?
      JOIN session_members sm ON sm.user_id = wt.user_id AND sm.session_id = ?
      WHERE ss.session_id = ?
      GROUP BY ss.place
    `).all(planId, planId, planId);
    wttRows.forEach(r => { wantToTryCounts[r.place] = r.cnt; });

    const weighted = [];
    suggestions.forEach(s => {
      const weight = Math.max(s.vote_count - s.downvote_count, 1) + (wantToTryCounts[s.place] || 0);
      for (let i = 0; i < weight; i++) weighted.push(s);
    });
    winner = weighted[Math.floor(Math.random() * weighted.length)];
  }

  db.prepare('UPDATE sessions SET winner_place = ?, picked_at = datetime(?) WHERE id = ?').run(winner.place, 'now', planId);
  io.to(`plan:${planId}`).emit('plan:winner-picked', { winner });
  sendPushToPlanMembers(planId, { title: 'Winner!', body: `${winner.place} was picked!`, tag: `plan-${planId}-winner` }, req.user.id);
  res.json({ winner });
});

app.post('/api/plans/:id/close', auth, (req, res) => {
  const planId = req.params.id;
  const { winner_place } = req.body || {};
  const plan = db.prepare('SELECT * FROM sessions WHERE id = ?').get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  if (plan.creator_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can close this plan' });

  if (winner_place) {
    db.prepare("UPDATE sessions SET status = 'closed', winner_place = ?, picked_at = datetime('now') WHERE id = ?").run(winner_place, planId);
    io.to(`plan:${planId}`).emit('plan:winner-picked', { winner: { place: winner_place } });
    sendPushToPlanMembers(planId, { title: 'Winner!', body: `${winner_place} was picked in ${plan.name}!`, tag: `plan-${planId}-winner` }, req.user.id);
  } else {
    db.prepare("UPDATE sessions SET status = 'closed' WHERE id = ?").run(planId);
  }
  io.to(`plan:${planId}`).emit('plan:closed', { planId });
  sendPushToPlanMembers(planId, { title: 'Plan Closed', body: `${plan.name} has been closed`, tag: `plan-${planId}` }, req.user.id);
  res.json({ success: true });
});

app.delete('/api/plans/:id', auth, (req, res) => {
  const planId = req.params.id;
  const plan = db.prepare('SELECT * FROM sessions WHERE id = ?').get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  if (plan.creator_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can delete this plan' });
  if (plan.status !== 'closed') return res.status(400).json({ error: 'Plan must be closed before deleting' });

  const deleteAll = db.transaction(() => {
    db.prepare('DELETE FROM message_reactions WHERE message_id IN (SELECT id FROM session_messages WHERE session_id = ?)').run(planId);
    db.prepare('DELETE FROM session_messages WHERE session_id = ?').run(planId);
    db.prepare('DELETE FROM session_votes WHERE session_id = ?').run(planId);
    db.prepare('DELETE FROM session_suggestions WHERE session_id = ?').run(planId);
    db.prepare('DELETE FROM session_members WHERE session_id = ?').run(planId);
    db.prepare('DELETE FROM sessions WHERE id = ?').run(planId);
  });
  deleteAll();

  io.to(`plan:${planId}`).emit('plan:deleted', { planId: Number(planId) });
  res.json({ success: true });
});

// ── Voting Deadline ──────────────────────────────────────────────────────────────
app.post('/api/plans/:id/deadline', auth, (req, res) => {
  const planId = req.params.id;
  const plan = db.prepare('SELECT * FROM sessions WHERE id = ?').get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  if (plan.creator_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can set a deadline' });

  const { deadline } = req.body;
  db.prepare('UPDATE sessions SET voting_deadline = ? WHERE id = ?').run(deadline || null, planId);
  io.to(`plan:${planId}`).emit('plan:deadline-updated', { planId: Number(planId), deadline: deadline || null });
  res.json({ success: true });
});

// ── Plan Chat ─────────────────────────────────────────────────────────────────
app.get('/api/plans/:id/messages', auth, (req, res) => {
  const planId = req.params.id;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });

  const messages = db.prepare(`
    SELECT sm.id, sm.message, sm.message_type, sm.created_at, sm.user_id, u.username
    FROM session_messages sm
    JOIN users u ON u.id = sm.user_id
    WHERE sm.session_id = ?
    ORDER BY sm.created_at ASC
    LIMIT 100
  `).all(planId);

  const messageIds = messages.map(m => m.id);
  const reactionsMap = {};
  if (messageIds.length > 0) {
    const placeholders = messageIds.map(() => '?').join(',');
    const reactions = db.prepare(`
      SELECT mr.message_id, mr.emoji, mr.user_id, u.username
      FROM message_reactions mr
      JOIN users u ON u.id = mr.user_id
      WHERE mr.message_id IN (${placeholders})
    `).all(...messageIds);
    reactions.forEach(r => {
      if (!reactionsMap[r.message_id]) reactionsMap[r.message_id] = [];
      reactionsMap[r.message_id].push({ emoji: r.emoji, user_id: r.user_id, username: r.username });
    });
  }

  const enriched = messages.map(m => ({
    ...m,
    message_type: m.message_type || 'text',
    reactions: reactionsMap[m.id] || []
  }));
  res.json({ messages: enriched });
});

app.post('/api/plans/:id/messages', auth, (req, res) => {
  const planId = req.params.id;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });

  const { message, message_type } = req.body;
  const type = message_type === 'gif' ? 'gif' : 'text';

  if (type === 'gif') {
    if (!message || !/^https:\/\/media\d*\.giphy\.com\//.test(message)) return res.status(400).json({ error: 'Invalid GIF URL' });
    if (message.length > 1000) return res.status(400).json({ error: 'URL too long' });
  } else {
    if (!message || !message.trim()) return res.status(400).json({ error: 'Message cannot be empty' });
    if (message.length > 500) return res.status(400).json({ error: 'Message too long (max 500 characters)' });
  }

  const content = type === 'text' ? message.trim() : message;
  const result = db.prepare('INSERT INTO session_messages (session_id, user_id, message, message_type) VALUES (?, ?, ?, ?)').run(planId, req.user.id, content, type);
  const username = db.prepare('SELECT username FROM users WHERE id = ?').get(req.user.id).username;

  const msg = { id: result.lastInsertRowid, message: content, message_type: type, user_id: req.user.id, username, created_at: new Date().toISOString(), reactions: [] };
  io.to(`plan:${planId}`).emit('plan:message', msg);
  res.json({ message: msg });
});

// ── Message Reactions ────────────────────────────────────────────────────────
app.post('/api/plans/:id/messages/:messageId/react', auth, (req, res) => {
  const planId = req.params.id;
  const messageId = req.params.messageId;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });

  const { emoji } = req.body;
  if (!emoji || emoji.length > 8) return res.status(400).json({ error: 'Invalid emoji' });

  const msg = db.prepare('SELECT id FROM session_messages WHERE id = ? AND session_id = ?').get(messageId, planId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });

  db.prepare('INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)').run(messageId, req.user.id, emoji);

  const reactions = db.prepare(`
    SELECT mr.emoji, mr.user_id, u.username
    FROM message_reactions mr JOIN users u ON u.id = mr.user_id
    WHERE mr.message_id = ?
  `).all(messageId);

  io.to(`plan:${planId}`).emit('plan:reaction-updated', { message_id: Number(messageId), reactions });
  res.json({ success: true });
});

app.delete('/api/plans/:id/messages/:messageId/react', auth, (req, res) => {
  const planId = req.params.id;
  const messageId = req.params.messageId;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });

  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: 'Missing emoji' });

  db.prepare('DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?').run(messageId, req.user.id, emoji);

  const reactions = db.prepare(`
    SELECT mr.emoji, mr.user_id, u.username
    FROM message_reactions mr JOIN users u ON u.id = mr.user_id
    WHERE mr.message_id = ?
  `).all(messageId);

  io.to(`plan:${planId}`).emit('plan:reaction-updated', { message_id: Number(messageId), reactions });
  res.json({ success: true });
});

// ── Giphy GIF Proxy ──────────────────────────────────────────────────────────
let GIPHY_API_KEY = getSetting('giphy_api_key') || process.env.GIPHY_API_KEY;

app.get('/api/giphy/search', auth, async (req, res) => {
  if (!GIPHY_API_KEY) return res.status(400).json({ error: 'Giphy API not configured' });
  const { q, offset } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing search query' });

  try {
    const url = new URL('https://api.giphy.com/v1/gifs/search');
    url.searchParams.set('api_key', GIPHY_API_KEY);
    url.searchParams.set('q', q);
    url.searchParams.set('limit', '20');
    url.searchParams.set('rating', 'g');
    if (offset) url.searchParams.set('offset', offset);

    const r = await fetch(url);
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Giphy API error' });
  }
});

app.get('/api/giphy/trending', auth, async (req, res) => {
  if (!GIPHY_API_KEY) return res.status(400).json({ error: 'Giphy API not configured' });

  try {
    const url = new URL('https://api.giphy.com/v1/gifs/trending');
    url.searchParams.set('api_key', GIPHY_API_KEY);
    url.searchParams.set('limit', '20');
    url.searchParams.set('rating', 'g');

    const r = await fetch(url);
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Giphy API error' });
  }
});

// ── Config Routes ────────────────────────────────────────────────────────────────
app.get('/api/config/maps-key', auth, (req, res) => {
  res.json({ key: API_KEY });
});

// ── SPA Fallback ────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start Server ────────────────────────────────────────────────────────────────
const server = http.createServer(app);

// ── Socket.IO ───────────────────────────────────────────────────────────────────
const io = new Server(server, {
  cors: { origin: false },
});

// Authenticate socket connections via the auth cookie
io.use((socket, next) => {
  try {
    const raw = socket.handshake.headers.cookie || '';
    const match = raw.match(/(?:^|;\s*)token=([^;]*)/);
    if (!match) return next(new Error('Not authenticated'));
    const decoded = jwt.verify(match[1], JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (err) {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  socket.on('join-plan', (planId) => {
    const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, socket.user.id);
    if (membership) {
      socket.join(`plan:${planId}`);
    }
  });

  socket.on('leave-plan', (planId) => {
    socket.leave(`plan:${planId}`);
  });
});

if (require.main === module) {
  server.listen(PORT, () => console.log(`Server listening on ${PORT}`));
}

// ── Graceful Shutdown ───────────────────────────────────────────────────────────
function shutdown() {
  console.log('Shutting down gracefully...');
  io.close();
  server.close(() => {
    db.close();
    console.log('Server closed.');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 5000);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = { app, server, io, db, haversine, generatePlanCode, getSetting, setSetting, encryptSetting, decryptSetting };
