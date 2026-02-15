const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
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

// ── Infrastructure (env-only) ─────────────────────────────────────────────────
const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 8080;

// App config vars — initialized after DB is ready (see initConfig below)
let API_KEY, JWT_SECRET, VAPID_PUBLIC, VAPID_PRIVATE, COOKIE_SECURE;

console.log(`Environment: ${NODE_ENV}`);
console.log(`Port: ${PORT}`);

// ── Express App & Middleware ────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);

// Generate CSP nonce per request
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-eval'",
        (req, res) => `'nonce-${res.locals.cspNonce}'`,
        "'strict-dynamic'",
        "https://cdn.jsdelivr.net",
        "https://cdn.socket.io",
        "https://maps.googleapis.com",
      ],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "blob:", "https://maps.gstatic.com", "https://maps.googleapis.com", "https://*.ggpht.com", "https://*.googleusercontent.com", "https://*.giphy.com", "https://media.giphy.com", "https://media0.giphy.com", "https://media1.giphy.com", "https://media2.giphy.com", "https://media3.giphy.com", "https://media4.giphy.com", "https://i.giphy.com"],
      connectSrc: ["'self'", "ws:", "wss:", "https://maps.googleapis.com", "https://places.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      upgradeInsecureRequests: null,
    }
  },
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
}));
app.use(compression());
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
// Serve .well-known explicitly before denying other dotfiles
app.use('/.well-known', express.static(path.join(__dirname, 'public', '.well-known')));
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  index: false,
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('CDN-Cache-Control', 'no-store');
  }
}));

// Rate limiting (disabled in test mode)
if (NODE_ENV === 'test') console.warn('WARNING: Rate limiting is disabled (NODE_ENV=test)');
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

// CSRF protection: verify Origin header on state-changing requests
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.headers.origin || req.headers.referer;
  if (origin) {
    try {
      const url = new URL(origin);
      if (url.host !== req.headers.host) {
        return res.status(403).json({ error: 'Cross-origin request blocked' });
      }
    } catch (e) {
      return res.status(403).json({ error: 'Invalid origin' });
    }
  }
  next();
});

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
  CREATE TABLE IF NOT EXISTS session_vetoes (
    session_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    suggestion_id INTEGER NOT NULL,
    UNIQUE(session_id, user_id, suggestion_id)
  );
  CREATE TABLE IF NOT EXISTS friend_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    creator_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS friend_group_members (
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    UNIQUE(group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES friend_groups(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS recurring_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    creator_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    frequency TEXT NOT NULL DEFAULT 'weekly',
    member_ids TEXT NOT NULL DEFAULT '[]',
    veto_limit INTEGER DEFAULT 0,
    next_occurrence TEXT NOT NULL,
    paused INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS message_reads (
    session_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    last_read_message_id INTEGER NOT NULL DEFAULT 0,
    read_at TEXT DEFAULT (datetime('now')),
    UNIQUE(session_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    lat REAL NOT NULL,
    lng REAL NOT NULL,
    radius_km REAL NOT NULL DEFAULT 25,
    is_default INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, name)
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
try { db.exec("ALTER TABLE sessions ADD COLUMN veto_limit INTEGER DEFAULT 1"); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE likes ADD COLUMN address TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE dislikes ADD COLUMN address TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE want_to_try ADD COLUMN address TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE places ADD COLUMN address TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN accent_color TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE likes ADD COLUMN meal_types TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE want_to_try ADD COLUMN meal_types TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE likes ADD COLUMN photo_ref TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE dislikes ADD COLUMN photo_ref TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE want_to_try ADD COLUMN photo_ref TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE places ADD COLUMN photo_ref TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE session_suggestions ADD COLUMN photo_ref TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE sessions ADD COLUMN meal_type TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE session_suggestions ADD COLUMN meal_types TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN display_name TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE users ADD COLUMN profile_pic TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE session_messages ADD COLUMN edited_at TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE sessions ADD COLUMN dietary_tags TEXT'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE likes ADD COLUMN lat REAL'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE likes ADD COLUMN lng REAL'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE dislikes ADD COLUMN lat REAL'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE dislikes ADD COLUMN lng REAL'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE want_to_try ADD COLUMN lat REAL'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE want_to_try ADD COLUMN lng REAL'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE places ADD COLUMN lat REAL'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE places ADD COLUMN lng REAL'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE likes ADD COLUMN zone_id INTEGER'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE dislikes ADD COLUMN zone_id INTEGER'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE want_to_try ADD COLUMN zone_id INTEGER'); } catch (e) { /* already exists */ }
try { db.exec('ALTER TABLE places ADD COLUMN zone_id INTEGER'); } catch (e) { /* already exists */ }

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

// ── App Config Initialization (DB → env → auto-generate) ────────────────────
function initConfig() {
  // JWT_SECRET
  JWT_SECRET = getSetting('jwt_secret');
  if (!JWT_SECRET && process.env.JWT_SECRET) {
    if (process.env.JWT_SECRET.length < 32) {
      console.warn('WARNING: JWT_SECRET from environment is too weak (< 32 chars) — generating a secure secret instead.');
    } else {
      JWT_SECRET = process.env.JWT_SECRET;
      setSetting('jwt_secret', JWT_SECRET);
    }
  }
  if (!JWT_SECRET) {
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    setSetting('jwt_secret', JWT_SECRET);
    console.log('Generated and saved new JWT secret to database.');
  }

  // GOOGLE_API_KEY
  API_KEY = getSetting('google_api_key');
  if (!API_KEY && process.env.GOOGLE_API_KEY) {
    API_KEY = process.env.GOOGLE_API_KEY;
    setSetting('google_api_key', API_KEY);
  }
  if (!API_KEY) {
    console.warn('WARNING: Google API key not set — configure via admin panel.');
  }

  // VAPID keys
  const dbPub = getSetting('vapid_public_key');
  const dbPriv = getSetting('vapid_private_key');
  if (dbPub && dbPriv) {
    VAPID_PUBLIC = dbPub;
    VAPID_PRIVATE = dbPriv;
  } else if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY;
    VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY;
    setSetting('vapid_public_key', VAPID_PUBLIC);
    setSetting('vapid_private_key', VAPID_PRIVATE);
  } else {
    const keys = webpush.generateVAPIDKeys();
    VAPID_PUBLIC = keys.publicKey;
    VAPID_PRIVATE = keys.privateKey;
    setSetting('vapid_public_key', VAPID_PUBLIC);
    setSetting('vapid_private_key', VAPID_PRIVATE);
    console.log('Generated and saved new VAPID keys to database.');
  }
  let vapidEmail = getSetting('vapid_email');
  if (!vapidEmail && process.env.VAPID_EMAIL) {
    vapidEmail = process.env.VAPID_EMAIL;
    setSetting('vapid_email', vapidEmail);
  }
  webpush.setVapidDetails(vapidEmail || 'mailto:noreply@example.com', VAPID_PUBLIC, VAPID_PRIVATE);

  // COOKIE_SECURE
  const dbCookieSecure = getSetting('cookie_secure');
  if (dbCookieSecure !== null) {
    COOKIE_SECURE = dbCookieSecure === 'true';
  } else if (process.env.COOKIE_SECURE) {
    COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
    setSetting('cookie_secure', COOKIE_SECURE ? 'true' : 'false');
  } else {
    COOKIE_SECURE = false;
  }
}
initConfig();

// ── Admin Initialization ─────────────────────────────────────────────────────
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
if (ADMIN_USERNAME) {
  const adminUser = db.prepare('SELECT id, is_admin FROM users WHERE LOWER(username) = LOWER(?)').get(ADMIN_USERNAME);
  if (adminUser && !adminUser.is_admin) {
    db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(adminUser.id);
    console.log(`Admin privilege granted to user: ${ADMIN_USERNAME}`);
  } else if (!adminUser) {
    console.log(`ADMIN_USERNAME '${ADMIN_USERNAME}' not found — will be granted admin on registration`);
  }
}
// If no admin exists, make the first registered user admin
const adminExists = db.prepare('SELECT 1 FROM users WHERE is_admin = 1').get();
if (!adminExists) {
  const firstUser = db.prepare('SELECT id FROM users ORDER BY id ASC LIMIT 1').get();
  if (firstUser) {
    db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(firstUser.id);
  }
}

// ── Security Constants ───────────────────────────────────────────────────────
const BCRYPT_ROUNDS = 12;
const ALLOWED_TABLES = new Set(['likes', 'dislikes', 'want_to_try', 'places', 'suggestions', 'session_suggestions']);
function assertTable(name) {
  if (!ALLOWED_TABLES.has(name)) throw new Error(`Invalid table: ${name}`);
}

// ── Helpers ─────────────────────────────────────────────────────────────────────
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username, is_admin: !!user.is_admin }, JWT_SECRET, { expiresIn: getSetting('jwt_expiry') || '12h' });
}

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
  for (let attempt = 0; attempt < 10; attempt++) {
    let code = '';
    for (let i = 0; i < 6; i++) code += chars[crypto.randomInt(chars.length)];
    if (!db.prepare('SELECT 1 FROM sessions WHERE code = ?').get(code)) return code;
  }
  throw new Error('Failed to generate unique plan code');
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
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (!trimmedEmail) return res.status(400).json({ error: 'Email is required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) return res.status(400).json({ error: 'Invalid email format' });

  try {
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
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
  const user = db.prepare('SELECT id, username, email, is_admin, accent_color, display_name, profile_pic FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, email: user.email || null, is_admin: !!user.is_admin, accent_color: user.accent_color || null, display_name: user.display_name || null, profile_pic: user.profile_pic || null });
});

app.post('/api/accent-color', auth, (req, res) => {
  const { accentColor } = req.body;
  const allowed = ['coral', 'ocean', 'forest', 'royal', 'amber', 'rose', 'slate', 'lavender'];
  if (accentColor && !allowed.includes(accentColor)) {
    return res.status(400).json({ error: 'Invalid accent color' });
  }
  db.prepare('UPDATE users SET accent_color = ? WHERE id = ?').run(accentColor || null, req.user.id);
  res.json({ success: true });
});

app.post('/api/profile', auth, express.json({ limit: '500kb' }), (req, res) => {
  const { displayName, profilePic } = req.body;
  if (displayName !== undefined) {
    if (typeof displayName === 'string' && displayName.trim().length > 50) {
      return res.status(400).json({ error: 'Display name must be 50 characters or less' });
    }
    db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName ? displayName.trim() : null, req.user.id);
  }
  if (profilePic !== undefined) {
    if (profilePic !== null && (typeof profilePic !== 'string' || !profilePic.startsWith('data:image/'))) {
      return res.status(400).json({ error: 'Invalid profile picture format' });
    }
    if (profilePic && profilePic.length > 266000) {
      return res.status(400).json({ error: 'Profile picture too large (max 200KB)' });
    }
    db.prepare('UPDATE users SET profile_pic = ? WHERE id = ?').run(profilePic || null, req.user.id);
  }
  const user = db.prepare('SELECT display_name, profile_pic FROM users WHERE id = ?').get(req.user.id);

  // Broadcast profile update to friends and plan co-members
  const profileUpdate = { userId: req.user.id, username: req.user.username, display_name: user.display_name || null, profile_pic: user.profile_pic || null };
  const friendIds = db.prepare(`
    SELECT friend_id AS id FROM friends WHERE user_id = ? AND status = 'accepted'
    UNION
    SELECT user_id AS id FROM friends WHERE friend_id = ? AND status = 'accepted'
  `).all(req.user.id, req.user.id).map(r => r.id);
  const coMemberIds = db.prepare(`
    SELECT DISTINCT sm2.user_id AS id FROM session_members sm1
    JOIN session_members sm2 ON sm2.session_id = sm1.session_id AND sm2.user_id != sm1.user_id
    JOIN sessions s ON s.id = sm1.session_id AND s.status = 'open'
    WHERE sm1.user_id = ?
  `).all(req.user.id).map(r => r.id);
  const notifyIds = [...new Set([...friendIds, ...coMemberIds])];
  for (const id of notifyIds) {
    io.to(`user:${id}`).emit('user:profile-updated', profileUpdate);
  }

  res.json({ success: true, display_name: user.display_name || null, profile_pic: user.profile_pic || null });
});

// ── Stats ────────────────────────────────────────────────────────────────────────
app.get('/api/stats', auth, (req, res) => {
  const uid = req.user.id;

  // Total unique restaurants visited (winners from closed plans the user was in)
  const restaurantsVisited = db.prepare(`
    SELECT COUNT(DISTINCT s.winner_place) AS c FROM sessions s
    JOIN session_members sm ON sm.session_id = s.id
    WHERE sm.user_id = ? AND s.status = 'closed' AND s.winner_place IS NOT NULL
  `).get(uid).c;

  // Plans joined
  const plansJoined = db.prepare('SELECT COUNT(*) AS c FROM session_members WHERE user_id = ?').get(uid).c;

  // Plans created
  const plansCreated = db.prepare('SELECT COUNT(*) AS c FROM sessions WHERE creator_id = ?').get(uid).c;

  // Suggestion win rate
  const totalSuggested = db.prepare(`
    SELECT COUNT(*) AS c FROM session_suggestions WHERE user_id = ?
  `).get(uid).c;
  const suggestionsWon = db.prepare(`
    SELECT COUNT(*) AS c FROM session_suggestions ss
    JOIN sessions s ON s.id = ss.session_id
    WHERE ss.user_id = ? AND s.status = 'closed' AND s.winner_place = ss.place
  `).get(uid).c;
  const winRate = totalSuggested > 0 ? Math.round((suggestionsWon / totalSuggested) * 100) : 0;

  // Top 5 cuisine types
  const topCuisines = db.prepare(`
    SELECT restaurant_type AS type, COUNT(*) AS count FROM (
      SELECT restaurant_type FROM likes WHERE user_id = ? AND restaurant_type IS NOT NULL
      UNION ALL
      SELECT winner_place AS restaurant_type FROM (
        SELECT ss.restaurant_type AS winner_place FROM sessions s
        JOIN session_suggestions ss ON ss.session_id = s.id AND ss.place = s.winner_place
        JOIN session_members sm ON sm.session_id = s.id
        WHERE sm.user_id = ? AND s.status = 'closed' AND ss.restaurant_type IS NOT NULL
      )
    ) GROUP BY restaurant_type ORDER BY count DESC LIMIT 5
  `).all(uid, uid);

  // Top 5 dining companions
  const topCompanions = db.prepare(`
    SELECT u.username, u.display_name, u.profile_pic, COUNT(DISTINCT sm2.session_id) AS count
    FROM session_members sm1
    JOIN session_members sm2 ON sm2.session_id = sm1.session_id AND sm2.user_id != sm1.user_id
    JOIN users u ON u.id = sm2.user_id
    WHERE sm1.user_id = ?
    GROUP BY sm2.user_id ORDER BY count DESC LIMIT 5
  `).all(uid);

  // Voting patterns
  const upvotes = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE user_id = ? AND vote_type = 'up'").get(uid).c;
  const downvotes = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE user_id = ? AND vote_type = 'down'").get(uid).c;
  const vetoes = db.prepare('SELECT COUNT(*) AS c FROM session_vetoes WHERE user_id = ?').get(uid).c;

  // Places counts
  const likesCount = db.prepare('SELECT COUNT(*) AS c FROM likes WHERE user_id = ?').get(uid).c;
  const dislikesCount = db.prepare('SELECT COUNT(*) AS c FROM dislikes WHERE user_id = ?').get(uid).c;
  const wantToTryCount = db.prepare('SELECT COUNT(*) AS c FROM want_to_try WHERE user_id = ?').get(uid).c;

  // Monthly activity (last 12 months)
  const monthlyActivity = db.prepare(`
    SELECT strftime('%Y-%m', s.created_at) AS month,
           COUNT(DISTINCT s.id) AS plans_count,
           COUNT(DISTINCT CASE WHEN s.winner_place IS NOT NULL THEN s.winner_place END) AS restaurants_visited
    FROM session_members sm
    JOIN sessions s ON s.id = sm.session_id
    WHERE sm.user_id = ? AND s.created_at >= datetime('now', '-12 months')
    GROUP BY month ORDER BY month
  `).all(uid);

  // Adventure score (unique cuisine types tried / total available)
  const uniqueCuisines = db.prepare('SELECT COUNT(DISTINCT restaurant_type) AS c FROM likes WHERE user_id = ? AND restaurant_type IS NOT NULL').get(uid).c;
  const totalCuisines = db.prepare('SELECT COUNT(DISTINCT restaurant_type) AS c FROM likes WHERE restaurant_type IS NOT NULL').get().c || 1;
  const adventureScore = Math.round((uniqueCuisines / totalCuisines) * 100);

  // Average group size
  const avgGroupSize = db.prepare(`
    SELECT ROUND(AVG(cnt), 1) AS avg FROM (
      SELECT COUNT(*) AS cnt FROM session_members sm
      JOIN sessions s ON s.id = sm.session_id
      JOIN session_members sm2 ON sm2.session_id = s.id AND sm2.user_id = ?
      GROUP BY sm.session_id
    )
  `).get(uid)?.avg || 0;

  res.json({
    restaurantsVisited, plansJoined, plansCreated, totalSuggested, suggestionsWon, winRate,
    topCuisines, topCompanions,
    upvotes, downvotes, vetoes,
    likesCount, dislikesCount, wantToTryCount,
    monthlyActivity, adventureScore, avgGroupSize,
  });
});

// ── Badges ───────────────────────────────────────────────────────────────────────
function computeBadges(userId) {
  const completedPlans = db.prepare(`
    SELECT COUNT(*) AS c FROM session_members sm
    JOIN sessions s ON s.id = sm.session_id
    WHERE sm.user_id = ? AND s.status = 'closed' AND s.winner_place IS NOT NULL
  `).get(userId).c;

  const suggestionsWon = db.prepare(`
    SELECT COUNT(*) AS c FROM session_suggestions ss
    JOIN sessions s ON s.id = ss.session_id
    WHERE ss.user_id = ? AND s.status = 'closed' AND s.winner_place = ss.place
  `).get(userId).c;

  const wantToTryCount = db.prepare('SELECT COUNT(*) AS c FROM want_to_try WHERE user_id = ?').get(userId).c;

  const cuisineTypes = db.prepare('SELECT COUNT(DISTINCT restaurant_type) AS c FROM likes WHERE user_id = ? AND restaurant_type IS NOT NULL').get(userId).c;

  const friendCount = db.prepare(`
    SELECT COUNT(*) AS c FROM friends WHERE (user_id = ? OR friend_id = ?) AND status = 'accepted'
  `).get(userId, userId).c;

  const vetoCount = db.prepare('SELECT COUNT(*) AS c FROM session_vetoes WHERE user_id = ?').get(userId).c;

  const starredCount = db.prepare(`
    SELECT COUNT(*) AS c FROM (
      SELECT 1 FROM likes WHERE user_id = ? AND starred = 1
      UNION ALL SELECT 1 FROM want_to_try WHERE user_id = ? AND starred = 1
    )
  `).get(userId, userId).c;

  const dislikeCount = db.prepare('SELECT COUNT(*) AS c FROM dislikes WHERE user_id = ?').get(userId).c;

  const uniqueRestaurants = db.prepare(`
    SELECT COUNT(DISTINCT s.winner_place) AS c FROM sessions s
    JOIN session_members sm ON sm.session_id = s.id
    WHERE sm.user_id = ? AND s.status = 'closed' AND s.winner_place IS NOT NULL
  `).get(userId).c;

  const plansCreated = db.prepare('SELECT COUNT(*) AS c FROM sessions WHERE creator_id = ?').get(userId).c;

  // Early Bird: first to suggest in plans
  const earlyBirdCount = db.prepare(`
    SELECT COUNT(*) AS c FROM (
      SELECT ss.session_id FROM session_suggestions ss
      WHERE ss.user_id = ?
      AND ss.id = (SELECT MIN(id) FROM session_suggestions WHERE session_id = ss.session_id)
    )
  `).get(userId).c;

  // Streak: consecutive weeks with activity
  const weekRows = db.prepare(`
    SELECT DISTINCT strftime('%Y-%W', s.created_at) AS wk FROM sessions s
    JOIN session_members sm ON sm.session_id = s.id
    WHERE sm.user_id = ? ORDER BY wk DESC
  `).all(userId);
  let streak = 0, maxStreak = 0;
  for (let i = 0; i < weekRows.length; i++) {
    if (i === 0) { streak = 1; maxStreak = 1; continue; }
    const [py, pw] = weekRows[i - 1].wk.split('-').map(Number);
    const [cy, cw] = weekRows[i].wk.split('-').map(Number);
    if ((py === cy && pw - cw === 1) || (py - cy === 1 && pw === 0 && cw >= 51)) {
      streak++;
      maxStreak = Math.max(maxStreak, streak);
    } else {
      streak = 1;
    }
  }

  const badges = [
    { id: 'first_bite', icon: '🍽️', name: 'First Bite', desc: 'Complete your first plan', target: 1, current: completedPlans },
    { id: 'regular', icon: '🔄', name: 'Regular', desc: 'Complete 5 plans', target: 5, current: completedPlans },
    { id: 'foodie', icon: '👨‍🍳', name: 'Foodie', desc: 'Complete 25 plans', target: 25, current: completedPlans },
    { id: 'trendsetter', icon: '🏆', name: 'Trendsetter', desc: 'Win 3 suggestion picks', target: 3, current: suggestionsWon },
    { id: 'crowd_pleaser', icon: '🎯', name: 'Crowd Pleaser', desc: 'Win 10 suggestion picks', target: 10, current: suggestionsWon },
    { id: 'explorer', icon: '🗺️', name: 'Explorer', desc: 'Add 10 want-to-try places', target: 10, current: wantToTryCount },
    { id: 'globetrotter', icon: '🌎', name: 'Globetrotter', desc: 'Like 5 different cuisine types', target: 5, current: cuisineTypes },
    { id: 'social_butterfly', icon: '🦋', name: 'Social Butterfly', desc: 'Make 5 friends', target: 5, current: friendCount },
    { id: 'veto_king', icon: '🚫', name: 'Veto King', desc: 'Use 10 vetoes', target: 10, current: vetoCount },
    { id: 'loyal_fan', icon: '⭐', name: 'Loyal Fan', desc: 'Star 5 places', target: 5, current: starredCount },
    { id: 'critic', icon: '👎', name: 'Critic', desc: 'Dislike 10 places', target: 10, current: dislikeCount },
    { id: 'adventurer', icon: '🧭', name: 'Adventurer', desc: 'Visit 10 unique restaurants', target: 10, current: uniqueRestaurants },
    { id: 'plan_master', icon: '📋', name: 'Plan Master', desc: 'Create 10 plans', target: 10, current: plansCreated },
    { id: 'early_bird', icon: '🐦', name: 'Early Bird', desc: 'Be first to suggest in 5 plans', target: 5, current: earlyBirdCount },
    { id: 'streak', icon: '🔥', name: 'On Fire', desc: '3 consecutive active weeks', target: 3, current: maxStreak },
  ];

  return badges.map(b => ({ ...b, earned: b.current >= b.target }));
}

app.get('/api/badges', auth, (req, res) => {
  res.json(computeBadges(req.user.id));
});

app.get('/api/badges/:userId', auth, (req, res) => {
  const targetId = parseInt(req.params.userId);
  // Only allow viewing friends' badges
  const isFriend = db.prepare(`
    SELECT 1 FROM friends WHERE ((user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)) AND status = 'accepted'
  `).get(req.user.id, targetId, targetId, req.user.id);
  if (!isFriend) return res.status(403).json({ error: 'Not friends' });
  res.json(computeBadges(targetId));
});

// ── Friend Leaderboard ──────────────────────────────────────────────────────
app.get('/api/friends/leaderboard', auth, (req, res) => {
  const uid = req.user.id;
  const friendIds = db.prepare(`
    SELECT friend_id AS id FROM friends WHERE user_id = ? AND status = 'accepted'
    UNION
    SELECT user_id AS id FROM friends WHERE friend_id = ? AND status = 'accepted'
  `).all(uid, uid).map(r => r.id);
  friendIds.push(uid); // Include self

  const leaderboard = friendIds.map(fid => {
    const user = db.prepare('SELECT id, username, display_name, profile_pic FROM users WHERE id = ?').get(fid);
    if (!user) return null;
    const plans = db.prepare('SELECT COUNT(*) AS c FROM session_members WHERE user_id = ?').get(fid).c;
    const totalSuggested = db.prepare('SELECT COUNT(*) AS c FROM session_suggestions WHERE user_id = ?').get(fid).c;
    const suggestionsWon = db.prepare(`
      SELECT COUNT(*) AS c FROM session_suggestions ss
      JOIN sessions s ON s.id = ss.session_id
      WHERE ss.user_id = ? AND s.status = 'closed' AND s.winner_place = ss.place
    `).get(fid).c;
    const winRate = totalSuggested > 0 ? Math.round((suggestionsWon / totalSuggested) * 100) : 0;
    const restaurantsVisited = db.prepare(`
      SELECT COUNT(DISTINCT s.winner_place) AS c FROM sessions s
      JOIN session_members sm ON sm.session_id = s.id
      WHERE sm.user_id = ? AND s.status = 'closed' AND s.winner_place IS NOT NULL
    `).get(fid).c;
    return { ...user, plans, winRate, suggestionsWon, restaurantsVisited, is_self: fid === uid };
  }).filter(Boolean);

  res.json(leaderboard);
});

// ── Activity Feed ───────────────────────────────────────────────────────────
app.get('/api/activity', auth, (req, res) => {
  const uid = req.user.id;
  const friendIds = db.prepare(`
    SELECT friend_id AS id FROM friends WHERE user_id = ? AND status = 'accepted'
    UNION
    SELECT user_id AS id FROM friends WHERE friend_id = ? AND status = 'accepted'
  `).all(uid, uid).map(r => r.id);
  if (friendIds.length === 0) return res.json([]);

  const placeholders = friendIds.map(() => '?').join(',');
  const activities = [];

  // Recent likes by friends (last 7 days)
  const recentLikes = db.prepare(`
    SELECT l.place, l.restaurant_type, l.created_at, u.username, u.display_name, u.profile_pic, u.id AS user_id
    FROM likes l JOIN users u ON u.id = l.user_id
    WHERE l.user_id IN (${placeholders}) AND l.created_at >= datetime('now', '-7 days')
    ORDER BY l.created_at DESC LIMIT 20
  `).all(...friendIds);
  recentLikes.forEach(l => activities.push({ type: 'like', ...l }));

  // Plans created/closed by friends (last 7 days)
  const recentPlans = db.prepare(`
    SELECT s.name, s.status, s.winner_place, s.created_at, s.picked_at, u.username, u.display_name, u.profile_pic, u.id AS user_id
    FROM sessions s JOIN users u ON u.id = s.creator_id
    WHERE s.creator_id IN (${placeholders}) AND s.created_at >= datetime('now', '-7 days')
    ORDER BY s.created_at DESC LIMIT 20
  `).all(...friendIds);
  recentPlans.forEach(p => activities.push({ type: p.status === 'closed' ? 'plan_closed' : 'plan_created', ...p }));

  // Sort by date and limit
  activities.sort((a, b) => {
    const da = a.picked_at || a.created_at || '';
    const db2 = b.picked_at || b.created_at || '';
    return db2.localeCompare(da);
  });

  res.json(activities.slice(0, 50));
});

app.post('/api/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const valid = await bcrypt.compare(currentPassword, user.password);
  if (!valid) return res.status(401).json({ error: 'Incorrect current password' });

  const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, req.user.id);
  res.json({ success: true });
});

// ── Data Export ──────────────────────────────────────────────────────────────
app.get('/api/account/export', auth, (req, res) => {
  try {
  const uid = req.user.id;
  const user = db.prepare('SELECT username, email, display_name, accent_color, created_at FROM users WHERE id = ?').get(uid);
  const likes = db.prepare('SELECT place, place_id, restaurant_type, address, visited_at, notes, starred, meal_types FROM likes WHERE user_id = ?').all(uid);
  const dislikes = db.prepare('SELECT place, place_id, restaurant_type, address FROM dislikes WHERE user_id = ?').all(uid);
  const wantToTry = db.prepare('SELECT place, place_id, restaurant_type, address, starred, meal_types FROM want_to_try WHERE user_id = ?').all(uid);
  const friends = db.prepare(`
    SELECT u.username, u.display_name, f.status
    FROM friends f JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ? AND f.status = 'accepted'
  `).all(uid);
  const plansCreated = db.prepare('SELECT id, name, code, status, winner_place, meal_type, dietary_tags, created_at, picked_at FROM sessions WHERE creator_id = ?').all(uid);
  const plansJoined = db.prepare(`
    SELECT s.id, s.name, s.status, s.winner_place, s.meal_type, s.created_at, s.picked_at
    FROM session_members sm JOIN sessions s ON s.id = sm.session_id
    WHERE sm.user_id = ? AND s.creator_id != ?
  `).all(uid, uid);
  const messages = db.prepare(`
    SELECT sm.message, sm.message_type, sm.created_at, s.name AS plan_name
    FROM session_messages sm JOIN sessions s ON s.id = sm.session_id
    WHERE sm.user_id = ?
  `).all(uid);
  const suggestions = db.prepare(`
    SELECT ss.place, s.name AS plan_name, ss.restaurant_type
    FROM session_suggestions ss JOIN sessions s ON s.id = ss.session_id
    WHERE ss.user_id = ?
  `).all(uid);

  const exportData = {
    export_date: new Date().toISOString(),
    user: { username: user.username, email: user.email, display_name: user.display_name, accent_color: user.accent_color, account_created: user.created_at },
    places: { likes, dislikes, want_to_try: wantToTry },
    social: { friends },
    plans: { created: plansCreated, participated: plansJoined },
    activity: { messages_sent: messages, suggestions_made: suggestions }
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="dinner-roulette-export-${Date.now()}.json"`);
  res.json(exportData);
  } catch (e) { console.error('Export error:', e.message); res.status(500).json({ error: 'Export failed: ' + e.message }); }
});

// ── Calendar Export ──────────────────────────────────────────────────────────
app.get('/api/plans/:id/calendar', auth, (req, res) => {
  const planId = req.params.id;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });
  const plan = db.prepare('SELECT * FROM sessions WHERE id = ?').get(planId);
  if (!plan || !plan.winner_place) return res.status(400).json({ error: 'Plan has no winner yet' });

  const winnerLike = db.prepare('SELECT place, address FROM likes WHERE place = ? LIMIT 1').get(plan.winner_place);
  const winnerAddress = winnerLike?.address || null;

  const dt = plan.picked_at ? new Date(plan.picked_at + (plan.picked_at.includes('Z') ? '' : 'Z')) : new Date();
  const fmt = (d) => d.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const endDt = new Date(dt.getTime() + 2 * 60 * 60 * 1000); // 2 hours

  const ics = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Dinner Roulette//EN',
    'BEGIN:VEVENT',
    `DTSTART:${fmt(dt)}`,
    `DTEND:${fmt(endDt)}`,
    `SUMMARY:${plan.name} - ${plan.winner_place}`,
    winnerAddress ? `LOCATION:${winnerAddress}` : '',
    `DESCRIPTION:Winner picked via Dinner Roulette`,
    `UID:dinner-roulette-${plan.id}@app`,
    'END:VEVENT',
    'END:VCALENDAR'
  ].filter(Boolean).join('\r\n');

  res.setHeader('Content-Type', 'text/calendar');
  res.setHeader('Content-Disposition', `attachment; filename="dinner-${plan.code}.ics"`);
  res.send(ics);
});

app.post('/api/delete-account', authLimiter, auth, async (req, res) => {
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
    db.prepare('DELETE FROM zones WHERE user_id = ?').run(uid);
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
  if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const row = db.prepare(`
    SELECT user_id FROM password_reset_tokens
    WHERE token = ? AND used = 0 AND expires_at > datetime('now')
  `).get(token);
  if (!row) return res.status(400).json({ error: 'Invalid or expired reset link' });

  const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
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
  res.json({ users, plans, active_plans, places, smtp_configured, vapid_source: 'db' });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const users = db.prepare('SELECT id, username, email, is_admin, created_at, display_name, profile_pic FROM users ORDER BY id ASC').all();
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
  console.log(`[ADMIN] ${req.user.username} — edited user #${targetId} (${target.username})`);
  res.json({ success: true });
});

app.post('/api/admin/users/:id/reset-password', adminAuth, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, target.id);
  console.log(`[ADMIN] ${req.user.username} — reset password for user #${target.id}`);
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
    db.prepare('DELETE FROM zones WHERE user_id = ?').run(targetId);
    db.prepare('DELETE FROM users WHERE id = ?').run(targetId);
  });
  deleteAll();
  console.log(`[ADMIN] ${req.user.username} — deleted user #${targetId}`);
  res.json({ success: true });
});

app.post('/api/admin/users/:id/toggle-admin', adminAuth, (req, res) => {
  const targetId = Number(req.params.id);
  if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot modify your own admin status' });
  const target = db.prepare('SELECT id, is_admin FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const newStatus = target.is_admin ? 0 : 1;
  db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(newStatus, targetId);
  console.log(`[ADMIN] ${req.user.username} — ${newStatus ? 'granted' : 'revoked'} admin for user #${targetId}`);
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
  console.log(`[ADMIN] ${req.user.username} — updated SMTP settings`);
  res.json({ success: true });
});

app.post('/api/admin/smtp/test', adminAuth, async (req, res) => {
  const to = (req.body.to || req.body.email || '').trim();
  if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return res.status(400).json({ error: 'Valid recipient email required' });
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
  res.json({ publicKey: VAPID_PUBLIC, hasPrivateKey: !!VAPID_PRIVATE, source: 'db' });
});

app.post('/api/admin/vapid/generate', adminAuth, (req, res) => {
  const keys = webpush.generateVAPIDKeys();
  setSetting('vapid_public_key', keys.publicKey);
  setSetting('vapid_private_key', keys.privateKey);
  VAPID_PUBLIC = keys.publicKey;
  VAPID_PRIVATE = keys.privateKey;
  const email = getSetting('vapid_email') || 'mailto:noreply@example.com';
  webpush.setVapidDetails(email, VAPID_PUBLIC, VAPID_PRIVATE);
  console.log(`[ADMIN] ${req.user.username} — regenerated VAPID keys`);
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
  console.log(`[ADMIN] ${req.user.username} — updated Google API key`);
  res.json({ success: true });
});

// One-time migration: repull place data from new Places API
app.post('/api/admin/repull-places', adminAuth, async (req, res) => {
  if (!API_KEY) return res.status(400).json({ error: 'Google API key not configured' });
  const tables = ['likes', 'dislikes', 'want_to_try', 'places', 'session_suggestions'];
  let updated = 0, failed = 0, total = 0;
  const seen = new Set();

  for (const table of tables) {
    assertTable(table);
    const rows = db.prepare(`SELECT DISTINCT place_id FROM ${table} WHERE place_id IS NOT NULL AND place_id != ''`).all();
    for (const row of rows) {
      if (seen.has(row.place_id)) continue;
      seen.add(row.place_id);
      total++;
      try {
        const r = await fetch(`https://places.googleapis.com/v1/places/${row.place_id}`, {
          headers: {
            'X-Goog-Api-Key': API_KEY,
            'X-Goog-FieldMask': 'id,displayName,formattedAddress,types,photos',
          },
        });
        const data = await r.json();
        if (data.error) { failed++; continue; }
        const placeName = data.displayName?.text || null;
        const photoRef = data.photos?.[0]?.name || null;
        const address = data.formattedAddress || null;
        const types = (data.types || []).map(t => t.toLowerCase());
        const restaurantType = formatPlaceTypes(types);
        // Update all tables that have this place_id
        for (const t of tables) {
          assertTable(t);
          db.prepare(`UPDATE ${t} SET photo_ref = ? WHERE place_id = ?`).run(photoRef, row.place_id);
          if (placeName) db.prepare(`UPDATE ${t} SET place = ? WHERE place_id = ?`).run(placeName, row.place_id);
          if (['likes', 'dislikes', 'want_to_try', 'places'].includes(t)) {
            db.prepare(`UPDATE ${t} SET address = ? WHERE place_id = ? AND (address IS NULL OR address = '')`).run(address, row.place_id);
            db.prepare(`UPDATE ${t} SET restaurant_type = ? WHERE place_id = ?`).run(restaurantType, row.place_id);
          }
        }
        updated++;
        // Rate limit: ~5 req/sec to stay well within quota
        await new Promise(resolve => setTimeout(resolve, 200));
      } catch (e) {
        console.error(`Repull failed for ${row.place_id}:`, e.message);
        failed++;
      }
    }
  }
  console.log(`Repull complete: ${updated}/${total} updated, ${failed} failed`);
  res.json({ success: true, total, updated, failed });
});

// Helper for repull: format place types to human-readable
function formatPlaceTypes(types) {
  const typeMap = {
    'restaurant': 'Restaurant', 'cafe': 'Cafe', 'bar': 'Bar', 'bakery': 'Bakery',
    'meal_takeaway': 'Takeaway', 'meal_delivery': 'Delivery', 'night_club': 'Night Club',
    'food': 'Food', 'pizza_restaurant': 'Pizza', 'sushi_restaurant': 'Sushi',
    'chinese_restaurant': 'Chinese', 'japanese_restaurant': 'Japanese',
    'mexican_restaurant': 'Mexican', 'italian_restaurant': 'Italian',
    'thai_restaurant': 'Thai', 'indian_restaurant': 'Indian',
    'korean_restaurant': 'Korean', 'vietnamese_restaurant': 'Vietnamese',
    'american_restaurant': 'American', 'seafood_restaurant': 'Seafood',
    'steak_house': 'Steakhouse', 'hamburger_restaurant': 'Burgers',
    'ice_cream_shop': 'Ice Cream', 'coffee_shop': 'Coffee Shop',
    'brunch_restaurant': 'Brunch', 'breakfast_restaurant': 'Breakfast',
    'sandwich_shop': 'Sandwich Shop', 'fast_food_restaurant': 'Fast Food',
    'vegetarian_restaurant': 'Vegetarian', 'vegan_restaurant': 'Vegan',
  };
  for (const t of types) {
    if (typeMap[t] && t !== 'restaurant' && t !== 'food') return typeMap[t];
  }
  for (const t of types) {
    if (typeMap[t]) return typeMap[t];
  }
  return null;
}

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
  console.log(`[ADMIN] ${req.user.username} — updated Giphy API key`);
  res.json({ success: true });
});

app.get('/api/admin/settings', adminAuth, (req, res) => {
  res.json({
    jwt_expiry: getSetting('jwt_expiry') || '12h',
    cookie_secure: getSetting('cookie_secure') === 'true' ? 'true' : 'false',
  });
});

app.post('/api/admin/settings', adminAuth, (req, res) => {
  const { jwt_expiry, cookie_secure } = req.body;
  if (jwt_expiry !== undefined) setSetting('jwt_expiry', jwt_expiry);
  if (cookie_secure !== undefined) setSetting('cookie_secure', cookie_secure === 'true' ? 'true' : 'false');
  console.log(`[ADMIN] ${req.user.username} — updated app settings`);
  res.json({ success: true });
});

// ── Admin Plan Management ────────────────────────────────────────────────────────
app.get('/api/admin/plans', adminAuth, (req, res) => {
  const plans = db.prepare(`
    SELECT s.id, s.name, s.code, s.status, s.created_at, s.winner_place, s.picked_at,
           u.username as creator_name, u.display_name as creator_display_name,
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
  console.log(`[ADMIN] ${req.user.username} — closed plan #${planId} (${plan.name})`);
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
  console.log(`[ADMIN] ${req.user.username} — deleted plan #${planId} (${plan.name})`);
  res.json({ success: true });
});

// ── Admin Backup ─────────────────────────────────────────────────────────────────
app.post('/api/admin/backup', adminAuth, async (req, res) => {
  try {
    const backupDir = path.join(path.dirname(DB_PATH), 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFile = path.join(backupDir, `db-backup-${timestamp}.sqlite`);
    await db.backup(backupFile);
    // Rotate: keep last 7 backups
    const files = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('db-backup-') && f.endsWith('.sqlite'))
      .sort()
      .reverse();
    for (const old of files.slice(7)) {
      fs.unlinkSync(path.join(backupDir, old));
    }
    console.log(`[ADMIN] ${req.user.username} — created backup: ${path.basename(backupFile)}`);
    res.json({ success: true, file: path.basename(backupFile), count: Math.min(files.length, 7) });
  } catch (e) {
    console.error('Backup failed:', e);
    res.status(500).json({ error: 'Backup failed' });
  }
});

// ── Places Routes ───────────────────────────────────────────────────────────────
app.get('/api/autocomplete', auth, async (req, res) => {
  if (!API_KEY) return res.status(400).json({ error: 'Google API key not configured' });
  try {
    const { input } = req.query;
    if (!input) return res.status(400).json({ error: 'Missing input' });
    const r = await fetch('https://places.googleapis.com/v1/places:autocomplete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Goog-Api-Key': API_KEY },
      body: JSON.stringify({ input, includedPrimaryTypes: ['restaurant', 'cafe', 'bar', 'bakery', 'meal_takeaway'] }),
    });
    const data = await r.json();
    if (data.error) {
      console.error('Places API error:', data.error.message || JSON.stringify(data.error));
      return res.status(data.error.code || 500).json({ error: data.error.message });
    }
    // Transform new API response to match legacy format the frontend expects
    const predictions = (data.suggestions || [])
      .filter(s => s.placePrediction)
      .map(s => {
        const p = s.placePrediction;
        return {
          place_id: p.placeId,
          description: p.text?.text || '',
          structured_formatting: {
            main_text: p.structuredFormat?.mainText?.text || '',
            secondary_text: p.structuredFormat?.secondaryText?.text || '',
          },
          types: (p.types || []).map(t => t.toLowerCase()),
        };
      });
    res.json({ predictions, status: predictions.length ? 'OK' : 'ZERO_RESULTS' });
  } catch (e) {
    console.error('Autocomplete proxy error:', e.message);
    res.status(500).json({ error: 'Proxy error' });
  }
});

app.get('/api/place-details', auth, async (req, res) => {
  if (!API_KEY) return res.status(400).json({ error: 'Google API key not configured' });
  try {
    const { place_id } = req.query;
    if (!place_id) return res.status(400).json({ error: 'Missing place_id' });
    const r = await fetch(`https://places.googleapis.com/v1/places/${place_id}`, {
      headers: {
        'X-Goog-Api-Key': API_KEY,
        'X-Goog-FieldMask': 'id,displayName,formattedAddress,types,photos,location',
      },
    });
    const data = await r.json();
    if (data.error) {
      console.error('Place details API error:', data.error.message || JSON.stringify(data.error));
      return res.status(data.error.code || 500).json({ error: data.error.message });
    }
    // Transform to legacy format the frontend expects
    const result = {
      types: (data.types || []).map(t => t.toLowerCase()),
      geometry: data.location ? { location: { lat: data.location.latitude, lng: data.location.longitude } } : undefined,
      name: data.displayName?.text,
      formatted_address: data.formattedAddress,
    };
    if (data.photos?.[0]?.name) {
      result.photo_reference = data.photos[0].name;
    }
    res.json({ result, status: 'OK' });
  } catch (e) {
    console.error('Place details proxy error:', e.message);
    res.status(500).json({ error: 'Proxy error' });
  }
});

// ── Explore Nearby ──────────────────────────────────────────────────────────
app.get('/api/places/nearby', auth, async (req, res) => {
  if (!API_KEY) return res.status(400).json({ error: 'Google API key not configured' });
  const { lat, lng } = req.query;
  if (!lat || !lng) return res.status(400).json({ error: 'Missing lat/lng' });
  try {
    const r = await fetch('https://places.googleapis.com/v1/places:searchNearby', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Goog-Api-Key': API_KEY, 'X-Goog-FieldMask': 'places.id,places.displayName,places.formattedAddress,places.types,places.rating,places.priceLevel,places.photos,places.location' },
      body: JSON.stringify({
        includedPrimaryTypes: ['restaurant', 'cafe', 'bar', 'bakery', 'meal_takeaway'],
        maxResultCount: 20,
        locationRestriction: { circle: { center: { latitude: parseFloat(lat), longitude: parseFloat(lng) }, radius: 2000.0 } }
      }),
    });
    const data = await r.json();
    if (data.error) return res.status(data.error.code || 500).json({ error: data.error.message });
    const places = (data.places || []).map(p => ({
      place_id: p.id,
      name: p.displayName?.text || '',
      address: p.formattedAddress || '',
      types: (p.types || []).map(t => t.toLowerCase()),
      rating: p.rating,
      price_level: p.priceLevel ? ['FREE', 'INEXPENSIVE', 'MODERATE', 'EXPENSIVE', 'VERY_EXPENSIVE'].indexOf(p.priceLevel) : null,
      photo_ref: p.photos?.[0]?.name || null,
      lat: p.location?.latitude,
      lng: p.location?.longitude,
    }));
    res.json({ places });
  } catch (e) {
    console.error('Nearby search error:', e.message);
    res.status(500).json({ error: 'Proxy error' });
  }
});

app.get('/api/place-photo', auth, async (req, res) => {
  if (!API_KEY) return res.status(400).json({ error: 'Google API key not configured' });
  const { ref, maxwidth } = req.query;
  if (!ref) return res.status(400).json({ error: 'Missing photo reference' });
  try {
    // New API: ref is a resource name like "places/ChIJ.../photos/AUy..."
    const photoUrl = `https://places.googleapis.com/v1/${ref}/media?maxWidthPx=${maxwidth || 300}&key=${API_KEY}`;
    const r = await fetch(photoUrl, { redirect: 'follow' });
    if (!r.ok) return res.status(r.status).end();
    res.set('Content-Type', r.headers.get('content-type') || 'image/jpeg');
    res.set('Cache-Control', 'public, max-age=604800');
    const arrayBuffer = await r.arrayBuffer();
    res.send(Buffer.from(arrayBuffer));
  } catch (e) {
    res.status(500).json({ error: 'Photo proxy error' });
  }
});

app.post('/api/place', auth, (req, res) => {
  const { place, place_id, restaurant_type, address, photo_ref, lat, lng } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  db.prepare('INSERT OR IGNORE INTO places (user_id, place, place_id, restaurant_type, address, photo_ref, lat, lng) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(req.user.id, place, place_id || null, restaurant_type || null, address || null, photo_ref || null, lat || null, lng || null);
  res.json({ success: true });
});

// ── Zones Routes ────────────────────────────────────────────────────────────────
app.get('/api/zones', auth, (req, res) => {
  const zones = db.prepare('SELECT * FROM zones WHERE user_id = ? ORDER BY is_default DESC, name ASC').all(req.user.id);
  res.json({ zones });
});

app.post('/api/zones', auth, (req, res) => {
  const { name, lat, lng, radius_km, is_default } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Zone name is required' });
  if (lat == null || lng == null) return res.status(400).json({ error: 'Location is required' });
  if (typeof lat !== 'number' || typeof lng !== 'number') return res.status(400).json({ error: 'Invalid coordinates' });

  const uid = req.user.id;
  const radiusVal = radius_km || 25;
  const isDefaultVal = is_default ? 1 : 0;
  const existingZones = db.prepare('SELECT COUNT(*) AS c FROM zones WHERE user_id = ?').get(uid).c;

  try {
    const createZone = db.transaction(() => {
      if (isDefaultVal) {
        db.prepare('UPDATE zones SET is_default = 0 WHERE user_id = ?').run(uid);
      }
      const result = db.prepare(
        'INSERT INTO zones (user_id, name, lat, lng, radius_km, is_default) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(uid, name.trim(), lat, lng, radiusVal, isDefaultVal);
      return result.lastInsertRowid;
    });

    const zoneId = createZone();
    let backfilled = 0;
    let backfilledSaved = 0;

    // If first zone and it's the default, backfill all existing places
    if (existingZones === 0 && isDefaultVal) {
      for (const table of ['likes', 'dislikes', 'want_to_try']) {
        const r = db.prepare(`UPDATE ${table} SET zone_id = ? WHERE user_id = ? AND zone_id IS NULL`).run(zoneId, uid);
        backfilledSaved += r.changes;
      }
      // Also backfill the history table (not shown to user)
      const r2 = db.prepare('UPDATE places SET zone_id = ? WHERE user_id = ? AND zone_id IS NULL').run(zoneId, uid);
      backfilled = backfilledSaved + r2.changes;
    }

    const zone = db.prepare('SELECT * FROM zones WHERE id = ?').get(zoneId);
    res.json({ zone, backfilled, backfilledSaved });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) {
      return res.status(409).json({ error: 'A zone with this name already exists' });
    }
    res.status(500).json({ error: 'Failed to create zone' });
  }
});

app.put('/api/zones/:id', auth, (req, res) => {
  const zoneId = Number(req.params.id);
  const uid = req.user.id;
  const zone = db.prepare('SELECT * FROM zones WHERE id = ? AND user_id = ?').get(zoneId, uid);
  if (!zone) return res.status(404).json({ error: 'Zone not found' });

  const { name, lat, lng, radius_km, is_default } = req.body;

  try {
    const updateZone = db.transaction(() => {
      if (is_default) {
        db.prepare('UPDATE zones SET is_default = 0 WHERE user_id = ?').run(uid);
      }
      const updates = [];
      const params = [];
      if (name !== undefined) { updates.push('name = ?'); params.push(name.trim()); }
      if (lat !== undefined) { updates.push('lat = ?'); params.push(lat); }
      if (lng !== undefined) { updates.push('lng = ?'); params.push(lng); }
      if (radius_km !== undefined) { updates.push('radius_km = ?'); params.push(radius_km); }
      if (is_default !== undefined) { updates.push('is_default = ?'); params.push(is_default ? 1 : 0); }
      if (updates.length > 0) {
        params.push(zoneId);
        db.prepare(`UPDATE zones SET ${updates.join(', ')} WHERE id = ?`).run(...params);
      }
    });
    updateZone();
    const updated = db.prepare('SELECT * FROM zones WHERE id = ?').get(zoneId);
    res.json({ zone: updated });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) {
      return res.status(409).json({ error: 'A zone with this name already exists' });
    }
    res.status(500).json({ error: 'Failed to update zone' });
  }
});

app.delete('/api/zones/:id', auth, (req, res) => {
  const zoneId = Number(req.params.id);
  const uid = req.user.id;
  const zone = db.prepare('SELECT * FROM zones WHERE id = ? AND user_id = ?').get(zoneId, uid);
  if (!zone) return res.status(404).json({ error: 'Zone not found' });

  const totalZones = db.prepare('SELECT COUNT(*) AS c FROM zones WHERE user_id = ?').get(uid).c;
  if (zone.is_default && totalZones > 1) {
    return res.status(400).json({ error: 'Cannot delete the default zone while other zones exist. Set a different default first.' });
  }

  const deleteZone = db.transaction(() => {
    let reassigned = 0;
    if (totalZones === 1) {
      for (const table of ['likes', 'dislikes', 'want_to_try', 'places']) {
        db.prepare(`UPDATE ${table} SET zone_id = NULL WHERE user_id = ? AND zone_id = ?`).run(uid, zoneId);
      }
    } else {
      const defaultZone = db.prepare('SELECT id FROM zones WHERE user_id = ? AND is_default = 1').get(uid);
      if (defaultZone) {
        for (const table of ['likes', 'dislikes', 'want_to_try', 'places']) {
          const r = db.prepare(`UPDATE ${table} SET zone_id = ? WHERE user_id = ? AND zone_id = ?`).run(defaultZone.id, uid, zoneId);
          reassigned += r.changes;
        }
      }
    }
    db.prepare('DELETE FROM zones WHERE id = ?').run(zoneId);
    return reassigned;
  });

  const reassigned = deleteZone();
  res.json({ success: true, reassigned });
});

app.post('/api/zones/detect', auth, (req, res) => {
  const { lat, lng } = req.body;
  if (lat == null || lng == null) return res.status(400).json({ error: 'Missing coordinates' });

  const zones = db.prepare('SELECT * FROM zones WHERE user_id = ?').all(req.user.id);
  if (zones.length === 0) return res.json({ zone: null, distance_km: null });

  let closest = null, minDist = Infinity;
  for (const z of zones) {
    const dist = haversine(lat, lng, z.lat, z.lng);
    if (dist < minDist) { minDist = dist; closest = z; }
  }

  if (closest && minDist <= closest.radius_km) {
    res.json({ zone: closest, distance_km: Math.round(minDist * 10) / 10 });
  } else {
    res.json({ zone: null, distance_km: closest ? Math.round(minDist * 10) / 10 : null });
  }
});

app.get('/api/zones/reverse-geocode', auth, async (req, res) => {
  if (!API_KEY) return res.status(400).json({ error: 'Google API key not configured' });
  const { lat, lng } = req.query;
  if (!lat || !lng) return res.status(400).json({ error: 'Missing coordinates' });
  try {
    const r = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&result_type=locality|administrative_area_level_1&key=${API_KEY}`);
    const data = await r.json();
    if (data.results && data.results.length > 0) {
      const components = data.results[0].address_components || [];
      const locality = components.find(c => c.types.includes('locality'));
      const area = components.find(c => c.types.includes('administrative_area_level_1'));
      const name = locality ? locality.long_name : (area ? area.long_name : data.results[0].formatted_address);
      res.json({ name, formatted: data.results[0].formatted_address });
    } else {
      res.json({ name: null, formatted: null });
    }
  } catch (e) {
    res.status(500).json({ error: 'Geocoding failed' });
  }
});

// ── Places Routes ───────────────────────────────────────────────────────────────
app.get('/api/places', auth, (req, res) => {
  const uid = req.user.id;
  const likes = db.prepare('SELECT place, place_id, restaurant_type, address, visited_at, notes, starred, meal_types, photo_ref, lat, lng, zone_id FROM likes WHERE user_id = ?').all(uid);
  const dislikes = db.prepare('SELECT place, place_id, restaurant_type, address, photo_ref, lat, lng, zone_id FROM dislikes WHERE user_id = ?').all(uid);
  const wantToTry = db.prepare('SELECT place, place_id, restaurant_type, address, starred, meal_types, photo_ref, lat, lng, zone_id FROM want_to_try WHERE user_id = ?').all(uid);
  const all = db.prepare('SELECT place, place_id, restaurant_type, address, photo_ref, lat, lng, zone_id FROM places WHERE user_id = ?').all(uid);
  res.json({
    likes: likes.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type, address: r.address || null, visited_at: r.visited_at || null, notes: r.notes || null, starred: !!r.starred, meal_types: r.meal_types ? r.meal_types.split(',') : [], photo_ref: r.photo_ref || null, lat: r.lat || null, lng: r.lng || null, zone_id: r.zone_id || null })),
    dislikes: dislikes.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type, address: r.address || null, photo_ref: r.photo_ref || null, lat: r.lat || null, lng: r.lng || null, zone_id: r.zone_id || null })),
    want_to_try: wantToTry.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type, address: r.address || null, starred: !!r.starred, meal_types: r.meal_types ? r.meal_types.split(',') : [], photo_ref: r.photo_ref || null, lat: r.lat || null, lng: r.lng || null, zone_id: r.zone_id || null })),
    all: all.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type, address: r.address || null, photo_ref: r.photo_ref || null, lat: r.lat || null, lng: r.lng || null, zone_id: r.zone_id || null })),
  });
  // Background backfill: fetch missing data from Google for places with a place_id
  if (API_KEY) {
    const tables = ['likes', 'dislikes', 'want_to_try', 'places'];
    const incomplete = [];
    const seen = new Set();
    for (const table of tables) {
      assertTable(table);
      const rows = db.prepare(`SELECT place_id FROM ${table} WHERE user_id = ? AND place_id IS NOT NULL AND place_id != '' AND (photo_ref IS NULL OR photo_ref = '' OR address IS NULL OR address = '' OR lat IS NULL)`).all(uid);
      for (const row of rows) {
        if (!seen.has(row.place_id)) { seen.add(row.place_id); incomplete.push(row.place_id); }
      }
    }
    if (incomplete.length > 0) {
      backfillPlaces(incomplete).catch(e => console.error('Background backfill error:', e.message));
    }
  }
});

async function backfillPlaces(placeIds) {
  const tables = ['likes', 'dislikes', 'want_to_try', 'places'];
  for (const placeId of placeIds) {
    try {
      const r = await fetch(`https://places.googleapis.com/v1/places/${placeId}`, {
        headers: {
          'X-Goog-Api-Key': API_KEY,
          'X-Goog-FieldMask': 'id,displayName,formattedAddress,types,photos,location',
        },
      });
      const data = await r.json();
      if (data.error) continue;
      const placeName = data.displayName?.text || null;
      const photoRef = data.photos?.[0]?.name || null;
      const address = data.formattedAddress || null;
      const types = (data.types || []).map(t => t.toLowerCase());
      const restaurantType = formatPlaceTypes(types);
      const lat = data.location?.latitude || null;
      const lng = data.location?.longitude || null;
      for (const t of tables) {
        assertTable(t);
        if (photoRef) db.prepare(`UPDATE ${t} SET photo_ref = ? WHERE place_id = ? AND (photo_ref IS NULL OR photo_ref = '')`).run(photoRef, placeId);
        if (address) db.prepare(`UPDATE ${t} SET address = ? WHERE place_id = ? AND (address IS NULL OR address = '')`).run(address, placeId);
        if (placeName) db.prepare(`UPDATE ${t} SET place = ? WHERE place_id = ?`).run(placeName, placeId);
        if (restaurantType) db.prepare(`UPDATE ${t} SET restaurant_type = ? WHERE place_id = ? AND (restaurant_type IS NULL OR restaurant_type = '')`).run(restaurantType, placeId);
        if (lat != null && lng != null) db.prepare(`UPDATE ${t} SET lat = ?, lng = ? WHERE place_id = ? AND lat IS NULL`).run(lat, lng, placeId);
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    } catch (e) {
      console.error(`Backfill failed for ${placeId}:`, e.message);
    }
  }
}

app.post('/api/places/:type/star', auth, (req, res) => {
  const { place } = req.body;
  const type = req.params.type;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  if (type !== 'likes' && type !== 'want_to_try') return res.status(400).json({ error: 'Invalid type' });
  const table = type === 'likes' ? 'likes' : 'want_to_try';
  assertTable(table);
  const row = db.prepare(`SELECT starred FROM ${table} WHERE user_id = ? AND place = ?`).get(req.user.id, place);
  if (!row) return res.status(404).json({ error: 'Place not found in your list' });
  const newVal = row.starred ? 0 : 1;
  db.prepare(`UPDATE ${table} SET starred = ? WHERE user_id = ? AND place = ?`).run(newVal, req.user.id, place);
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

app.post('/api/places/meal-types', auth, (req, res) => {
  const { place, meal_types, list_type } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  if (list_type !== 'likes' && list_type !== 'want_to_try') return res.status(400).json({ error: 'Invalid list type' });
  if (!Array.isArray(meal_types)) return res.status(400).json({ error: 'meal_types must be an array' });
  const table = list_type === 'likes' ? 'likes' : 'want_to_try';
  assertTable(table);
  const row = db.prepare(`SELECT 1 FROM ${table} WHERE user_id = ? AND place = ?`).get(req.user.id, place);
  if (!row) return res.status(404).json({ error: 'Place not found in your list' });
  const val = meal_types.length > 0 ? meal_types.join(',') : null;
  db.prepare(`UPDATE ${table} SET meal_types = ? WHERE user_id = ? AND place = ?`).run(val, req.user.id, place);
  res.json({ success: true });
});

app.post('/api/places', auth, async (req, res) => {
  const { type, place, place_id, remove, restaurant_type, address, photo_ref, active_zone_id } = req.body;
  const validTypes = ['likes', 'want_to_try', 'dislikes'];
  if (!place) return res.status(400).json({ error: 'Missing place' });
  if (!validTypes.includes(type)) return res.status(400).json({ error: 'Invalid type' });
  const uid = req.user.id;
  let movedFrom = null;

  // If we have a place_id but missing photo/address, fetch from Google before saving
  let finalPlace = place, finalAddress = address, finalPhotoRef = photo_ref, finalType = restaurant_type;
  let finalLat = null, finalLng = null;
  if (!remove && place_id && API_KEY && (!photo_ref || !address)) {
    try {
      const r = await fetch(`https://places.googleapis.com/v1/places/${place_id}`, {
        headers: { 'X-Goog-Api-Key': API_KEY, 'X-Goog-FieldMask': 'id,displayName,formattedAddress,types,photos,location' },
      });
      const data = await r.json();
      if (!data.error) {
        if (data.displayName?.text) finalPlace = data.displayName.text;
        if (!finalAddress && data.formattedAddress) finalAddress = data.formattedAddress;
        if (!finalPhotoRef && data.photos?.[0]?.name) finalPhotoRef = data.photos[0].name;
        if (!finalType) {
          const types = (data.types || []).map(t => t.toLowerCase());
          finalType = formatPlaceTypes(types) || finalType;
        }
        if (data.location) {
          finalLat = data.location.latitude;
          finalLng = data.location.longitude;
        }
      }
    } catch (e) { /* continue with what we have */ }
  }

  // Auto-assign zone_id based on coordinates or fallback to active zone
  let finalZoneId = null;
  if (!remove) {
    const zones = db.prepare('SELECT * FROM zones WHERE user_id = ?').all(uid);
    if (zones.length > 0 && finalLat != null && finalLng != null) {
      let closest = null, minDist = Infinity;
      for (const z of zones) {
        const dist = haversine(finalLat, finalLng, z.lat, z.lng);
        if (dist < minDist) { minDist = dist; closest = z; }
      }
      finalZoneId = closest.id;
    } else if (zones.length > 0 && active_zone_id) {
      const valid = zones.find(z => z.id === Number(active_zone_id));
      if (valid) finalZoneId = valid.id;
    }
  }

  if (remove) {
    db.prepare(`DELETE FROM ${type} WHERE user_id = ? AND place = ?`).run(uid, place);
  } else {
    db.prepare('INSERT OR IGNORE INTO places (user_id, place, place_id, restaurant_type, address, photo_ref, lat, lng, zone_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(uid, finalPlace, place_id || null, finalType || null, finalAddress || null, finalPhotoRef || null, finalLat, finalLng, finalZoneId);
    const others = { likes: ['dislikes', 'want_to_try'], want_to_try: ['likes', 'dislikes'], dislikes: ['likes', 'want_to_try'] };
    for (const tbl of others[type]) {
      const del = db.prepare(`DELETE FROM ${tbl} WHERE user_id = ? AND place = ?`).run(uid, finalPlace);
      if (del.changes > 0 && !movedFrom) movedFrom = tbl;
      // Also clean up by old name in case it differs
      if (finalPlace !== place) {
        const del2 = db.prepare(`DELETE FROM ${tbl} WHERE user_id = ? AND place = ?`).run(uid, place);
        if (del2.changes > 0 && !movedFrom) movedFrom = tbl;
      }
    }
    db.prepare(`INSERT OR IGNORE INTO ${type} (user_id, place, place_id, restaurant_type, address, photo_ref, lat, lng, zone_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(uid, finalPlace, place_id || null, finalType || null, finalAddress || null, finalPhotoRef || null, finalLat, finalLng, finalZoneId);
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
    sendPushToUser(friend.id, { title: 'Friend Request Accepted', body: `${req.user.username} accepted your friend request`, tag: 'friend-accepted' });
    return res.json({ success: true, autoAccepted: true });
  }

  db.prepare("INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, 'pending')").run(req.user.id, friend.id);
  sendPushToUser(friend.id, { title: 'Friend Request', body: `${req.user.username} sent you a friend request`, tag: 'friend-request' });
  res.json({ success: true });
});

app.get('/api/friend-requests', auth, (req, res) => {
  const requests = db.prepare(`
    SELECT u.id, u.username, u.display_name, u.profile_pic FROM friends f
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

app.get('/api/friend-requests/outgoing', auth, (req, res) => {
  const requests = db.prepare(`
    SELECT u.id, u.username, u.display_name, u.profile_pic FROM friends f
    JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ? AND f.status = 'pending'
  `).all(req.user.id);
  res.json({ requests });
});

app.get('/api/friends', auth, (req, res) => {
  const friends = db.prepare(`
    SELECT u.id, u.username, u.display_name, u.profile_pic FROM friends f
    JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ? AND f.status = 'accepted'
  `).all(req.user.id);
  res.json({ friends });
});

app.get('/api/friends/:id/likes', auth, (req, res) => {
  const friendId = req.params.id;
  const friendship = db.prepare("SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ? AND status = 'accepted'").get(req.user.id, friendId);
  if (!friendship) return res.status(403).json({ error: 'Not friends with this user' });
  const likes = db.prepare('SELECT DISTINCT place, place_id, restaurant_type, address, photo_ref FROM likes WHERE user_id = ?').all(friendId);
  res.json({ likes: likes.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type, address: r.address, photo_ref: r.photo_ref })) });
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
    JOIN likes l2 ON (l2.place = l1.place OR (l1.place_id IS NOT NULL AND l1.place_id != '' AND l2.place_id = l1.place_id))
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

// ── History Timeline ─────────────────────────────────────────────────────────────
app.get('/api/history', auth, (req, res) => {
  const uid = req.user.id;
  const { from, to, member } = req.query;
  let query = `
    SELECT s.id, s.name, s.winner_place, s.created_at, s.picked_at,
           s.creator_id, ss.restaurant_type AS winner_type
    FROM sessions s
    JOIN session_members sm ON sm.session_id = s.id AND sm.user_id = ?
    LEFT JOIN session_suggestions ss ON ss.session_id = s.id AND ss.place = s.winner_place
    WHERE s.status = 'closed' AND s.winner_place IS NOT NULL
  `;
  const params = [uid];

  if (from) { query += ' AND s.picked_at >= ?'; params.push(from); }
  if (to) { query += ' AND s.picked_at <= ?'; params.push(to + 'T23:59:59'); }

  if (member) {
    query += ` AND s.id IN (
      SELECT sm2.session_id FROM session_members sm2
      JOIN users u2 ON u2.id = sm2.user_id
      WHERE LOWER(u2.username) LIKE ?
    )`;
    params.push(`%${member.toLowerCase()}%`);
  }

  query += ' ORDER BY s.picked_at DESC, s.created_at DESC LIMIT 50';

  const plans = db.prepare(query).all(...params);

  // Fetch members for each plan
  const result = plans.map(p => {
    const members = db.prepare(`
      SELECT u.username, u.display_name, u.profile_pic FROM session_members sm JOIN users u ON u.id = sm.user_id WHERE sm.session_id = ?
    `).all(p.id);
    return { ...p, members };
  });

  res.json(result);
});

// ── Friend Groups ────────────────────────────────────────────────────────────────
app.get('/api/friend-groups', auth, (req, res) => {
  const groups = db.prepare('SELECT * FROM friend_groups WHERE creator_id = ?').all(req.user.id);
  const result = groups.map(g => {
    const members = db.prepare(`
      SELECT fgm.user_id, u.username, u.display_name, u.profile_pic FROM friend_group_members fgm
      JOIN users u ON u.id = fgm.user_id
      WHERE fgm.group_id = ?
    `).all(g.id);
    return { ...g, members };
  });
  res.json(result);
});

app.post('/api/friend-groups', auth, (req, res) => {
  const { name, memberIds } = req.body;
  if (!name || !Array.isArray(memberIds) || memberIds.length === 0) {
    return res.status(400).json({ error: 'Name and at least one member required' });
  }
  // Validate all are friends
  for (const mid of memberIds) {
    const isFriend = db.prepare(`
      SELECT 1 FROM friends WHERE ((user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)) AND status = 'accepted'
    `).get(req.user.id, mid, mid, req.user.id);
    if (!isFriend) return res.status(400).json({ error: 'All members must be friends' });
  }
  const result = db.prepare('INSERT INTO friend_groups (creator_id, name) VALUES (?, ?)').run(req.user.id, name.trim());
  const groupId = result.lastInsertRowid;
  const ins = db.prepare('INSERT OR IGNORE INTO friend_group_members (group_id, user_id) VALUES (?, ?)');
  for (const mid of memberIds) ins.run(groupId, mid);
  res.json({ success: true, id: groupId });
});

app.put('/api/friend-groups/:id', auth, (req, res) => {
  const groupId = req.params.id;
  const group = db.prepare('SELECT * FROM friend_groups WHERE id = ? AND creator_id = ?').get(groupId, req.user.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  const { name, memberIds } = req.body;
  if (name) db.prepare('UPDATE friend_groups SET name = ? WHERE id = ?').run(name.trim(), groupId);
  if (Array.isArray(memberIds)) {
    db.prepare('DELETE FROM friend_group_members WHERE group_id = ?').run(groupId);
    const ins = db.prepare('INSERT OR IGNORE INTO friend_group_members (group_id, user_id) VALUES (?, ?)');
    for (const mid of memberIds) ins.run(groupId, mid);
  }
  res.json({ success: true });
});

app.delete('/api/friend-groups/:id', auth, (req, res) => {
  const group = db.prepare('SELECT * FROM friend_groups WHERE id = ? AND creator_id = ?').get(req.params.id, req.user.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  db.prepare('DELETE FROM friend_groups WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.post('/api/plans/:id/invite-group', auth, (req, res) => {
  const planId = req.params.id;
  const { groupId } = req.body;
  const plan = db.prepare('SELECT * FROM sessions WHERE id = ?').get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });
  const group = db.prepare('SELECT * FROM friend_groups WHERE id = ? AND creator_id = ?').get(groupId, req.user.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  const members = db.prepare('SELECT user_id FROM friend_group_members WHERE group_id = ?').all(groupId);
  const ins = db.prepare('INSERT OR IGNORE INTO session_members (session_id, user_id) VALUES (?, ?)');
  let added = 0;
  for (const m of members) {
    const result = ins.run(planId, m.user_id);
    if (result.changes > 0) added++;
  }
  if (added > 0) {
    sendPushToPlanMembers(planId, { title: 'Group Invited', body: `${req.user.username} invited group "${group.name}" to ${plan.name}`, tag: `plan-${planId}` }, req.user.id);
    io.to(`plan:${planId}`).emit('plan:updated');
  }
  res.json({ success: true, added });
});

// ── Recurring Plans ──────────────────────────────────────────────────────────────
app.get('/api/recurring-plans', auth, (req, res) => {
  const plans = db.prepare('SELECT * FROM recurring_plans WHERE creator_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(plans.map(p => ({ ...p, member_ids: JSON.parse(p.member_ids || '[]') })));
});

app.post('/api/recurring-plans', auth, (req, res) => {
  const { name, frequency, memberIds, vetoLimit } = req.body;
  if (!name || !frequency) return res.status(400).json({ error: 'Name and frequency required' });
  const validFreqs = ['weekly', 'biweekly', 'monthly'];
  if (!validFreqs.includes(frequency)) return res.status(400).json({ error: 'Invalid frequency' });

  // Calculate next occurrence
  const now = new Date();
  let next = new Date(now);
  if (frequency === 'weekly') next.setDate(next.getDate() + 7);
  else if (frequency === 'biweekly') next.setDate(next.getDate() + 14);
  else if (frequency === 'monthly') next.setMonth(next.getMonth() + 1);

  const result = db.prepare(
    'INSERT INTO recurring_plans (creator_id, name, frequency, member_ids, veto_limit, next_occurrence) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(req.user.id, name.trim(), frequency, JSON.stringify(memberIds || []), vetoLimit || 0, next.toISOString());
  res.json({ success: true, id: result.lastInsertRowid });
});

app.patch('/api/recurring-plans/:id', auth, (req, res) => {
  const rp = db.prepare('SELECT * FROM recurring_plans WHERE id = ? AND creator_id = ?').get(req.params.id, req.user.id);
  if (!rp) return res.status(404).json({ error: 'Not found' });
  const { paused, frequency } = req.body;
  if (paused !== undefined) {
    db.prepare('UPDATE recurring_plans SET paused = ? WHERE id = ?').run(paused ? 1 : 0, rp.id);
  }
  if (frequency) {
    db.prepare('UPDATE recurring_plans SET frequency = ? WHERE id = ?').run(frequency, rp.id);
  }
  res.json({ success: true });
});

app.delete('/api/recurring-plans/:id', auth, (req, res) => {
  const rp = db.prepare('SELECT * FROM recurring_plans WHERE id = ? AND creator_id = ?').get(req.params.id, req.user.id);
  if (!rp) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM recurring_plans WHERE id = ?').run(rp.id);
  res.json({ success: true });
});

app.post('/api/recurring-plans/:id/skip', auth, (req, res) => {
  const rp = db.prepare('SELECT * FROM recurring_plans WHERE id = ? AND creator_id = ?').get(req.params.id, req.user.id);
  if (!rp) return res.status(404).json({ error: 'Not found' });
  const next = new Date(rp.next_occurrence);
  if (rp.frequency === 'weekly') next.setDate(next.getDate() + 7);
  else if (rp.frequency === 'biweekly') next.setDate(next.getDate() + 14);
  else if (rp.frequency === 'monthly') next.setMonth(next.getMonth() + 1);
  db.prepare('UPDATE recurring_plans SET next_occurrence = ? WHERE id = ?').run(next.toISOString(), rp.id);
  res.json({ success: true, next_occurrence: next.toISOString() });
});

// ── Plan Routes ──────────────────────────────────────────────────────────────
app.post('/api/plans', auth, (req, res) => {
  const { name, veto_limit, meal_type, dietary_tags } = req.body;
  const planName = (name || 'Dinner Plan').trim().slice(0, 100);
  const code = generatePlanCode();
  const vetoLimit = (veto_limit != null && veto_limit >= 0) ? veto_limit : 1;
  const dietaryStr = Array.isArray(dietary_tags) ? dietary_tags.join(',') : (dietary_tags || null);
  try {
    const result = db.prepare('INSERT INTO sessions (code, creator_id, name, veto_limit, meal_type, dietary_tags) VALUES (?, ?, ?, ?, ?, ?)').run(code, req.user.id, planName, vetoLimit, meal_type || null, dietaryStr);
    const planId = result.lastInsertRowid;
    db.prepare('INSERT INTO session_members (session_id, user_id) VALUES (?, ?)').run(planId, req.user.id);
    res.json({ id: planId, code, name: planName, meal_type: meal_type || null, dietary_tags: dietaryStr });
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
  const joiner = db.prepare('SELECT display_name, profile_pic FROM users WHERE id = ?').get(req.user.id);
  io.to(`plan:${plan.id}`).emit('plan:member-joined', { username: req.user.username, userId: req.user.id, display_name: joiner?.display_name || null, profile_pic: joiner?.profile_pic || null });
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
  const target = db.prepare('SELECT id, username, display_name, profile_pic FROM users WHERE LOWER(username) = LOWER(?)').get(username.trim());
  if (!target) return res.status(404).json({ error: 'User not found' });
  const alreadyMember = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, target.id);
  if (alreadyMember) return res.json({ success: true, alreadyMember: true });
  db.prepare('INSERT OR IGNORE INTO session_members (session_id, user_id) VALUES (?, ?)').run(planId, target.id);
  io.to(`plan:${planId}`).emit('plan:member-joined', { username: target.username, userId: target.id, display_name: target.display_name || null, profile_pic: target.profile_pic || null });
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
    SELECT s.id, s.code, s.name, s.status, s.winner_place, s.picked_at, s.created_at, s.creator_id, s.voting_deadline, s.meal_type,
           u.username AS creator_username, u.display_name AS creator_display_name, u.profile_pic AS creator_profile_pic,
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
    SELECT u.id, u.username, u.display_name, u.profile_pic FROM session_members sm
    JOIN users u ON u.id = sm.user_id
    WHERE sm.session_id = ?
  `).all(planId);

  const suggestions = db.prepare(`
    SELECT ss.id, ss.place, ss.place_id, ss.restaurant_type, ss.lat, ss.lng, ss.price_level, ss.photo_ref, ss.meal_types, ss.user_id,
           u.username AS suggested_by, u.display_name AS suggested_by_display_name, u.profile_pic AS suggested_by_profile_pic,
           (SELECT COUNT(*) FROM session_votes sv WHERE sv.suggestion_id = ss.id AND sv.vote_type = 'up') AS vote_count,
           (SELECT COUNT(*) FROM session_votes sv WHERE sv.suggestion_id = ss.id AND sv.vote_type = 'down') AS downvote_count,
           (SELECT COUNT(*) FROM session_vetoes svt WHERE svt.suggestion_id = ss.id) AS veto_count
    FROM session_suggestions ss
    JOIN users u ON u.id = ss.user_id
    WHERE ss.session_id = ?
  `).all(planId);

  const userVotes = db.prepare('SELECT suggestion_id, vote_type FROM session_votes WHERE session_id = ? AND user_id = ?').all(planId, req.user.id);
  const votedIds = new Set(userVotes.filter(v => v.vote_type === 'up').map(v => v.suggestion_id));
  const downvotedIds = new Set(userVotes.filter(v => v.vote_type === 'down').map(v => v.suggestion_id));

  const userVetoes = db.prepare('SELECT suggestion_id FROM session_vetoes WHERE session_id = ? AND user_id = ?').all(planId, req.user.id);
  const vetoedIds = new Set(userVetoes.map(v => v.suggestion_id));

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

  // Fetch vetoers for each suggestion
  const allVetoes = db.prepare(`
    SELECT svt.suggestion_id, u.username
    FROM session_vetoes svt
    JOIN users u ON u.id = svt.user_id
    WHERE svt.session_id = ?
  `).all(planId);
  const vetoersMap = {};
  allVetoes.forEach(v => {
    if (!vetoersMap[v.suggestion_id]) vetoersMap[v.suggestion_id] = [];
    vetoersMap[v.suggestion_id].push(v.username);
  });

  const userVetoCount = db.prepare('SELECT COUNT(*) AS c FROM session_vetoes WHERE session_id = ? AND user_id = ?').get(planId, req.user.id).c;
  const vetoesRemaining = (plan.veto_limit || 0) - userVetoCount;

  // Find which session suggestions are on members' want-to-try lists
  const memberIds = members.map(m => m.id);
  const wantToTryMap = {};
  if (memberIds.length > 0 && suggestions.length > 0) {
    const placeholders = memberIds.map(() => '?').join(',');
    const wantToTryRows = db.prepare(`
      SELECT wt.place, wt.user_id, u.username, u.display_name, u.profile_pic
      FROM want_to_try wt
      JOIN users u ON u.id = wt.user_id
      WHERE wt.user_id IN (${placeholders})
        AND (wt.place IN (SELECT place FROM session_suggestions WHERE session_id = ?)
             OR (wt.place_id IS NOT NULL AND wt.place_id != '' AND wt.place_id IN (SELECT place_id FROM session_suggestions WHERE session_id = ? AND place_id IS NOT NULL)))
    `).all(...memberIds, planId, planId);
    wantToTryRows.forEach(row => {
      if (!wantToTryMap[row.place]) wantToTryMap[row.place] = [];
      wantToTryMap[row.place].push({ user_id: row.user_id, username: row.username, display_name: row.display_name, profile_pic: row.profile_pic });
    });
  }

  res.json({
    plan,
    members,
    suggestions: suggestions.map(s => ({ ...s, meal_types: s.meal_types ? s.meal_types.split(',') : [], user_voted: votedIds.has(s.id), user_downvoted: downvotedIds.has(s.id), user_vetoed: vetoedIds.has(s.id), voters: votersMap[s.id] || [], downvoters: downvotersMap[s.id] || [], vetoers: vetoersMap[s.id] || [] })),
    want_to_try: wantToTryMap,
    vetoesRemaining,
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

  let lat = null, lng = null, priceLevel = null, photoRef = null;
  if (place_id) {
    try {
      const r = await fetch(`https://places.googleapis.com/v1/places/${place_id}`, {
        headers: {
          'X-Goog-Api-Key': API_KEY,
          'X-Goog-FieldMask': 'location,priceLevel,photos',
        },
      });
      const data = await r.json();
      if (data.location) {
        lat = data.location.latitude;
        lng = data.location.longitude;
      }
      if (data.priceLevel != null) {
        // New API returns enum strings like PRICE_LEVEL_MODERATE; convert to number
        const priceLevels = { PRICE_LEVEL_FREE: 0, PRICE_LEVEL_INEXPENSIVE: 1, PRICE_LEVEL_MODERATE: 2, PRICE_LEVEL_EXPENSIVE: 3, PRICE_LEVEL_VERY_EXPENSIVE: 4 };
        priceLevel = priceLevels[data.priceLevel] ?? null;
      }
      if (data.photos?.[0]?.name) {
        photoRef = data.photos[0].name;
      }
    } catch (e) {
      console.error('Failed to fetch place details:', e.message);
    }
  }

  // Auto-populate meal_types from user's liked places
  let mealTypes = null;
  const likedPlace = db.prepare('SELECT meal_types FROM likes WHERE user_id = ? AND place = ?').get(req.user.id, place);
  if (likedPlace?.meal_types) mealTypes = likedPlace.meal_types;

  try {
    const result = db.prepare('INSERT OR IGNORE INTO session_suggestions (session_id, user_id, place, place_id, restaurant_type, lat, lng, price_level, photo_ref, meal_types) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(planId, req.user.id, place, place_id || null, restaurant_type || null, lat, lng, priceLevel, photoRef, mealTypes);
    if (result.changes === 0) return res.status(409).json({ error: 'Already suggested' });
    const suggestionId = result.lastInsertRowid;
    db.prepare("INSERT OR IGNORE INTO session_votes (session_id, user_id, suggestion_id, vote_type) VALUES (?, ?, ?, 'up')").run(planId, req.user.id, suggestionId);
    io.to(`plan:${planId}`).emit('plan:suggestion-added', {
      id: suggestionId, place, place_id: place_id || null,
      restaurant_type: restaurant_type || null,
      meal_types: mealTypes ? mealTypes.split(',') : [],
      lat, lng, price_level: priceLevel, photo_ref: photoRef, suggested_by: req.user.username, vote_count: 1, user_voted: true,
    });
    sendPushToPlanMembers(planId, { title: 'New Suggestion', body: `${req.user.username} suggested ${place}`, tag: `plan-${planId}` }, req.user.id);
    res.json({ success: true, id: suggestionId });
  } catch (err) {
    res.status(500).json({ error: 'Failed to suggest' });
  }
});

app.put('/api/plans/:id/meal-type', auth, (req, res) => {
  const planId = req.params.id;
  const { meal_type } = req.body;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });
  db.prepare('UPDATE sessions SET meal_type = ? WHERE id = ?').run(meal_type || null, planId);
  io.to(`plan:${planId}`).emit('plan:updated', { meal_type: meal_type || null });
  res.json({ success: true });
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

  db.prepare('DELETE FROM session_vetoes WHERE suggestion_id = ?').run(suggestionId);
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

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

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

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  db.prepare("DELETE FROM session_votes WHERE session_id = ? AND user_id = ? AND suggestion_id = ? AND vote_type = 'down'").run(planId, req.user.id, suggestion_id);
  const voteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'up'").get(suggestion_id).c;
  const downvoteCount = db.prepare("SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ? AND vote_type = 'down'").get(suggestion_id).c;
  io.to(`plan:${planId}`).emit('plan:vote-updated', { suggestion_id, vote_count: voteCount, downvote_count: downvoteCount, user_id: req.user.id, username: req.user.username, action: 'undownvote' });
  res.json({ success: true });
});

// ── Vetoes ────────────────────────────────────────────────────────────────────
app.post('/api/plans/:id/veto', auth, (req, res) => {
  const planId = req.params.id;
  const { suggestion_id } = req.body;
  if (!suggestion_id) return res.status(400).json({ error: 'Missing suggestion_id' });

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const plan = db.prepare('SELECT status, veto_limit FROM sessions WHERE id = ?').get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  if (plan.status !== 'open') return res.status(400).json({ error: 'Plan is closed' });

  const userVetoCount = db.prepare('SELECT COUNT(*) AS c FROM session_vetoes WHERE session_id = ? AND user_id = ?').get(planId, req.user.id).c;
  if (userVetoCount >= (plan.veto_limit || 0)) return res.status(400).json({ error: 'No vetoes remaining' });

  try {
    db.prepare('INSERT INTO session_vetoes (session_id, user_id, suggestion_id) VALUES (?, ?, ?)').run(planId, req.user.id, suggestion_id);
  } catch (e) {
    if (e.message.includes('UNIQUE constraint')) return res.status(400).json({ error: 'Already vetoed' });
    throw e;
  }

  const vetoCount = db.prepare('SELECT COUNT(*) AS c FROM session_vetoes WHERE suggestion_id = ?').get(suggestion_id).c;
  const vetoers = db.prepare('SELECT u.username FROM session_vetoes sv JOIN users u ON u.id = sv.user_id WHERE sv.suggestion_id = ?').all(suggestion_id).map(r => r.username);
  io.to(`plan:${planId}`).emit('plan:veto-updated', { suggestion_id, veto_count: vetoCount, vetoers, user_id: req.user.id, username: req.user.username, action: 'veto' });
  res.json({ success: true });
});

app.post('/api/plans/:id/unveto', auth, (req, res) => {
  const planId = req.params.id;
  const { suggestion_id } = req.body;
  if (!suggestion_id) return res.status(400).json({ error: 'Missing suggestion_id' });

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  db.prepare('DELETE FROM session_vetoes WHERE session_id = ? AND user_id = ? AND suggestion_id = ?').run(planId, req.user.id, suggestion_id);

  const vetoCount = db.prepare('SELECT COUNT(*) AS c FROM session_vetoes WHERE suggestion_id = ?').get(suggestion_id).c;
  const vetoers = db.prepare('SELECT u.username FROM session_vetoes sv JOIN users u ON u.id = sv.user_id WHERE sv.suggestion_id = ?').all(suggestion_id).map(r => r.username);
  io.to(`plan:${planId}`).emit('plan:veto-updated', { suggestion_id, veto_count: vetoCount, vetoers, user_id: req.user.id, username: req.user.username, action: 'unveto' });
  res.json({ success: true });
});

app.post('/api/plans/:id/veto-limit', auth, (req, res) => {
  const planId = req.params.id;
  const { veto_limit } = req.body;
  if (veto_limit == null || veto_limit < 0) return res.status(400).json({ error: 'Invalid veto limit' });

  const plan = db.prepare('SELECT * FROM sessions WHERE id = ?').get(planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  if (plan.creator_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can change veto limit' });

  db.prepare('UPDATE sessions SET veto_limit = ? WHERE id = ?').run(veto_limit, planId);
  io.to(`plan:${planId}`).emit('plan:veto-limit-updated', { planId: Number(planId), veto_limit });
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
           (SELECT COUNT(*) FROM session_votes sv WHERE sv.suggestion_id = ss.id AND sv.vote_type = 'down') AS downvote_count,
           (SELECT COUNT(*) FROM session_vetoes svt WHERE svt.suggestion_id = ss.id) AS veto_count
    FROM session_suggestions ss
    WHERE ss.session_id = ?
  `).all(planId);

  if (suggestions.length === 0) return res.status(400).json({ error: 'No suggestions yet' });

  // Filter out vetoed suggestions; fall back to all if everything is vetoed
  const nonVetoed = suggestions.filter(s => s.veto_count === 0);
  const eligible = nonVetoed.length > 0 ? nonVetoed : suggestions;

  let winner;

  if (mode === 'closest') {
    if (lat == null || lng == null) return res.status(400).json({ error: 'Location required for closest pick' });
    const withCoords = eligible.filter(s => s.lat != null && s.lng != null);
    if (withCoords.length === 0) return res.status(400).json({ error: 'No suggestions have location data' });
    withCoords.forEach(s => { s.distance = haversine(lat, lng, s.lat, s.lng); });
    withCoords.sort((a, b) => a.distance - b.distance);
    winner = withCoords[0];
  } else {
    // Pick from top net-voted suggestions only (wheel acts as tiebreaker)
    const maxNetVotes = Math.max(...eligible.map(s => s.vote_count - s.downvote_count));
    const topVoted = eligible.filter(s => s.vote_count - s.downvote_count === maxNetVotes);
    winner = topVoted[Math.floor(Math.random() * topVoted.length)];
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
    db.prepare('DELETE FROM session_vetoes WHERE session_id = ?').run(planId);
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

// ── Mention Extraction ───────────────────────────────────────────────────────
function extractMentions(text, planMembers) {
  const mentionRegex = /@(all|[\w_-]+)/g;
  const mentions = new Set();
  let match;
  while ((match = mentionRegex.exec(text)) !== null) {
    if (match[1] === 'all') mentions.add('all');
    else {
      const member = planMembers.find(m => m.username === match[1]);
      if (member) mentions.add(member.user_id);
    }
  }
  return Array.from(mentions);
}

// ── Plan Chat ─────────────────────────────────────────────────────────────────
app.get('/api/plans/:id/messages', auth, (req, res) => {
  const planId = req.params.id;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });

  const messages = db.prepare(`
    SELECT sm.id, sm.message, sm.message_type, sm.created_at, sm.edited_at, sm.user_id, u.username, u.display_name, u.profile_pic
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
    if (!message || message.length > 1000) return res.status(400).json({ error: 'Invalid GIF URL' });
    try {
      const gifUrl = new URL(message);
      if (gifUrl.protocol !== 'https:' || !/^(media\d*|i)\.giphy\.com$/.test(gifUrl.hostname)) {
        return res.status(400).json({ error: 'Invalid GIF URL' });
      }
    } catch { return res.status(400).json({ error: 'Invalid GIF URL' }); }
  } else {
    if (!message || !message.trim()) return res.status(400).json({ error: 'Message cannot be empty' });
    if (message.length > 500) return res.status(400).json({ error: 'Message too long (max 500 characters)' });
  }

  const content = type === 'text' ? message.trim().replace(/<[^>]*>/g, '') : message;
  if (type === 'text' && !content) return res.status(400).json({ error: 'Message cannot be empty' });
  const result = db.prepare('INSERT INTO session_messages (session_id, user_id, message, message_type) VALUES (?, ?, ?, ?)').run(planId, req.user.id, content, type);
  const sender = db.prepare('SELECT username, display_name, profile_pic FROM users WHERE id = ?').get(req.user.id);
  const username = sender.username;

  let mentions = [];
  if (type === 'text') {
    const members = db.prepare('SELECT sm.user_id, u.username FROM session_members sm JOIN users u ON u.id = sm.user_id WHERE sm.session_id = ?').all(planId);
    mentions = extractMentions(content, members);

    if (mentions.length > 0) {
      const plan = db.prepare('SELECT name FROM sessions WHERE id = ?').get(planId);
      const planName = plan?.name || 'a plan';
      const pushPayload = { title: 'You were mentioned', body: `${username} mentioned you in ${planName}`, tag: `mention-${planId}` };
      if (mentions.includes('all')) {
        sendPushToPlanMembers(planId, pushPayload, req.user.id);
      } else {
        for (const uid of mentions) {
          if (uid !== req.user.id) sendPushToUser(uid, pushPayload);
        }
      }
    }
  }

  const msg = { id: result.lastInsertRowid, message: content, message_type: type, user_id: req.user.id, username, display_name: sender.display_name || null, profile_pic: sender.profile_pic || null, created_at: new Date().toISOString(), reactions: [], mentions };
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
  if (!emoji || !/^\p{Emoji}/u.test(emoji) || emoji.length > 8) return res.status(400).json({ error: 'Invalid emoji' });

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

// Delete a chat message (author or admin)
app.delete('/api/plans/:id/messages/:messageId', auth, (req, res) => {
  const planId = req.params.id;
  const messageId = req.params.messageId;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });
  const msg = db.prepare('SELECT user_id FROM session_messages WHERE id = ? AND session_id = ?').get(messageId, planId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  const isAdmin = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.user.id)?.is_admin;
  if (msg.user_id !== req.user.id && !isAdmin) return res.status(403).json({ error: 'Permission denied' });
  db.prepare('DELETE FROM message_reactions WHERE message_id = ?').run(messageId);
  db.prepare('DELETE FROM session_messages WHERE id = ?').run(messageId);
  io.to(`plan:${planId}`).emit('plan:message-deleted', { message_id: Number(messageId) });
  res.json({ success: true });
});

// Edit a chat message (author only)
app.patch('/api/plans/:id/messages/:messageId', auth, (req, res) => {
  const planId = req.params.id;
  const messageId = req.params.messageId;
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message cannot be empty' });
  if (message.length > 500) return res.status(400).json({ error: 'Message too long (max 500 characters)' });
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });
  const msg = db.prepare('SELECT user_id, message_type FROM session_messages WHERE id = ? AND session_id = ?').get(messageId, planId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.user_id !== req.user.id) return res.status(403).json({ error: 'Only the author can edit a message' });
  if (msg.message_type === 'gif') return res.status(400).json({ error: 'Cannot edit GIF messages' });
  const sanitized = message.trim().replace(/<[^>]*>/g, '');
  if (!sanitized) return res.status(400).json({ error: 'Message cannot be empty' });
  db.prepare('UPDATE session_messages SET message = ?, edited_at = datetime(\'now\') WHERE id = ?').run(sanitized, messageId);
  io.to(`plan:${planId}`).emit('plan:message-edited', { message_id: Number(messageId), message: sanitized, edited_at: new Date().toISOString() });
  res.json({ success: true });
});

// ── Read Receipts ───────────────────────────────────────────────────────────
app.post('/api/plans/:id/messages/read', auth, (req, res) => {
  const planId = req.params.id;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });
  const lastMsg = db.prepare('SELECT MAX(id) AS max_id FROM session_messages WHERE session_id = ?').get(planId);
  if (!lastMsg?.max_id) return res.json({ success: true });
  db.prepare('INSERT INTO message_reads (session_id, user_id, last_read_message_id, read_at) VALUES (?, ?, ?, datetime(\'now\')) ON CONFLICT(session_id, user_id) DO UPDATE SET last_read_message_id = ?, read_at = datetime(\'now\')').run(planId, req.user.id, lastMsg.max_id, lastMsg.max_id);
  const user = db.prepare('SELECT username, display_name FROM users WHERE id = ?').get(req.user.id);
  io.to(`plan:${planId}`).emit('plan:messages-read', { user_id: req.user.id, username: user.username, display_name: user.display_name, last_read_message_id: lastMsg.max_id });
  res.json({ success: true });
});

app.get('/api/plans/:id/messages/reads', auth, (req, res) => {
  const planId = req.params.id;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this plan' });
  const reads = db.prepare(`
    SELECT mr.user_id, mr.last_read_message_id, u.username, u.display_name
    FROM message_reads mr JOIN users u ON u.id = mr.user_id
    WHERE mr.session_id = ?
  `).all(planId);
  res.json(reads);
});

// ── Giphy GIF Proxy ──────────────────────────────────────────────────────────
let GIPHY_API_KEY = getSetting('giphy_api_key');
if (!GIPHY_API_KEY && process.env.GIPHY_API_KEY) {
  GIPHY_API_KEY = process.env.GIPHY_API_KEY;
  setSetting('giphy_api_key', GIPHY_API_KEY);
}
if (!GIPHY_API_KEY) {
  console.warn('WARNING: Giphy API key not set — configure via admin panel.');
}

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
  if (!API_KEY) return res.status(503).json({ error: 'Maps not configured' });
  res.json({ key: API_KEY });
});

// ── SPA Fallback ────────────────────────────────────────────────────────────────
const indexTemplate = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
app.use((req, res) => {
  const html = indexTemplate.replace(/__CSP_NONCE__/g, res.locals.cspNonce);
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.type('html').send(html);
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
  socket.join(`user:${socket.user.id}`);

  socket.on('join-plan', (planId) => {
    const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, socket.user.id);
    if (membership) {
      socket.join(`plan:${planId}`);
    }
  });

  socket.on('leave-plan', (planId) => {
    socket.leave(`plan:${planId}`);
  });

  socket.on('typing-start', (planId) => {
    const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(planId, socket.user.id);
    if (!membership) return;
    const user = db.prepare('SELECT username, display_name FROM users WHERE id = ?').get(socket.user.id);
    socket.to(`plan:${planId}`).emit('user-typing', { user_id: socket.user.id, username: user.username, display_name: user.display_name });
  });

  socket.on('typing-stop', (planId) => {
    socket.to(`plan:${planId}`).emit('user-stopped-typing', { user_id: socket.user.id });
  });
});

// ── Recurring Plan Scheduler ──────────────────────────────────────────────────
function processRecurringPlans() {
  const now = new Date().toISOString();
  const due = db.prepare('SELECT * FROM recurring_plans WHERE paused = 0 AND next_occurrence <= ?').all(now);
  for (const rp of due) {
    try {
      const code = generatePlanCode();
      const result = db.prepare('INSERT INTO sessions (code, creator_id, name, veto_limit) VALUES (?, ?, ?, ?)').run(code, rp.creator_id, rp.name, rp.veto_limit || 0);
      const planId = result.lastInsertRowid;
      db.prepare('INSERT INTO session_members (session_id, user_id) VALUES (?, ?)').run(planId, rp.creator_id);
      const memberIds = JSON.parse(rp.member_ids || '[]');
      const ins = db.prepare('INSERT OR IGNORE INTO session_members (session_id, user_id) VALUES (?, ?)');
      for (const mid of memberIds) ins.run(planId, mid);
      // Advance next_occurrence
      const next = new Date(rp.next_occurrence);
      if (rp.frequency === 'weekly') next.setDate(next.getDate() + 7);
      else if (rp.frequency === 'biweekly') next.setDate(next.getDate() + 14);
      else if (rp.frequency === 'monthly') next.setMonth(next.getMonth() + 1);
      db.prepare('UPDATE recurring_plans SET next_occurrence = ? WHERE id = ?').run(next.toISOString(), rp.id);
      // Send push notifications
      sendPushToPlanMembers(planId, { title: 'Recurring Plan', body: `"${rp.name}" — a new plan has been created`, tag: `plan-${planId}` }, rp.creator_id);
      console.log(`Recurring plan "${rp.name}" created plan #${planId}`);
    } catch (e) {
      console.error(`Failed to process recurring plan ${rp.id}:`, e.message);
    }
  }
}
if (require.main === module) {
  // Check every 15 minutes
  setInterval(processRecurringPlans, 15 * 60 * 1000);
  // Run once on startup to catch any missed
  setTimeout(processRecurringPlans, 5000);
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
