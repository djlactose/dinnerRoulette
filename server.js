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

// ── Environment Validation ─────────────────────────────────────────────────────
const API_KEY = process.env.GOOGLE_API_KEY;
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
      scriptSrc: ["'self'", "'unsafe-eval'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdn.socket.io"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      upgradeInsecureRequests: null,
    }
  }
}));
app.use(compression());
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

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

// ── Helpers ─────────────────────────────────────────────────────────────────────
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
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

function generateSessionCode() {
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
  const { username, password, remember } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const trimmedUser = username.trim();
  if (trimmedUser.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const existing = db.prepare('SELECT 1 FROM users WHERE LOWER(username) = LOWER(?)').get(trimmedUser);
    if (existing) return res.status(400).json({ error: 'Username taken' });
    const result = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(trimmedUser, hash);
    const token = generateToken({ id: result.lastInsertRowid, username: trimmedUser });
    res.cookie('token', token, cookieOpts(remember));
    res.json({ username: trimmedUser });
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
  res.json({ username: user.username });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username });
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
    db.prepare('DELETE FROM session_votes WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM session_suggestions WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM session_members WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM likes WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM dislikes WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM places WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM suggestions WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM friends WHERE user_id = ? OR friend_id = ?').run(uid, uid);
    db.prepare('DELETE FROM users WHERE id = ?').run(uid);
  });
  deleteAll();

  res.clearCookie('token');
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
  const likes = db.prepare('SELECT place, place_id, restaurant_type FROM likes WHERE user_id = ?').all(uid);
  const dislikes = db.prepare('SELECT place, place_id, restaurant_type FROM dislikes WHERE user_id = ?').all(uid);
  const all = db.prepare('SELECT place, place_id, restaurant_type FROM places WHERE user_id = ?').all(uid);
  res.json({
    likes: likes.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type })),
    dislikes: dislikes.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type })),
    all: all.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type })),
  });
});

app.post('/api/places', auth, (req, res) => {
  const { type, place, place_id, remove, restaurant_type } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  const uid = req.user.id;

  if (remove) {
    if (type === 'likes') {
      db.prepare('DELETE FROM likes WHERE user_id = ? AND place = ?').run(uid, place);
    } else {
      db.prepare('DELETE FROM dislikes WHERE user_id = ? AND place = ?').run(uid, place);
    }
  } else {
    db.prepare('INSERT OR IGNORE INTO places (user_id, place, place_id, restaurant_type) VALUES (?, ?, ?, ?)').run(uid, place, place_id || null, restaurant_type || null);
    if (type === 'likes') {
      db.prepare('INSERT OR IGNORE INTO likes (user_id, place, place_id, restaurant_type) VALUES (?, ?, ?, ?)').run(uid, place, place_id || null, restaurant_type || null);
    } else {
      db.prepare('INSERT OR IGNORE INTO dislikes (user_id, place, place_id, restaurant_type) VALUES (?, ?, ?, ?)').run(uid, place, place_id || null, restaurant_type || null);
    }
  }
  res.json({ success: true });
});

// ── Friends Routes ──────────────────────────────────────────────────────────────
app.post('/api/invite', auth, (req, res) => {
  const { friendUsername } = req.body;
  if (!friendUsername) return res.status(400).json({ error: 'Missing friend username' });
  const friend = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get(friendUsername.trim());
  if (!friend) return res.status(404).json({ error: 'User not found' });
  if (friend.id === req.user.id) return res.status(400).json({ error: 'Cannot add yourself' });
  db.prepare('INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)').run(req.user.id, friend.id);
  res.json({ success: true });
});

app.get('/api/friends', auth, (req, res) => {
  const friends = db.prepare(`
    SELECT u.id, u.username FROM friends f
    JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ?
  `).all(req.user.id);
  res.json({ friends });
});

app.get('/api/common-places', auth, (req, res) => {
  const friendUsername = req.query.friendUsername;
  if (!friendUsername) return res.status(400).json({ error: 'Missing friendUsername' });
  const friend = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)').get(friendUsername.trim());
  if (!friend) return res.status(404).json({ error: 'User not found' });
  const common = db.prepare(`
    SELECT l1.place FROM likes l1
    JOIN likes l2 ON l2.place = l1.place
    WHERE l1.user_id = ? AND l2.user_id = ?
  `).all(req.user.id, friend.id);
  res.json({ common: common.map(r => r.place) });
});

// ── Suggestions Routes ──────────────────────────────────────────────────────────
app.post('/api/suggest', auth, (req, res) => {
  const { place, place_id, restaurant_type } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  try {
    db.prepare('INSERT OR IGNORE INTO suggestions (user_id, place, place_id, restaurant_type) VALUES (?, ?, ?, ?)').run(req.user.id, place, place_id || null, restaurant_type || null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save suggestion' });
  }
});

app.get('/api/suggestions', auth, (req, res) => {
  const rows = db.prepare('SELECT place, place_id, restaurant_type FROM suggestions WHERE user_id = ?').all(req.user.id);
  res.json({ suggestions: rows.map(r => ({ name: r.place, place_id: r.place_id, restaurant_type: r.restaurant_type })) });
});

app.post('/api/suggestions/remove', auth, (req, res) => {
  const { place } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });
  db.prepare('DELETE FROM suggestions WHERE user_id = ? AND place = ?').run(req.user.id, place);
  res.json({ success: true });
});

// ── Session Routes ──────────────────────────────────────────────────────────────
app.post('/api/sessions', auth, (req, res) => {
  const { name } = req.body;
  const code = generateSessionCode();
  try {
    const result = db.prepare('INSERT INTO sessions (code, creator_id, name) VALUES (?, ?, ?)').run(code, req.user.id, name || 'Dinner Session');
    const sessionId = result.lastInsertRowid;
    db.prepare('INSERT INTO session_members (session_id, user_id) VALUES (?, ?)').run(sessionId, req.user.id);
    res.json({ id: sessionId, code, name: name || 'Dinner Session' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create session' });
  }
});

app.post('/api/sessions/join', auth, (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Missing code' });
  const session = db.prepare("SELECT * FROM sessions WHERE code = ? AND status = 'open'").get(code.toUpperCase());
  if (!session) return res.status(404).json({ error: 'Session not found or closed' });
  db.prepare('INSERT OR IGNORE INTO session_members (session_id, user_id) VALUES (?, ?)').run(session.id, req.user.id);
  io.to(`session:${session.id}`).emit('session:member-joined', { username: req.user.username, userId: req.user.id });
  res.json({ id: session.id, code: session.code, name: session.name });
});

app.get('/api/sessions', auth, (req, res) => {
  const sessions = db.prepare(`
    SELECT s.id, s.code, s.name, s.status, s.winner_place, s.picked_at, s.created_at, s.creator_id
    FROM sessions s
    JOIN session_members sm ON sm.session_id = s.id
    WHERE sm.user_id = ?
    ORDER BY s.created_at DESC
  `).all(req.user.id);
  res.json({ sessions });
});

app.get('/api/sessions/:id', auth, (req, res) => {
  const sessionId = req.params.id;
  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(sessionId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member of this session' });

  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });

  const members = db.prepare(`
    SELECT u.id, u.username FROM session_members sm
    JOIN users u ON u.id = sm.user_id
    WHERE sm.session_id = ?
  `).all(sessionId);

  const suggestions = db.prepare(`
    SELECT ss.id, ss.place, ss.place_id, ss.restaurant_type, ss.lat, ss.lng, ss.user_id,
           u.username AS suggested_by,
           (SELECT COUNT(*) FROM session_votes sv WHERE sv.suggestion_id = ss.id) AS vote_count
    FROM session_suggestions ss
    JOIN users u ON u.id = ss.user_id
    WHERE ss.session_id = ?
  `).all(sessionId);

  const userVotes = db.prepare('SELECT suggestion_id FROM session_votes WHERE session_id = ? AND user_id = ?').all(sessionId, req.user.id);
  const votedIds = new Set(userVotes.map(v => v.suggestion_id));

  res.json({
    session,
    members,
    suggestions: suggestions.map(s => ({ ...s, user_voted: votedIds.has(s.id) })),
  });
});

app.post('/api/sessions/:id/suggest', auth, async (req, res) => {
  const sessionId = req.params.id;
  const { place, place_id, restaurant_type } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(sessionId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const session = db.prepare("SELECT status FROM sessions WHERE id = ?").get(sessionId);
  if (!session || session.status !== 'open') return res.status(400).json({ error: 'Session is closed' });

  let lat = null, lng = null;
  if (place_id) {
    try {
      const url = new URL('https://maps.googleapis.com/maps/api/place/details/json');
      url.searchParams.set('place_id', place_id);
      url.searchParams.set('fields', 'geometry');
      url.searchParams.set('key', API_KEY);
      const r = await fetch(url);
      const data = await r.json();
      if (data.result?.geometry?.location) {
        lat = data.result.geometry.location.lat;
        lng = data.result.geometry.location.lng;
      }
    } catch (e) {
      console.error('Failed to fetch place details:', e.message);
    }
  }

  try {
    const result = db.prepare('INSERT OR IGNORE INTO session_suggestions (session_id, user_id, place, place_id, restaurant_type, lat, lng) VALUES (?, ?, ?, ?, ?, ?, ?)').run(sessionId, req.user.id, place, place_id || null, restaurant_type || null, lat, lng);
    if (result.changes === 0) return res.status(409).json({ error: 'Already suggested' });
    io.to(`session:${sessionId}`).emit('session:suggestion-added', {
      id: result.lastInsertRowid, place, place_id: place_id || null,
      restaurant_type: restaurant_type || null,
      lat, lng, suggested_by: req.user.username, vote_count: 0, user_voted: false,
    });
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (err) {
    res.status(500).json({ error: 'Failed to suggest' });
  }
});

app.post('/api/sessions/:id/vote', auth, (req, res) => {
  const sessionId = req.params.id;
  const { suggestion_id } = req.body;
  if (!suggestion_id) return res.status(400).json({ error: 'Missing suggestion_id' });

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(sessionId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  db.prepare('INSERT OR IGNORE INTO session_votes (session_id, user_id, suggestion_id) VALUES (?, ?, ?)').run(sessionId, req.user.id, suggestion_id);
  const count = db.prepare('SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ?').get(suggestion_id);
  io.to(`session:${sessionId}`).emit('session:vote-updated', { suggestion_id, vote_count: count.c, user_id: req.user.id, action: 'vote' });
  res.json({ success: true });
});

app.post('/api/sessions/:id/unvote', auth, (req, res) => {
  const sessionId = req.params.id;
  const { suggestion_id } = req.body;
  if (!suggestion_id) return res.status(400).json({ error: 'Missing suggestion_id' });

  db.prepare('DELETE FROM session_votes WHERE session_id = ? AND user_id = ? AND suggestion_id = ?').run(sessionId, req.user.id, suggestion_id);
  const count = db.prepare('SELECT COUNT(*) AS c FROM session_votes WHERE suggestion_id = ?').get(suggestion_id);
  io.to(`session:${sessionId}`).emit('session:vote-updated', { suggestion_id, vote_count: count.c, user_id: req.user.id, action: 'unvote' });
  res.json({ success: true });
});

app.post('/api/sessions/:id/pick', auth, (req, res) => {
  const sessionId = req.params.id;
  const { mode, lat, lng } = req.body;

  const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(sessionId, req.user.id);
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const suggestions = db.prepare(`
    SELECT ss.id, ss.place, ss.place_id, ss.lat, ss.lng,
           (SELECT COUNT(*) FROM session_votes sv WHERE sv.suggestion_id = ss.id) AS vote_count
    FROM session_suggestions ss
    WHERE ss.session_id = ?
  `).all(sessionId);

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
    const weighted = [];
    suggestions.forEach(s => {
      const weight = Math.max(s.vote_count, 1);
      for (let i = 0; i < weight; i++) weighted.push(s);
    });
    winner = weighted[Math.floor(Math.random() * weighted.length)];
  }

  db.prepare('UPDATE sessions SET winner_place = ?, picked_at = datetime(?) WHERE id = ?').run(winner.place, 'now', sessionId);
  io.to(`session:${sessionId}`).emit('session:winner-picked', { winner });
  res.json({ winner });
});

app.post('/api/sessions/:id/close', auth, (req, res) => {
  const sessionId = req.params.id;
  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  if (session.creator_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can close this session' });

  db.prepare("UPDATE sessions SET status = 'closed' WHERE id = ?").run(sessionId);
  io.to(`session:${sessionId}`).emit('session:closed', { sessionId });
  res.json({ success: true });
});

app.delete('/api/sessions/:id', auth, (req, res) => {
  const sessionId = req.params.id;
  const session = db.prepare('SELECT * FROM sessions WHERE id = ?').get(sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  if (session.creator_id !== req.user.id) return res.status(403).json({ error: 'Only the creator can delete this session' });
  if (session.status !== 'closed') return res.status(400).json({ error: 'Session must be closed before deleting' });

  const deleteAll = db.transaction(() => {
    db.prepare('DELETE FROM session_votes WHERE session_id = ?').run(sessionId);
    db.prepare('DELETE FROM session_suggestions WHERE session_id = ?').run(sessionId);
    db.prepare('DELETE FROM session_members WHERE session_id = ?').run(sessionId);
    db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
  });
  deleteAll();

  io.to(`session:${sessionId}`).emit('session:deleted', { sessionId: Number(sessionId) });
  res.json({ success: true });
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
  socket.on('join-session', (sessionId) => {
    const membership = db.prepare('SELECT 1 FROM session_members WHERE session_id = ? AND user_id = ?').get(sessionId, socket.user.id);
    if (membership) {
      socket.join(`session:${sessionId}`);
    }
  });

  socket.on('leave-session', (sessionId) => {
    socket.leave(`session:${sessionId}`);
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

module.exports = { app, server, io, db, haversine, generateSessionCode };
