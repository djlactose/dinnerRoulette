const express = require('express');
const axios   = require('axios');
const path    = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

const app       = express();
const API_KEY   = process.env.GOOGLE_API_KEY;
const JWT_SECRET= process.env.JWT_SECRET || 'change_this';

if (!API_KEY) {
  console.error('ERROR: GOOGLE_API_KEY not set');
  process.exit(1);
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./data/db.sqlite');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS friends (
    user_id INTEGER,
    friend_id INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS likes (
    user_id INTEGER,
    place TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS dislikes (
    user_id INTEGER,
    place TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS places (
    user_id INTEGER,
    place TEXT,
    UNIQUE(user_id, place)
  )`);
});

function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
}
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Missing auth header' });
  const token = h.replace('Bearer ', '');
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = payload;
    next();
  });
}

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).end();
  const hash = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users(username,password) VALUES(?,?)`, [username, hash], function(err) {
    if (err) return res.status(400).json({ error: 'Username taken' });
    res.json({ token: generateToken({ id: this.lastID, username }) });
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (!user) return res.status(401).json({ error: 'User not found' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Bad password' });
    res.json({ token: generateToken(user) });
  });
});

app.get('/api/autocomplete', auth, async (req, res) => {
  try {
    const { input } = req.query;
    const r = await axios.get(
      'https://maps.googleapis.com/maps/api/place/autocomplete/json',
      { params: { input, types: 'establishment', key: API_KEY } }
    );
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: 'Proxy error' });
  }
});

// Save any selected place
app.post('/api/place', auth, (req, res) => {
  const { place } = req.body;
  if (!place) return res.status(400).json({ error: 'Missing place' });

  db.run(`INSERT OR IGNORE INTO places(user_id, place) VALUES(?, ?)`, [req.user.id, place], () => {
    res.json({ success: true });
  });
});

// Likes, Dislikes, All
app.get('/api/places', auth, (req, res) => {
  const uid = req.user.id;
  db.all(`SELECT place FROM likes WHERE user_id = ?`, [uid], (e, likes) => {
    db.all(`SELECT place FROM dislikes WHERE user_id = ?`, [uid], (e2, dislikes) => {
      db.all(`SELECT place FROM places WHERE user_id = ?`, [uid], (e3, all) => {
        res.json({
          likes: likes.map(r => r.place),
          dislikes: dislikes.map(r => r.place),
          all: all.map(r => r.place)
        });
      });
    });
  });
});

app.post('/api/places', auth, (req, res) => {
  const { type, place, remove } = req.body;
  const tbl = type === 'likes' ? 'likes' : 'dislikes';
  if (!place) return res.status(400).json({ error: 'Missing place' });

  if (remove) {
    db.run(`DELETE FROM ${tbl} WHERE user_id = ? AND place = ?`, [req.user.id, place], () => {
      res.json({ success: true });
    });
  } else {
    db.run(`INSERT OR IGNORE INTO places(user_id, place) VALUES(?, ?)`, [req.user.id, place], () => {
      db.run(`INSERT INTO ${tbl}(user_id, place) VALUES(?, ?)`, [req.user.id, place], () => {
        res.json({ success: true });
      });
    });
  }
});

app.post('/api/invite', auth, (req, res) => {
  const { friendUsername } = req.body;
  db.get(`SELECT id FROM users WHERE username = ?`, [friendUsername], (err, row) => {
    if (!row) return res.status(404).json({ error: 'No such user' });
    db.run(`INSERT INTO friends(user_id, friend_id) VALUES(?,?)`, [req.user.id, row.id], () => {
      res.json({ success: true });
    });
  });
});

app.get('/api/common-places', auth, (req, res) => {
  const friend = req.query.friendUsername;
  db.get(`SELECT id FROM users WHERE username = ?`, [friend], (e, row) => {
    if (!row) return res.status(404).json({ error: 'No such friend' });
    db.all(`
      SELECT l1.place FROM likes l1
      JOIN likes l2 ON l2.place = l1.place
      WHERE l1.user_id = ? AND l2.user_id = ?
    `, [req.user.id, row.id], (e2, commons) => {
      res.json({ common: commons.map(r => r.place) });
    });
  });
});

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
