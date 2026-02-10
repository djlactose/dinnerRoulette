// API integration tests

process.env.GOOGLE_API_KEY = 'test-key';
process.env.JWT_SECRET = 'test-secret';
process.env.DB_PATH = ':memory:';
process.env.NODE_ENV = 'test';

const request = require('supertest');
const { app, db, server, io } = require('../server');

afterAll(() => {
  io.close();
  server.close();
  db.close();
});

// Helper to register and get cookie
async function registerUser(username, password) {
  const res = await request(app)
    .post('/api/register')
    .send({ username, password, remember: true });
  const cookie = res.headers['set-cookie'];
  return { res, cookie };
}

// ── Auth Tests ──────────────────────────────────────────────────────────────────

describe('Auth', () => {
  test('POST /api/register — valid credentials', async () => {
    const { res } = await registerUser('alice', 'password123');
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('alice');
    expect(res.headers['set-cookie']).toBeDefined();
  });

  test('POST /api/register — short username rejected', async () => {
    const res = await request(app)
      .post('/api/register')
      .send({ username: 'ab', password: 'password123' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/3 characters/);
  });

  test('POST /api/register — short password rejected', async () => {
    const res = await request(app)
      .post('/api/register')
      .send({ username: 'testuser', password: '12345' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/6 characters/);
  });

  test('POST /api/register — duplicate username rejected', async () => {
    await registerUser('dupuser', 'password123');
    const res = await request(app)
      .post('/api/register')
      .send({ username: 'dupuser', password: 'password456' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/taken/i);
  });

  test('POST /api/login — correct credentials', async () => {
    await registerUser('loginuser', 'mypassword');
    const res = await request(app)
      .post('/api/login')
      .send({ username: 'loginuser', password: 'mypassword' });
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('loginuser');
    expect(res.headers['set-cookie']).toBeDefined();
  });

  test('POST /api/login — wrong password', async () => {
    await registerUser('wrongpw', 'correctpass');
    const res = await request(app)
      .post('/api/login')
      .send({ username: 'wrongpw', password: 'wrongpass' });
    expect(res.status).toBe(401);
  });

  test('GET /api/me — without auth returns 401', async () => {
    const res = await request(app).get('/api/me');
    expect(res.status).toBe(401);
  });

  test('GET /api/me — with auth returns user info', async () => {
    const { cookie } = await registerUser('meuser', 'password123');
    const res = await request(app)
      .get('/api/me')
      .set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('meuser');
    expect(res.body.id).toBeDefined();
  });

  test('POST /api/logout — clears cookie', async () => {
    const res = await request(app).post('/api/logout');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

// ── Health Check ────────────────────────────────────────────────────────────────

describe('Health', () => {
  test('GET /health — returns ok', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.uptime).toBeDefined();
  });
});

// ── Places Tests ────────────────────────────────────────────────────────────────

describe('Places', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('placeuser', 'password123');
    cookie = result.cookie;
  });

  test('POST /api/places — like a place', async () => {
    const res = await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'likes', place: 'Pizza Palace', place_id: 'pp123' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('POST /api/places — dislike a place', async () => {
    const res = await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'dislikes', place: 'Bad Burger', place_id: 'bb456' });
    expect(res.status).toBe(200);
  });

  test('GET /api/places — returns liked and disliked', async () => {
    const res = await request(app)
      .get('/api/places')
      .set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.likes.some(p => p.name === 'Pizza Palace')).toBe(true);
    expect(res.body.dislikes.some(p => p.name === 'Bad Burger')).toBe(true);
  });

  test('POST /api/places — remove a liked place', async () => {
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'likes', place: 'To Remove', place_id: 'tr789' });

    await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'likes', place: 'To Remove', remove: true });

    const res = await request(app)
      .get('/api/places')
      .set('Cookie', cookie);
    expect(res.body.likes.some(p => p.name === 'To Remove')).toBe(false);
  });
});

// ── Suggestions Tests ───────────────────────────────────────────────────────────

describe('Suggestions', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('suggestuser', 'password123');
    cookie = result.cookie;
  });

  test('POST /api/suggest — add a suggestion', async () => {
    const res = await request(app)
      .post('/api/suggest')
      .set('Cookie', cookie)
      .send({ place: 'Taco Town', place_id: 'tt001' });
    expect(res.status).toBe(200);
  });

  test('GET /api/suggestions — returns suggestions', async () => {
    const res = await request(app)
      .get('/api/suggestions')
      .set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.suggestions).toContain('Taco Town');
  });

  test('POST /api/suggestions/remove — removes suggestion', async () => {
    await request(app)
      .post('/api/suggestions/remove')
      .set('Cookie', cookie)
      .send({ place: 'Taco Town' });

    const res = await request(app)
      .get('/api/suggestions')
      .set('Cookie', cookie);
    expect(res.body.suggestions).not.toContain('Taco Town');
  });
});

// ── Friends Tests ───────────────────────────────────────────────────────────────

describe('Friends', () => {
  let cookie1, cookie2;

  beforeAll(async () => {
    const r1 = await registerUser('frienduser1', 'password123');
    cookie1 = r1.cookie;
    const r2 = await registerUser('frienduser2', 'password123');
    cookie2 = r2.cookie;
  });

  test('POST /api/invite — invite a friend', async () => {
    const res = await request(app)
      .post('/api/invite')
      .set('Cookie', cookie1)
      .send({ friendUsername: 'frienduser2' });
    expect(res.status).toBe(200);
  });

  test('GET /api/friends — returns friends list', async () => {
    const res = await request(app)
      .get('/api/friends')
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.friends.some(f => f.username === 'frienduser2')).toBe(true);
  });

  test('POST /api/invite — duplicate invite is ignored', async () => {
    const res = await request(app)
      .post('/api/invite')
      .set('Cookie', cookie1)
      .send({ friendUsername: 'frienduser2' });
    expect(res.status).toBe(200);

    const friends = await request(app)
      .get('/api/friends')
      .set('Cookie', cookie1);
    const count = friends.body.friends.filter(f => f.username === 'frienduser2').length;
    expect(count).toBe(1);
  });

  test('POST /api/invite — cannot add self', async () => {
    const res = await request(app)
      .post('/api/invite')
      .set('Cookie', cookie1)
      .send({ friendUsername: 'frienduser1' });
    expect(res.status).toBe(400);
  });

  test('GET /api/common-places — returns shared likes', async () => {
    // Both users like the same place
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie1)
      .send({ type: 'likes', place: 'Shared Sushi' });
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie2)
      .send({ type: 'likes', place: 'Shared Sushi' });

    const res = await request(app)
      .get('/api/common-places')
      .set('Cookie', cookie1)
      .query({ friendUsername: 'frienduser2' });
    expect(res.status).toBe(200);
    expect(res.body.common).toContain('Shared Sushi');
  });
});

// ── Session Tests ───────────────────────────────────────────────────────────────

describe('Sessions', () => {
  let cookie1, cookie2;
  let sessionId, sessionCode;

  beforeAll(async () => {
    const r1 = await registerUser('sessuser1', 'password123');
    cookie1 = r1.cookie;
    const r2 = await registerUser('sessuser2', 'password123');
    cookie2 = r2.cookie;
  });

  test('POST /api/sessions — create a session', async () => {
    const res = await request(app)
      .post('/api/sessions')
      .set('Cookie', cookie1)
      .send({ name: 'Friday Dinner' });
    expect(res.status).toBe(200);
    expect(res.body.code).toHaveLength(6);
    expect(res.body.name).toBe('Friday Dinner');
    sessionId = res.body.id;
    sessionCode = res.body.code;
  });

  test('POST /api/sessions/join — join by code', async () => {
    const res = await request(app)
      .post('/api/sessions/join')
      .set('Cookie', cookie2)
      .send({ code: sessionCode });
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(sessionId);
  });

  test('POST /api/sessions/join — invalid code returns 404', async () => {
    const res = await request(app)
      .post('/api/sessions/join')
      .set('Cookie', cookie2)
      .send({ code: 'XXXXXX' });
    expect(res.status).toBe(404);
  });

  test('GET /api/sessions — list sessions', async () => {
    const res = await request(app)
      .get('/api/sessions')
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.sessions.some(s => s.id === sessionId)).toBe(true);
  });

  test('GET /api/sessions/:id — session details include both members', async () => {
    const res = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.members).toHaveLength(2);
    expect(res.body.session.status).toBe('open');
  });

  test('GET /api/sessions/:id — non-member gets 403', async () => {
    const r3 = await registerUser('outsider', 'password123');
    const res = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', r3.cookie);
    expect(res.status).toBe(403);
  });

  test('POST /api/sessions/:id/suggest — add suggestion', async () => {
    const res = await request(app)
      .post(`/api/sessions/${sessionId}/suggest`)
      .set('Cookie', cookie1)
      .send({ place: 'Test Restaurant', place_id: null });
    expect(res.status).toBe(200);
    expect(res.body.id).toBeDefined();
  });

  test('POST /api/sessions/:id/suggest — duplicate rejected', async () => {
    const res = await request(app)
      .post(`/api/sessions/${sessionId}/suggest`)
      .set('Cookie', cookie2)
      .send({ place: 'Test Restaurant' });
    expect(res.status).toBe(409);
  });

  test('POST /api/sessions/:id/vote — vote on suggestion', async () => {
    const detail = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    const res = await request(app)
      .post(`/api/sessions/${sessionId}/vote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });
    expect(res.status).toBe(200);

    // Verify vote count
    const updated = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.vote_count).toBe(1);
    expect(s.user_voted).toBe(true);
  });

  test('POST /api/sessions/:id/vote — double vote has no effect', async () => {
    const detail = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    await request(app)
      .post(`/api/sessions/${sessionId}/vote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });

    const updated = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.vote_count).toBe(1);
  });

  test('POST /api/sessions/:id/unvote — removes vote', async () => {
    const detail = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    const res = await request(app)
      .post(`/api/sessions/${sessionId}/unvote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });
    expect(res.status).toBe(200);

    const updated = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.vote_count).toBe(0);
    expect(s.user_voted).toBe(false);
  });

  test('POST /api/sessions/:id/pick — random pick returns winner', async () => {
    const res = await request(app)
      .post(`/api/sessions/${sessionId}/pick`)
      .set('Cookie', cookie1)
      .send({ mode: 'random' });
    expect(res.status).toBe(200);
    expect(res.body.winner.place).toBe('Test Restaurant');
  });

  test('POST /api/sessions/:id/close — non-creator gets 403', async () => {
    const res = await request(app)
      .post(`/api/sessions/${sessionId}/close`)
      .set('Cookie', cookie2);
    expect(res.status).toBe(403);
  });

  test('POST /api/sessions/:id/close — creator can close', async () => {
    const res = await request(app)
      .post(`/api/sessions/${sessionId}/close`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);

    const detail = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    expect(detail.body.session.status).toBe('closed');
  });
});

// ── Account Management Tests ────────────────────────────────────────────────────

describe('Account', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('acctuser', 'oldpassword');
    cookie = result.cookie;
  });

  test('POST /api/change-password — changes password', async () => {
    const res = await request(app)
      .post('/api/change-password')
      .set('Cookie', cookie)
      .send({ currentPassword: 'oldpassword', newPassword: 'newpassword' });
    expect(res.status).toBe(200);

    // Old password fails
    const loginOld = await request(app)
      .post('/api/login')
      .send({ username: 'acctuser', password: 'oldpassword' });
    expect(loginOld.status).toBe(401);

    // New password works
    const loginNew = await request(app)
      .post('/api/login')
      .send({ username: 'acctuser', password: 'newpassword' });
    expect(loginNew.status).toBe(200);
  });

  test('POST /api/change-password — wrong current password', async () => {
    const res = await request(app)
      .post('/api/change-password')
      .set('Cookie', cookie)
      .send({ currentPassword: 'wrongpass', newPassword: 'newpassword' });
    expect(res.status).toBe(401);
  });

  test('POST /api/delete-account — deletes all user data', async () => {
    const { cookie: delCookie } = await registerUser('todelete', 'password123');

    // Add some data first
    await request(app)
      .post('/api/places')
      .set('Cookie', delCookie)
      .send({ type: 'likes', place: 'Doomed Place' });

    const res = await request(app)
      .post('/api/delete-account')
      .set('Cookie', delCookie)
      .send({ password: 'password123' });
    expect(res.status).toBe(200);

    // Login should fail
    const login = await request(app)
      .post('/api/login')
      .send({ username: 'todelete', password: 'password123' });
    expect(login.status).toBe(401);
  });
});
