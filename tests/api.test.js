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

// ── Want to Try Tests ────────────────────────────────────────────────────────────

describe('Want to Try', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('wttuser', 'password123');
    cookie = result.cookie;
  });

  test('POST /api/places — add to want_to_try', async () => {
    const res = await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'want_to_try', place: 'Fancy Sushi', place_id: 'fs123', restaurant_type: 'Japanese Restaurant' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('GET /api/places — returns want_to_try list', async () => {
    const res = await request(app)
      .get('/api/places')
      .set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.want_to_try).toBeDefined();
    expect(res.body.want_to_try.some(p => p.name === 'Fancy Sushi')).toBe(true);
  });

  test('POST /api/places — want_to_try is independent from likes', async () => {
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'likes', place: 'Fancy Sushi', place_id: 'fs123' });
    const res = await request(app)
      .get('/api/places')
      .set('Cookie', cookie);
    expect(res.body.likes.some(p => p.name === 'Fancy Sushi')).toBe(true);
    expect(res.body.want_to_try.some(p => p.name === 'Fancy Sushi')).toBe(true);
  });

  test('POST /api/places — want_to_try removes dislikes', async () => {
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'dislikes', place: 'Disliked Place', place_id: 'dp123' });
    const res = await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'want_to_try', place: 'Disliked Place', place_id: 'dp123' });
    expect(res.body.movedFrom).toBe('dislikes');

    const placesRes = await request(app)
      .get('/api/places')
      .set('Cookie', cookie);
    expect(placesRes.body.dislikes.some(p => p.name === 'Disliked Place')).toBe(false);
    expect(placesRes.body.want_to_try.some(p => p.name === 'Disliked Place')).toBe(true);
  });

  test('POST /api/places — remove from want_to_try', async () => {
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'want_to_try', place: 'Remove Me', place_id: 'rm123' });
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'want_to_try', place: 'Remove Me', remove: true });

    const res = await request(app)
      .get('/api/places')
      .set('Cookie', cookie);
    expect(res.body.want_to_try.some(p => p.name === 'Remove Me')).toBe(false);
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
    expect(res.body.suggestions).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'Taco Town' })])
    );
  });

  test('POST /api/suggestions/remove — removes suggestion', async () => {
    await request(app)
      .post('/api/suggestions/remove')
      .set('Cookie', cookie)
      .send({ place: 'Taco Town' });

    const res = await request(app)
      .get('/api/suggestions')
      .set('Cookie', cookie);
    expect(res.body.suggestions).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'Taco Town' })])
    );
  });
});

// ── Friends Tests ───────────────────────────────────────────────────────────────

describe('Friends', () => {
  let cookie1, cookie2, cookie3;
  let user2Id;

  beforeAll(async () => {
    const r1 = await registerUser('frienduser1', 'password123');
    cookie1 = r1.cookie;
    const r2 = await registerUser('frienduser2', 'password123');
    cookie2 = r2.cookie;
    // Get user2's id
    const me = await request(app).get('/api/me').set('Cookie', cookie2);
    user2Id = me.body.id;
    const r3 = await registerUser('frienduser3', 'password123');
    cookie3 = r3.cookie;
  });

  test('POST /api/invite — creates pending request (sender does NOT see friend yet)', async () => {
    const res = await request(app)
      .post('/api/invite')
      .set('Cookie', cookie1)
      .send({ friendUsername: 'frienduser2' });
    expect(res.status).toBe(200);

    // Sender should NOT see frienduser2 in friends list (still pending)
    const friends = await request(app)
      .get('/api/friends')
      .set('Cookie', cookie1);
    expect(friends.body.friends.some(f => f.username === 'frienduser2')).toBe(false);
  });

  test('GET /api/friend-requests — recipient sees pending request', async () => {
    const res = await request(app)
      .get('/api/friend-requests')
      .set('Cookie', cookie2);
    expect(res.status).toBe(200);
    expect(res.body.requests.some(r => r.username === 'frienduser1')).toBe(true);
  });

  test('POST /api/invite — duplicate invite is ignored', async () => {
    const res = await request(app)
      .post('/api/invite')
      .set('Cookie', cookie1)
      .send({ friendUsername: 'frienduser2' });
    expect(res.status).toBe(200);
  });

  test('POST /api/invite — cannot add self', async () => {
    const res = await request(app)
      .post('/api/invite')
      .set('Cookie', cookie1)
      .send({ friendUsername: 'frienduser1' });
    expect(res.status).toBe(400);
  });

  test('POST /api/friend-requests/:id/accept — both users become friends', async () => {
    // Get frienduser1's id
    const me1 = await request(app).get('/api/me').set('Cookie', cookie1);
    const user1Id = me1.body.id;

    const res = await request(app)
      .post(`/api/friend-requests/${user1Id}/accept`)
      .set('Cookie', cookie2);
    expect(res.status).toBe(200);

    // Both users should see each other as friends
    const friends1 = await request(app).get('/api/friends').set('Cookie', cookie1);
    expect(friends1.body.friends.some(f => f.username === 'frienduser2')).toBe(true);

    const friends2 = await request(app).get('/api/friends').set('Cookie', cookie2);
    expect(friends2.body.friends.some(f => f.username === 'frienduser1')).toBe(true);

    // No more pending requests for user2
    const reqs = await request(app).get('/api/friend-requests').set('Cookie', cookie2);
    expect(reqs.body.requests.some(r => r.username === 'frienduser1')).toBe(false);
  });

  test('POST /api/friend-requests/:id/reject — request removed, no friendship', async () => {
    // frienduser3 sends request to frienduser2
    await request(app)
      .post('/api/invite')
      .set('Cookie', cookie3)
      .send({ friendUsername: 'frienduser2' });

    const me3 = await request(app).get('/api/me').set('Cookie', cookie3);
    const user3Id = me3.body.id;

    const res = await request(app)
      .post(`/api/friend-requests/${user3Id}/reject`)
      .set('Cookie', cookie2);
    expect(res.status).toBe(200);

    // frienduser3 should NOT appear in frienduser2's friends
    const friends = await request(app).get('/api/friends').set('Cookie', cookie2);
    expect(friends.body.friends.some(f => f.username === 'frienduser3')).toBe(false);

    // No pending request either
    const reqs = await request(app).get('/api/friend-requests').set('Cookie', cookie2);
    expect(reqs.body.requests.some(r => r.username === 'frienduser3')).toBe(false);
  });

  test('GET /api/friends/:id/likes — returns friend likes', async () => {
    // frienduser2 likes a place
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie2)
      .send({ type: 'likes', place: 'Friend Falafel', place_id: 'ff001', restaurant_type: 'Restaurant' });

    const res = await request(app)
      .get(`/api/friends/${user2Id}/likes`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.likes.some(l => l.name === 'Friend Falafel')).toBe(true);
  });

  test('GET /api/friends/:id/likes — non-friend gets 403', async () => {
    const res = await request(app)
      .get(`/api/friends/${user2Id}/likes`)
      .set('Cookie', cookie3);
    expect(res.status).toBe(403);
  });

  test('POST /api/invite — auto-accepts if reverse pending request exists', async () => {
    // Register fresh users for this test
    const r4 = await registerUser('autouser1', 'password123');
    const r5 = await registerUser('autouser2', 'password123');

    // autouser1 sends request to autouser2
    await request(app)
      .post('/api/invite')
      .set('Cookie', r4.cookie)
      .send({ friendUsername: 'autouser2' });

    // autouser2 sends request to autouser1 — should auto-accept
    const res = await request(app)
      .post('/api/invite')
      .set('Cookie', r5.cookie)
      .send({ friendUsername: 'autouser1' });
    expect(res.status).toBe(200);
    expect(res.body.autoAccepted).toBe(true);

    // Both should be friends
    const friends4 = await request(app).get('/api/friends').set('Cookie', r4.cookie);
    expect(friends4.body.friends.some(f => f.username === 'autouser2')).toBe(true);

    const friends5 = await request(app).get('/api/friends').set('Cookie', r5.cookie);
    expect(friends5.body.friends.some(f => f.username === 'autouser1')).toBe(true);
  });

  test('GET /api/common-places — works for accepted friends', async () => {
    // Both frienduser1 and frienduser2 like the same place
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

  test('GET /api/common-places — non-friend gets 403', async () => {
    const res = await request(app)
      .get('/api/common-places')
      .set('Cookie', cookie3)
      .query({ friendUsername: 'frienduser2' });
    expect(res.status).toBe(403);
  });

  test('DELETE /api/friends/:id — removes friendship both ways', async () => {
    // frienduser1 and frienduser2 are already friends from earlier test
    const res = await request(app)
      .delete(`/api/friends/${user2Id}`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);

    // Neither should see the other as a friend
    const friends1 = await request(app).get('/api/friends').set('Cookie', cookie1);
    expect(friends1.body.friends.some(f => f.username === 'frienduser2')).toBe(false);

    const friends2 = await request(app).get('/api/friends').set('Cookie', cookie2);
    expect(friends2.body.friends.some(f => f.username === 'frienduser1')).toBe(false);
  });

  test('DELETE /api/friends/:id — non-friend returns 404', async () => {
    const res = await request(app)
      .delete(`/api/friends/${user2Id}`)
      .set('Cookie', cookie3);
    expect(res.status).toBe(404);
  });

  test('DELETE /api/friends/:id — unauthenticated returns 401', async () => {
    const res = await request(app).delete(`/api/friends/${user2Id}`);
    expect(res.status).toBe(401);
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

  test('GET /api/sessions/:id — includes want_to_try matches', async () => {
    // Add "Test Restaurant" to sessuser1's want-to-try list
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie1)
      .send({ type: 'want_to_try', place: 'Test Restaurant' });

    const res = await request(app)
      .get(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.want_to_try).toBeDefined();
    expect(res.body.want_to_try['Test Restaurant']).toBeDefined();
    expect(res.body.want_to_try['Test Restaurant'].some(u => u.username === 'sessuser1')).toBe(true);
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

  test('DELETE /api/sessions/:id — non-creator gets 403', async () => {
    const res = await request(app)
      .delete(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie2);
    expect(res.status).toBe(403);
  });

  test('DELETE /api/sessions/:id — creator can delete closed session', async () => {
    const res = await request(app)
      .delete(`/api/sessions/${sessionId}`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);

    // Session no longer appears in list
    const list = await request(app)
      .get('/api/sessions')
      .set('Cookie', cookie1);
    expect(list.body.sessions.some(s => s.id === sessionId)).toBe(false);
  });

  test('DELETE /api/sessions/:id — cannot delete open session', async () => {
    // Create a new session (defaults to open)
    const create = await request(app)
      .post('/api/sessions')
      .set('Cookie', cookie1)
      .send({ name: 'Open Session' });
    const openId = create.body.id;

    const res = await request(app)
      .delete(`/api/sessions/${openId}`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(400);
  });

  test('GET /api/sessions — includes creator_username', async () => {
    const res = await request(app)
      .get('/api/sessions')
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.sessions.length).toBeGreaterThan(0);
    expect(res.body.sessions[0].creator_username).toBe('sessuser1');
  });

  test('GET /api/sessions — includes member_count and suggestion_count', async () => {
    const res = await request(app)
      .get('/api/sessions')
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.sessions.length).toBeGreaterThan(0);
    expect(typeof res.body.sessions[0].member_count).toBe('number');
    expect(typeof res.body.sessions[0].suggestion_count).toBe('number');
  });

  test('POST /api/sessions/:id/invite — invites a user by username', async () => {
    const create = await request(app).post('/api/sessions').set('Cookie', cookie1)
      .send({ name: 'Invite Test' });
    const sid = create.body.id;
    const res = await request(app).post(`/api/sessions/${sid}/invite`).set('Cookie', cookie1)
      .send({ username: 'sessuser2' });
    expect(res.status).toBe(200);
    const detail = await request(app).get(`/api/sessions/${sid}`).set('Cookie', cookie2);
    expect(detail.status).toBe(200);
    expect(detail.body.members.some(m => m.username === 'sessuser2')).toBe(true);
  });

  test('POST /api/sessions/:id/invite — non-existent user returns 404', async () => {
    const create = await request(app).post('/api/sessions').set('Cookie', cookie1)
      .send({ name: 'Invite Fail' });
    const res = await request(app).post(`/api/sessions/${create.body.id}/invite`).set('Cookie', cookie1)
      .send({ username: 'nonexistent_user_xyz' });
    expect(res.status).toBe(404);
  });

  test('GET /api/sessions/:id/dislikes — returns disliked places by members', async () => {
    await request(app).post('/api/places').set('Cookie', cookie1)
      .send({ type: 'dislikes', place: 'Hated Diner' });
    const create = await request(app).post('/api/sessions').set('Cookie', cookie1)
      .send({ name: 'Dislike Test' });
    const res = await request(app).get(`/api/sessions/${create.body.id}/dislikes`).set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.dislikes).toContain('Hated Diner');
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

// ── Visited Tracking Tests ───────────────────────────────────────────────────

describe('Visited Tracking', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('visituser', 'password123');
    cookie = result.cookie;
    // Like a place first
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie)
      .send({ type: 'likes', place: 'Visit Cafe', place_id: 'vc001' });
  });

  test('POST /api/places/visit — marks a liked place as visited', async () => {
    const res = await request(app)
      .post('/api/places/visit')
      .set('Cookie', cookie)
      .send({ place: 'Visit Cafe' });
    expect(res.status).toBe(200);

    const places = await request(app).get('/api/places').set('Cookie', cookie);
    const cafe = places.body.likes.find(p => p.name === 'Visit Cafe');
    expect(cafe.visited_at).toBeTruthy();
  });

  test('POST /api/places/visit — non-liked place returns 404', async () => {
    const res = await request(app)
      .post('/api/places/visit')
      .set('Cookie', cookie)
      .send({ place: 'Unknown Place' });
    expect(res.status).toBe(404);
  });

  test('POST /api/places/visit — missing place returns 400', async () => {
    const res = await request(app)
      .post('/api/places/visit')
      .set('Cookie', cookie)
      .send({});
    expect(res.status).toBe(400);
  });

  test('POST /api/places/unvisit — clears visited_at', async () => {
    const res = await request(app)
      .post('/api/places/unvisit')
      .set('Cookie', cookie)
      .send({ place: 'Visit Cafe' });
    expect(res.status).toBe(200);

    const places = await request(app).get('/api/places').set('Cookie', cookie);
    const cafe = places.body.likes.find(p => p.name === 'Visit Cafe');
    expect(cafe.visited_at).toBeNull();
  });

  test('POST /api/places/visit — unauthenticated returns 401', async () => {
    const res = await request(app)
      .post('/api/places/visit')
      .send({ place: 'Visit Cafe' });
    expect(res.status).toBe(401);
  });
});

// ── Place Notes Tests ────────────────────────────────────────────────────────

describe('Place Notes', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('noteuser', 'password123');
    cookie = result.cookie;
    await request(app).post('/api/places').set('Cookie', cookie)
      .send({ type: 'likes', place: 'Note Cafe', place_id: 'nc001' });
  });

  test('POST /api/places/notes — saves note on liked place', async () => {
    const res = await request(app).post('/api/places/notes').set('Cookie', cookie)
      .send({ place: 'Note Cafe', notes: 'Great coffee' });
    expect(res.status).toBe(200);
    const places = await request(app).get('/api/places').set('Cookie', cookie);
    const cafe = places.body.likes.find(p => p.name === 'Note Cafe');
    expect(cafe.notes).toBe('Great coffee');
  });

  test('POST /api/places/notes — non-liked place returns 404', async () => {
    const res = await request(app).post('/api/places/notes').set('Cookie', cookie)
      .send({ place: 'Unknown', notes: 'test' });
    expect(res.status).toBe(404);
  });

  test('POST /api/places/notes — clears note when empty', async () => {
    await request(app).post('/api/places/notes').set('Cookie', cookie)
      .send({ place: 'Note Cafe', notes: '' });
    const places = await request(app).get('/api/places').set('Cookie', cookie);
    const cafe = places.body.likes.find(p => p.name === 'Note Cafe');
    expect(cafe.notes).toBeNull();
  });
});

// ── Duplicate Prevention Tests ───────────────────────────────────────────────

describe('Duplicate Prevention', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('crossuser', 'password123');
    cookie = result.cookie;
  });

  test('POST /api/places — liking a disliked place removes it from dislikes', async () => {
    await request(app).post('/api/places').set('Cookie', cookie)
      .send({ type: 'dislikes', place: 'CrossPlace', place_id: 'cp001' });
    const res = await request(app).post('/api/places').set('Cookie', cookie)
      .send({ type: 'likes', place: 'CrossPlace', place_id: 'cp001' });
    expect(res.body.movedFrom).toBe('dislikes');
    const places = await request(app).get('/api/places').set('Cookie', cookie);
    expect(places.body.likes.some(p => p.name === 'CrossPlace')).toBe(true);
    expect(places.body.dislikes.some(p => p.name === 'CrossPlace')).toBe(false);
  });

  test('POST /api/places — disliking a liked place removes it from likes', async () => {
    const res = await request(app).post('/api/places').set('Cookie', cookie)
      .send({ type: 'dislikes', place: 'CrossPlace', place_id: 'cp001' });
    expect(res.body.movedFrom).toBe('likes');
    const places = await request(app).get('/api/places').set('Cookie', cookie);
    expect(places.body.dislikes.some(p => p.name === 'CrossPlace')).toBe(true);
    expect(places.body.likes.some(p => p.name === 'CrossPlace')).toBe(false);
  });
});

describe('Push Notifications', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('pushuser', 'password123');
    cookie = result.cookie;
  });

  test('GET /api/push/vapid-key — returns public key', async () => {
    const res = await request(app).get('/api/push/vapid-key');
    expect(res.statusCode).toBe(200);
    expect(typeof res.body.publicKey).toBe('string');
    expect(res.body.publicKey.length).toBeGreaterThan(10);
  });

  test('POST /api/push/subscribe — saves subscription', async () => {
    const res = await request(app).post('/api/push/subscribe').set('Cookie', cookie)
      .send({ endpoint: 'https://example.com/push/1', keys: { p256dh: 'testkey123', auth: 'testauth123' } });
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('POST /api/push/subscribe — duplicate endpoint upserts', async () => {
    const res = await request(app).post('/api/push/subscribe').set('Cookie', cookie)
      .send({ endpoint: 'https://example.com/push/1', keys: { p256dh: 'updatedkey', auth: 'updatedauth' } });
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('POST /api/push/subscribe — rejects invalid data', async () => {
    const res = await request(app).post('/api/push/subscribe').set('Cookie', cookie)
      .send({ endpoint: 'https://example.com/push/2' });
    expect(res.statusCode).toBe(400);
  });

  test('DELETE /api/push/subscribe — removes subscription', async () => {
    const res = await request(app).delete('/api/push/subscribe').set('Cookie', cookie)
      .send({ endpoint: 'https://example.com/push/1' });
    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('POST /api/push/subscribe — 401 without auth', async () => {
    const res = await request(app).post('/api/push/subscribe')
      .send({ endpoint: 'https://example.com/push/3', keys: { p256dh: 'key', auth: 'auth' } });
    expect(res.statusCode).toBe(401);
  });
});

// ── Recent Suggestions Tests ───────────────────────────────────────────────

describe('Recent Suggestions', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('recentuser', 'password123');
    cookie = result.cookie;
  });

  test('GET /api/suggestions/recent — returns empty initially', async () => {
    const res = await request(app).get('/api/suggestions/recent').set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.recent).toEqual([]);
  });

  test('GET /api/suggestions/recent — returns suggestions after adding to session', async () => {
    // Create session and suggest
    const sess = await request(app).post('/api/sessions').set('Cookie', cookie)
      .send({ name: 'Recent Test' });
    await request(app).post(`/api/sessions/${sess.body.id}/suggest`).set('Cookie', cookie)
      .send({ place: 'Recent Place 1', place_id: null });
    await request(app).post(`/api/sessions/${sess.body.id}/suggest`).set('Cookie', cookie)
      .send({ place: 'Recent Place 2', place_id: null });

    const res = await request(app).get('/api/suggestions/recent').set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.recent.length).toBe(2);
    expect(res.body.recent[0].name).toBe('Recent Place 2');
  });
});

// ── Voting Deadline Tests ──────────────────────────────────────────────────

describe('Voting Deadline', () => {
  let cookie1, cookie2, sessionId;

  beforeAll(async () => {
    const r1 = await registerUser('deadlineuser1', 'password123');
    cookie1 = r1.cookie;
    const r2 = await registerUser('deadlineuser2', 'password123');
    cookie2 = r2.cookie;
    const sess = await request(app).post('/api/sessions').set('Cookie', cookie1)
      .send({ name: 'Deadline Session' });
    sessionId = sess.body.id;
    await request(app).post('/api/sessions/join').set('Cookie', cookie2)
      .send({ code: sess.body.code });
  });

  test('POST /api/sessions/:id/deadline — creator can set deadline', async () => {
    const deadline = new Date(Date.now() + 3600000).toISOString();
    const res = await request(app).post(`/api/sessions/${sessionId}/deadline`).set('Cookie', cookie1)
      .send({ deadline });
    expect(res.status).toBe(200);

    const detail = await request(app).get(`/api/sessions/${sessionId}`).set('Cookie', cookie1);
    expect(detail.body.session.voting_deadline).toBe(deadline);
  });

  test('POST /api/sessions/:id/deadline — non-creator gets 403', async () => {
    const res = await request(app).post(`/api/sessions/${sessionId}/deadline`).set('Cookie', cookie2)
      .send({ deadline: new Date().toISOString() });
    expect(res.status).toBe(403);
  });

  test('POST /api/sessions/:id/deadline — can remove deadline', async () => {
    const res = await request(app).post(`/api/sessions/${sessionId}/deadline`).set('Cookie', cookie1)
      .send({ deadline: null });
    expect(res.status).toBe(200);

    const detail = await request(app).get(`/api/sessions/${sessionId}`).set('Cookie', cookie1);
    expect(detail.body.session.voting_deadline).toBeNull();
  });
});

// ── Session Chat Tests ─────────────────────────────────────────────────────

describe('Session Chat', () => {
  let cookie1, cookie2, sessionId;

  beforeAll(async () => {
    const r1 = await registerUser('chatuser1', 'password123');
    cookie1 = r1.cookie;
    const r2 = await registerUser('chatuser2', 'password123');
    cookie2 = r2.cookie;
    const sess = await request(app).post('/api/sessions').set('Cookie', cookie1)
      .send({ name: 'Chat Session' });
    sessionId = sess.body.id;
    await request(app).post('/api/sessions/join').set('Cookie', cookie2)
      .send({ code: sess.body.code });
  });

  test('GET /api/sessions/:id/messages — returns empty initially', async () => {
    const res = await request(app).get(`/api/sessions/${sessionId}/messages`).set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.messages).toEqual([]);
  });

  test('POST /api/sessions/:id/messages — sends message', async () => {
    const res = await request(app).post(`/api/sessions/${sessionId}/messages`).set('Cookie', cookie1)
      .send({ message: 'Hello everyone!' });
    expect(res.status).toBe(200);
    expect(res.body.message.message).toBe('Hello everyone!');
    expect(res.body.message.username).toBe('chatuser1');
  });

  test('GET /api/sessions/:id/messages — returns messages', async () => {
    const res = await request(app).get(`/api/sessions/${sessionId}/messages`).set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBe(1);
    expect(res.body.messages[0].message).toBe('Hello everyone!');
  });

  test('POST /api/sessions/:id/messages — rejects empty message', async () => {
    const res = await request(app).post(`/api/sessions/${sessionId}/messages`).set('Cookie', cookie1)
      .send({ message: '   ' });
    expect(res.status).toBe(400);
  });

  test('POST /api/sessions/:id/messages — rejects too long message', async () => {
    const res = await request(app).post(`/api/sessions/${sessionId}/messages`).set('Cookie', cookie1)
      .send({ message: 'a'.repeat(501) });
    expect(res.status).toBe(400);
  });

  test('GET /api/sessions/:id/messages — non-member gets 403', async () => {
    const r3 = await registerUser('chatoutsider', 'password123');
    const res = await request(app).get(`/api/sessions/${sessionId}/messages`).set('Cookie', r3.cookie);
    expect(res.status).toBe(403);
  });
});

// ── Maps Config Tests ──────────────────────────────────────────────────────

describe('Maps Config', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('mapsuser', 'password123');
    cookie = result.cookie;
  });

  test('GET /api/config/maps-key — returns API key', async () => {
    const res = await request(app).get('/api/config/maps-key').set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.key).toBe('test-key');
  });

  test('GET /api/config/maps-key — 401 without auth', async () => {
    const res = await request(app).get('/api/config/maps-key');
    expect(res.status).toBe(401);
  });
});
