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
async function registerUser(username, password, email) {
  const res = await request(app)
    .post('/api/register')
    .send({ username, password, email: email || `${username}@test.com`, remember: true });
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
      .send({ username: 'ab', password: 'password123', email: 'ab@test.com' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/3 characters/);
  });

  test('POST /api/register — short password rejected', async () => {
    const res = await request(app)
      .post('/api/register')
      .send({ username: 'testuser', password: '1234567', email: 'testuser@test.com' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/8 characters/);
  });

  test('POST /api/register — email required', async () => {
    const res = await request(app)
      .post('/api/register')
      .send({ username: 'noemail', password: 'password123' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/email/i);
  });

  test('POST /api/register — invalid email rejected', async () => {
    const res = await request(app)
      .post('/api/register')
      .send({ username: 'bademail', password: 'password123', email: 'not-an-email' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/email/i);
  });

  test('POST /api/register — duplicate username rejected', async () => {
    await registerUser('dupuser', 'password123');
    const res = await request(app)
      .post('/api/register')
      .send({ username: 'dupuser', password: 'password456', email: 'dup2@test.com' });
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

  test('GET /api/me — with auth returns user info including email and is_admin', async () => {
    const { cookie } = await registerUser('meuser', 'password123', 'meuser@test.com');
    const res = await request(app)
      .get('/api/me')
      .set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('meuser');
    expect(res.body.id).toBeDefined();
    expect(res.body.email).toBe('meuser@test.com');
    expect(typeof res.body.is_admin).toBe('boolean');
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

// ── Star/Favorite Tests ─────────────────────────────────────────────────────────

describe('Star/Favorite', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('staruser', 'password123');
    cookie = result.cookie;
    await request(app).post('/api/places').set('Cookie', cookie)
      .send({ type: 'likes', place: 'Star Cafe', place_id: 'sc001', restaurant_type: 'Cafe' });
    await request(app).post('/api/places').set('Cookie', cookie)
      .send({ type: 'want_to_try', place: 'Star Bistro', place_id: 'sb001', restaurant_type: 'French' });
  });

  test('POST /api/places/likes/star — stars a liked place', async () => {
    const res = await request(app)
      .post('/api/places/likes/star')
      .set('Cookie', cookie)
      .send({ place: 'Star Cafe' });
    expect(res.status).toBe(200);
    expect(res.body.starred).toBe(true);
  });

  test('POST /api/places/likes/star — unstars a liked place', async () => {
    const res = await request(app)
      .post('/api/places/likes/star')
      .set('Cookie', cookie)
      .send({ place: 'Star Cafe' });
    expect(res.status).toBe(200);
    expect(res.body.starred).toBe(false);
  });

  test('POST /api/places/want_to_try/star — stars a want-to-try place', async () => {
    const res = await request(app)
      .post('/api/places/want_to_try/star')
      .set('Cookie', cookie)
      .send({ place: 'Star Bistro' });
    expect(res.status).toBe(200);
    expect(res.body.starred).toBe(true);
  });

  test('GET /api/places — returns starred field', async () => {
    const res = await request(app)
      .get('/api/places')
      .set('Cookie', cookie);
    expect(res.status).toBe(200);
    const wtt = res.body.want_to_try.find(p => p.name === 'Star Bistro');
    expect(wtt.starred).toBe(true);
  });

  test('POST /api/places/likes/star — 404 for nonexistent place', async () => {
    const res = await request(app)
      .post('/api/places/likes/star')
      .set('Cookie', cookie)
      .send({ place: 'Nonexistent Place' });
    expect(res.status).toBe(404);
  });

  test('POST /api/places/badtype/star — 400 for invalid type', async () => {
    const res = await request(app)
      .post('/api/places/badtype/star')
      .set('Cookie', cookie)
      .send({ place: 'Star Cafe' });
    expect(res.status).toBe(400);
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

// ── Plan Tests ───────────────────────────────────────────────────────────────

describe('Plans', () => {
  let cookie1, cookie2;
  let planId, planCode;

  beforeAll(async () => {
    const r1 = await registerUser('sessuser1', 'password123');
    cookie1 = r1.cookie;
    const r2 = await registerUser('sessuser2', 'password123');
    cookie2 = r2.cookie;
  });

  test('POST /api/plans — create a plan', async () => {
    const res = await request(app)
      .post('/api/plans')
      .set('Cookie', cookie1)
      .send({ name: 'Friday Dinner' });
    expect(res.status).toBe(200);
    expect(res.body.code).toHaveLength(6);
    expect(res.body.name).toBe('Friday Dinner');
    planId = res.body.id;
    planCode = res.body.code;
  });

  test('POST /api/plans/join — join by code', async () => {
    const res = await request(app)
      .post('/api/plans/join')
      .set('Cookie', cookie2)
      .send({ code: planCode });
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(planId);
  });

  test('POST /api/plans/join — invalid code returns 404', async () => {
    const res = await request(app)
      .post('/api/plans/join')
      .set('Cookie', cookie2)
      .send({ code: 'XXXXXX' });
    expect(res.status).toBe(404);
  });

  test('GET /api/plans — list plans', async () => {
    const res = await request(app)
      .get('/api/plans')
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.plans.some(s => s.id === planId)).toBe(true);
  });

  test('GET /api/plans/:id — plan details include both members', async () => {
    const res = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.members).toHaveLength(2);
    expect(res.body.plan.status).toBe('open');
  });

  test('GET /api/plans/:id — non-member gets 403', async () => {
    const r3 = await registerUser('outsider', 'password123');
    const res = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', r3.cookie);
    expect(res.status).toBe(403);
  });

  test('POST /api/plans/:id/suggest — add suggestion', async () => {
    const res = await request(app)
      .post(`/api/plans/${planId}/suggest`)
      .set('Cookie', cookie1)
      .send({ place: 'Test Restaurant', place_id: null });
    expect(res.status).toBe(200);
    expect(res.body.id).toBeDefined();
  });

  test('GET /api/plans/:id — includes want_to_try matches', async () => {
    // Add "Test Restaurant" to sessuser1's want-to-try list
    await request(app)
      .post('/api/places')
      .set('Cookie', cookie1)
      .send({ type: 'want_to_try', place: 'Test Restaurant' });

    const res = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.want_to_try).toBeDefined();
    expect(res.body.want_to_try['Test Restaurant']).toBeDefined();
    expect(res.body.want_to_try['Test Restaurant'].some(u => u.username === 'sessuser1')).toBe(true);
  });

  test('POST /api/plans/:id/suggest — duplicate rejected', async () => {
    const res = await request(app)
      .post(`/api/plans/${planId}/suggest`)
      .set('Cookie', cookie2)
      .send({ place: 'Test Restaurant' });
    expect(res.status).toBe(409);
  });

  test('POST /api/plans/:id/vote — vote on suggestion', async () => {
    const detail = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    const res = await request(app)
      .post(`/api/plans/${planId}/vote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });
    expect(res.status).toBe(200);

    // Verify vote count
    const updated = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.vote_count).toBe(1);
    expect(s.user_voted).toBe(true);
  });

  test('POST /api/plans/:id/vote — double vote has no effect', async () => {
    const detail = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    await request(app)
      .post(`/api/plans/${planId}/vote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });

    const updated = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.vote_count).toBe(1);
  });

  test('POST /api/plans/:id/unvote — removes vote', async () => {
    const detail = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    const res = await request(app)
      .post(`/api/plans/${planId}/unvote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });
    expect(res.status).toBe(200);

    const updated = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.vote_count).toBe(0);
    expect(s.user_voted).toBe(false);
  });

  test('POST /api/plans/:id/downvote — downvote on suggestion', async () => {
    const detail = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    const res = await request(app)
      .post(`/api/plans/${planId}/downvote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });
    expect(res.status).toBe(200);

    const updated = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.downvote_count).toBe(1);
    expect(s.user_downvoted).toBe(true);
    expect(s.vote_count).toBe(0);
    expect(s.user_voted).toBe(false);
  });

  test('POST /api/plans/:id/undownvote — removes downvote', async () => {
    const detail = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    const res = await request(app)
      .post(`/api/plans/${planId}/undownvote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });
    expect(res.status).toBe(200);

    const updated = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.downvote_count).toBe(0);
    expect(s.user_downvoted).toBe(false);
  });

  test('Mutual exclusivity — upvote then downvote removes upvote', async () => {
    const detail = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    await request(app)
      .post(`/api/plans/${planId}/vote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });

    await request(app)
      .post(`/api/plans/${planId}/downvote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });

    const updated = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.vote_count).toBe(0);
    expect(s.downvote_count).toBe(1);
    expect(s.user_voted).toBe(false);
    expect(s.user_downvoted).toBe(true);
  });

  test('Mutual exclusivity — downvote then upvote removes downvote', async () => {
    const detail = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const suggId = detail.body.suggestions[0].id;

    // Already downvoted from previous test, so vote now
    await request(app)
      .post(`/api/plans/${planId}/vote`)
      .set('Cookie', cookie1)
      .send({ suggestion_id: suggId });

    const updated = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    const s = updated.body.suggestions.find(s => s.id === suggId);
    expect(s.vote_count).toBe(1);
    expect(s.downvote_count).toBe(0);
    expect(s.user_voted).toBe(true);
    expect(s.user_downvoted).toBe(false);
  });

  test('POST /api/plans/:id/pick — random pick returns winner', async () => {
    const res = await request(app)
      .post(`/api/plans/${planId}/pick`)
      .set('Cookie', cookie1)
      .send({ mode: 'random' });
    expect(res.status).toBe(200);
    expect(res.body.winner.place).toBe('Test Restaurant');
  });

  test('POST /api/plans/:id/close — non-creator gets 403', async () => {
    const res = await request(app)
      .post(`/api/plans/${planId}/close`)
      .set('Cookie', cookie2);
    expect(res.status).toBe(403);
  });

  test('POST /api/plans/:id/close — creator can close', async () => {
    const res = await request(app)
      .post(`/api/plans/${planId}/close`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);

    const detail = await request(app)
      .get(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    expect(detail.body.plan.status).toBe('closed');
  });

  test('DELETE /api/plans/:id — non-creator gets 403', async () => {
    const res = await request(app)
      .delete(`/api/plans/${planId}`)
      .set('Cookie', cookie2);
    expect(res.status).toBe(403);
  });

  test('DELETE /api/plans/:id — creator can delete closed plan', async () => {
    const res = await request(app)
      .delete(`/api/plans/${planId}`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);

    // Plan no longer appears in list
    const list = await request(app)
      .get('/api/plans')
      .set('Cookie', cookie1);
    expect(list.body.plans.some(s => s.id === planId)).toBe(false);
  });

  test('DELETE /api/plans/:id — cannot delete open plan', async () => {
    // Create a new plan (defaults to open)
    const create = await request(app)
      .post('/api/plans')
      .set('Cookie', cookie1)
      .send({ name: 'Open Plan' });
    const openId = create.body.id;

    const res = await request(app)
      .delete(`/api/plans/${openId}`)
      .set('Cookie', cookie1);
    expect(res.status).toBe(400);
  });

  test('GET /api/plans — includes creator_username', async () => {
    const res = await request(app)
      .get('/api/plans')
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.plans.length).toBeGreaterThan(0);
    expect(res.body.plans[0].creator_username).toBe('sessuser1');
  });

  test('GET /api/plans — includes member_count and suggestion_count', async () => {
    const res = await request(app)
      .get('/api/plans')
      .set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.plans.length).toBeGreaterThan(0);
    expect(typeof res.body.plans[0].member_count).toBe('number');
    expect(typeof res.body.plans[0].suggestion_count).toBe('number');
  });

  test('POST /api/plans/:id/invite — invites a user by username', async () => {
    const create = await request(app).post('/api/plans').set('Cookie', cookie1)
      .send({ name: 'Invite Test' });
    const sid = create.body.id;
    const res = await request(app).post(`/api/plans/${sid}/invite`).set('Cookie', cookie1)
      .send({ username: 'sessuser2' });
    expect(res.status).toBe(200);
    const detail = await request(app).get(`/api/plans/${sid}`).set('Cookie', cookie2);
    expect(detail.status).toBe(200);
    expect(detail.body.members.some(m => m.username === 'sessuser2')).toBe(true);
  });

  test('POST /api/plans/:id/invite — non-existent user returns 404', async () => {
    const create = await request(app).post('/api/plans').set('Cookie', cookie1)
      .send({ name: 'Invite Fail' });
    const res = await request(app).post(`/api/plans/${create.body.id}/invite`).set('Cookie', cookie1)
      .send({ username: 'nonexistent_user_xyz' });
    expect(res.status).toBe(404);
  });

  test('GET /api/plans/:id/dislikes — returns disliked places by members', async () => {
    await request(app).post('/api/places').set('Cookie', cookie1)
      .send({ type: 'dislikes', place: 'Hated Diner' });
    const create = await request(app).post('/api/plans').set('Cookie', cookie1)
      .send({ name: 'Dislike Test' });
    const res = await request(app).get(`/api/plans/${create.body.id}/dislikes`).set('Cookie', cookie1);
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

  test('GET /api/suggestions/recent — returns suggestions after adding to plan', async () => {
    // Create plan and suggest
    const sess = await request(app).post('/api/plans').set('Cookie', cookie)
      .send({ name: 'Recent Test' });
    await request(app).post(`/api/plans/${sess.body.id}/suggest`).set('Cookie', cookie)
      .send({ place: 'Recent Place 1', place_id: null });
    await request(app).post(`/api/plans/${sess.body.id}/suggest`).set('Cookie', cookie)
      .send({ place: 'Recent Place 2', place_id: null });

    const res = await request(app).get('/api/suggestions/recent').set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.recent.length).toBe(2);
    expect(res.body.recent[0].name).toBe('Recent Place 2');
  });
});

// ── Voting Deadline Tests ──────────────────────────────────────────────────

describe('Voting Deadline', () => {
  let cookie1, cookie2, planId;

  beforeAll(async () => {
    const r1 = await registerUser('deadlineuser1', 'password123');
    cookie1 = r1.cookie;
    const r2 = await registerUser('deadlineuser2', 'password123');
    cookie2 = r2.cookie;
    const sess = await request(app).post('/api/plans').set('Cookie', cookie1)
      .send({ name: 'Deadline Plan' });
    planId = sess.body.id;
    await request(app).post('/api/plans/join').set('Cookie', cookie2)
      .send({ code: sess.body.code });
  });

  test('POST /api/plans/:id/deadline — creator can set deadline', async () => {
    const deadline = new Date(Date.now() + 3600000).toISOString();
    const res = await request(app).post(`/api/plans/${planId}/deadline`).set('Cookie', cookie1)
      .send({ deadline });
    expect(res.status).toBe(200);

    const detail = await request(app).get(`/api/plans/${planId}`).set('Cookie', cookie1);
    expect(detail.body.plan.voting_deadline).toBe(deadline);
  });

  test('POST /api/plans/:id/deadline — non-creator gets 403', async () => {
    const res = await request(app).post(`/api/plans/${planId}/deadline`).set('Cookie', cookie2)
      .send({ deadline: new Date().toISOString() });
    expect(res.status).toBe(403);
  });

  test('POST /api/plans/:id/deadline — can remove deadline', async () => {
    const res = await request(app).post(`/api/plans/${planId}/deadline`).set('Cookie', cookie1)
      .send({ deadline: null });
    expect(res.status).toBe(200);

    const detail = await request(app).get(`/api/plans/${planId}`).set('Cookie', cookie1);
    expect(detail.body.plan.voting_deadline).toBeNull();
  });
});

// ── Plan Chat Tests ─────────────────────────────────────────────────────

describe('Plan Chat', () => {
  let cookie1, cookie2, planId;

  beforeAll(async () => {
    const r1 = await registerUser('chatuser1', 'password123');
    cookie1 = r1.cookie;
    const r2 = await registerUser('chatuser2', 'password123');
    cookie2 = r2.cookie;
    const sess = await request(app).post('/api/plans').set('Cookie', cookie1)
      .send({ name: 'Chat Plan' });
    planId = sess.body.id;
    await request(app).post('/api/plans/join').set('Cookie', cookie2)
      .send({ code: sess.body.code });
  });

  test('GET /api/plans/:id/messages — returns empty initially', async () => {
    const res = await request(app).get(`/api/plans/${planId}/messages`).set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.messages).toEqual([]);
  });

  test('POST /api/plans/:id/messages — sends message', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages`).set('Cookie', cookie1)
      .send({ message: 'Hello everyone!' });
    expect(res.status).toBe(200);
    expect(res.body.message.message).toBe('Hello everyone!');
    expect(res.body.message.username).toBe('chatuser1');
  });

  test('GET /api/plans/:id/messages — returns messages', async () => {
    const res = await request(app).get(`/api/plans/${planId}/messages`).set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBe(1);
    expect(res.body.messages[0].message).toBe('Hello everyone!');
  });

  test('POST /api/plans/:id/messages — rejects empty message', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages`).set('Cookie', cookie1)
      .send({ message: '   ' });
    expect(res.status).toBe(400);
  });

  test('POST /api/plans/:id/messages — rejects too long message', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages`).set('Cookie', cookie1)
      .send({ message: 'a'.repeat(501) });
    expect(res.status).toBe(400);
  });

  test('GET /api/plans/:id/messages — non-member gets 403', async () => {
    const r3 = await registerUser('chatoutsider', 'password123');
    const res = await request(app).get(`/api/plans/${planId}/messages`).set('Cookie', r3.cookie);
    expect(res.status).toBe(403);
  });
});

// ── GIF Messages & Reactions Tests ────────────────────────────────────────

describe('GIF Messages & Reactions', () => {
  let cookie1, cookie2, cookie3, planId, messageId;

  beforeAll(async () => {
    const r1 = await registerUser('gifreactor1', 'password123');
    cookie1 = r1.cookie;
    const r2 = await registerUser('gifreactor2', 'password123');
    cookie2 = r2.cookie;
    const r3 = await registerUser('gifreactor3', 'password123');
    cookie3 = r3.cookie;
    const sess = await request(app).post('/api/plans').set('Cookie', cookie1)
      .send({ name: 'GIF Plan' });
    planId = sess.body.id;
    await request(app).post('/api/plans/join').set('Cookie', cookie2)
      .send({ code: sess.body.code });
    // Send a text message to react to
    const msgRes = await request(app).post(`/api/plans/${planId}/messages`).set('Cookie', cookie1)
      .send({ message: 'React to this!', message_type: 'text' });
    messageId = msgRes.body.message.id;
  });

  test('POST /api/plans/:id/messages — GIF message with valid Tenor URL', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages`).set('Cookie', cookie1)
      .send({ message: 'https://media0.giphy.com/media/abc123/giphy.gif', message_type: 'gif' });
    expect(res.status).toBe(200);
    expect(res.body.message.message_type).toBe('gif');
    expect(res.body.message.message).toBe('https://media0.giphy.com/media/abc123/giphy.gif');
  });

  test('POST /api/plans/:id/messages — rejects non-Giphy GIF URL', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages`).set('Cookie', cookie1)
      .send({ message: 'https://evil.com/malware.gif', message_type: 'gif' });
    expect(res.status).toBe(400);
  });

  test('POST /api/plans/:id/messages — rejects empty GIF URL', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages`).set('Cookie', cookie1)
      .send({ message: '', message_type: 'gif' });
    expect(res.status).toBe(400);
  });

  test('GET /api/plans/:id/messages — includes message_type and reactions', async () => {
    const res = await request(app).get(`/api/plans/${planId}/messages`).set('Cookie', cookie1);
    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBeGreaterThan(0);
    const textMsg = res.body.messages.find(m => m.message === 'React to this!');
    expect(textMsg.message_type).toBe('text');
    expect(textMsg.reactions).toEqual([]);
    const gifMsg = res.body.messages.find(m => m.message_type === 'gif');
    expect(gifMsg).toBeDefined();
  });

  test('POST /api/plans/:id/messages/:messageId/react — adds reaction', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages/${messageId}/react`).set('Cookie', cookie1)
      .send({ emoji: '👍' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  test('POST /api/plans/:id/messages/:messageId/react — duplicate is idempotent', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages/${messageId}/react`).set('Cookie', cookie1)
      .send({ emoji: '👍' });
    expect(res.status).toBe(200);
  });

  test('POST /api/plans/:id/messages/:messageId/react — second user reacts', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages/${messageId}/react`).set('Cookie', cookie2)
      .send({ emoji: '👍' });
    expect(res.status).toBe(200);
  });

  test('GET messages — shows reactions from both users', async () => {
    const res = await request(app).get(`/api/plans/${planId}/messages`).set('Cookie', cookie1);
    const msg = res.body.messages.find(m => m.id === messageId);
    const thumbsUp = msg.reactions.filter(r => r.emoji === '👍');
    expect(thumbsUp.length).toBe(2);
  });

  test('DELETE /api/plans/:id/messages/:messageId/react — removes reaction', async () => {
    const res = await request(app).delete(`/api/plans/${planId}/messages/${messageId}/react`).set('Cookie', cookie1)
      .send({ emoji: '👍' });
    expect(res.status).toBe(200);

    const msgs = await request(app).get(`/api/plans/${planId}/messages`).set('Cookie', cookie1);
    const msg = msgs.body.messages.find(m => m.id === messageId);
    const thumbsUp = msg.reactions.filter(r => r.emoji === '👍');
    expect(thumbsUp.length).toBe(1);
  });

  test('POST react — rejects invalid emoji (too long)', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages/${messageId}/react`).set('Cookie', cookie1)
      .send({ emoji: 'this is way too long to be an emoji' });
    expect(res.status).toBe(400);
  });

  test('POST react — non-member gets 403', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages/${messageId}/react`).set('Cookie', cookie3)
      .send({ emoji: '👍' });
    expect(res.status).toBe(403);
  });

  test('POST react — message not found returns 404', async () => {
    const res = await request(app).post(`/api/plans/${planId}/messages/99999/react`).set('Cookie', cookie1)
      .send({ emoji: '👍' });
    expect(res.status).toBe(404);
  });

  test('GET /api/giphy/search — returns 400 without GIPHY_API_KEY', async () => {
    const res = await request(app).get('/api/giphy/search?q=funny').set('Cookie', cookie1);
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('not configured');
  });

  test('GET /api/giphy/trending — returns 400 without GIPHY_API_KEY', async () => {
    const res = await request(app).get('/api/giphy/trending').set('Cookie', cookie1);
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('not configured');
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

// ── Settings Infrastructure Tests ────────────────────────────────────────────

describe('Settings Infrastructure', () => {
  test('getSetting/setSetting — round-trip works', () => {
    const { getSetting, setSetting } = require('../server');
    setSetting('test_key', 'test_value');
    expect(getSetting('test_key')).toBe('test_value');
    setSetting('test_key', 'updated_value');
    expect(getSetting('test_key')).toBe('updated_value');
  });

  test('getSetting — returns null for missing key', () => {
    const { getSetting } = require('../server');
    expect(getSetting('nonexistent_key')).toBeNull();
  });

  test('encryptSetting/decryptSetting — round-trip works', () => {
    const { encryptSetting, decryptSetting } = require('../server');
    const plaintext = 'my-secret-password';
    const encrypted = encryptSetting(plaintext);
    expect(encrypted).not.toBe(plaintext);
    expect(encrypted).toContain(':');
    expect(decryptSetting(encrypted)).toBe(plaintext);
  });
});

// ── Email Update Tests ───────────────────────────────────────────────────────

describe('Email Update', () => {
  let cookie;

  beforeAll(async () => {
    const result = await registerUser('emailuser', 'password123', 'old@test.com');
    cookie = result.cookie;
  });

  test('POST /api/update-email — updates email', async () => {
    const res = await request(app).post('/api/update-email').set('Cookie', cookie)
      .send({ email: 'new@test.com' });
    expect(res.status).toBe(200);
    expect(res.body.email).toBe('new@test.com');

    const me = await request(app).get('/api/me').set('Cookie', cookie);
    expect(me.body.email).toBe('new@test.com');
  });

  test('POST /api/update-email — rejects invalid email', async () => {
    const res = await request(app).post('/api/update-email').set('Cookie', cookie)
      .send({ email: 'bad-email' });
    expect(res.status).toBe(400);
  });

  test('POST /api/update-email — 401 without auth', async () => {
    const res = await request(app).post('/api/update-email')
      .send({ email: 'test@test.com' });
    expect(res.status).toBe(401);
  });
});

// ── Admin Tests ──────────────────────────────────────────────────────────────

describe('Admin', () => {
  let adminCookie, userCookie, userId;

  beforeAll(async () => {
    // First user in a fresh context — make them admin via DB
    const r1 = await registerUser('adminuser', 'password123', 'admin@test.com');
    adminCookie = r1.cookie;
    // Force admin via DB
    db.prepare("UPDATE users SET is_admin = 1 WHERE username = 'adminuser'").run();
    // Re-login to get fresh token with is_admin
    const loginRes = await request(app).post('/api/login')
      .send({ username: 'adminuser', password: 'password123' });
    adminCookie = loginRes.headers['set-cookie'];

    const r2 = await registerUser('normaluser', 'password123', 'normal@test.com');
    userCookie = r2.cookie;
    const me = await request(app).get('/api/me').set('Cookie', userCookie);
    userId = me.body.id;
  });

  test('GET /api/admin/stats — admin can access', async () => {
    const res = await request(app).get('/api/admin/stats').set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(typeof res.body.users).toBe('number');
    expect(typeof res.body.plans).toBe('number');
    expect(typeof res.body.smtp_configured).toBe('boolean');
    expect(typeof res.body.vapid_source).toBe('string');
  });

  test('GET /api/admin/stats — non-admin gets 403', async () => {
    const res = await request(app).get('/api/admin/stats').set('Cookie', userCookie);
    expect(res.status).toBe(403);
  });

  test('GET /api/admin/stats — unauthenticated gets 401', async () => {
    const res = await request(app).get('/api/admin/stats');
    expect(res.status).toBe(401);
  });

  test('GET /api/admin/users — lists all users', async () => {
    const res = await request(app).get('/api/admin/users').set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.users)).toBe(true);
    expect(res.body.users.some(u => u.username === 'adminuser')).toBe(true);
    expect(res.body.users.some(u => u.username === 'normaluser')).toBe(true);
  });

  test('POST /api/admin/users/:id/reset-password — resets user password', async () => {
    const res = await request(app).post(`/api/admin/users/${userId}/reset-password`).set('Cookie', adminCookie)
      .send({ newPassword: 'resetpass123' });
    expect(res.status).toBe(200);

    const login = await request(app).post('/api/login')
      .send({ username: 'normaluser', password: 'resetpass123' });
    expect(login.status).toBe(200);
  });

  test('POST /api/admin/users/:id/toggle-admin — promotes user', async () => {
    const res = await request(app).post(`/api/admin/users/${userId}/toggle-admin`).set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(res.body.is_admin).toBe(true);

    // Toggle back
    const res2 = await request(app).post(`/api/admin/users/${userId}/toggle-admin`).set('Cookie', adminCookie);
    expect(res2.body.is_admin).toBe(false);
  });

  test('POST /api/admin/users/:id/toggle-admin — cannot modify self', async () => {
    const me = await request(app).get('/api/me').set('Cookie', adminCookie);
    const res = await request(app).post(`/api/admin/users/${me.body.id}/toggle-admin`).set('Cookie', adminCookie);
    expect(res.status).toBe(400);
  });

  test('DELETE /api/admin/users/:id — cannot delete self', async () => {
    const me = await request(app).get('/api/me').set('Cookie', adminCookie);
    const res = await request(app).delete(`/api/admin/users/${me.body.id}`).set('Cookie', adminCookie);
    expect(res.status).toBe(400);
  });

  test('DELETE /api/admin/users/:id — admin can delete user', async () => {
    const { cookie: delCookie } = await registerUser('admindel', 'password123', 'admindel@test.com');
    const me = await request(app).get('/api/me').set('Cookie', delCookie);
    const res = await request(app).delete(`/api/admin/users/${me.body.id}`).set('Cookie', adminCookie);
    expect(res.status).toBe(200);

    const login = await request(app).post('/api/login')
      .send({ username: 'admindel', password: 'password123' });
    expect(login.status).toBe(401);
  });

  test('GET /api/admin/smtp — returns SMTP config', async () => {
    const res = await request(app).get('/api/admin/smtp').set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(typeof res.body.configured).toBe('boolean');
  });

  test('POST /api/admin/smtp — saves SMTP config', async () => {
    const res = await request(app).post('/api/admin/smtp').set('Cookie', adminCookie)
      .send({ host: 'smtp.test.com', port: 587, user: 'test@test.com', password: 'secret', from: 'noreply@test.com', secure: false });
    expect(res.status).toBe(200);

    const get = await request(app).get('/api/admin/smtp').set('Cookie', adminCookie);
    expect(get.body.host).toBe('smtp.test.com');
    expect(get.body.configured).toBe(true);
  });

  test('GET /api/admin/vapid — returns VAPID info', async () => {
    const res = await request(app).get('/api/admin/vapid').set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(typeof res.body.publicKey).toBe('string');
    expect(typeof res.body.source).toBe('string');
  });

  test('POST /api/admin/vapid/generate — generates new keys', async () => {
    const res = await request(app).post('/api/admin/vapid/generate').set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(typeof res.body.publicKey).toBe('string');
  });

  test('GET /api/admin/settings — returns settings', async () => {
    const res = await request(app).get('/api/admin/settings').set('Cookie', adminCookie);
    expect(res.status).toBe(200);
    expect(typeof res.body.jwt_expiry).toBe('string');
    expect(typeof res.body.cookie_secure).toBe('string');
  });

  test('POST /api/admin/settings — saves settings', async () => {
    const res = await request(app).post('/api/admin/settings').set('Cookie', adminCookie)
      .send({ jwt_expiry: '24h', cookie_secure: 'false' });
    expect(res.status).toBe(200);

    const get = await request(app).get('/api/admin/settings').set('Cookie', adminCookie);
    expect(get.body.jwt_expiry).toBe('24h');
  });
});

// ── Password Reset Tests ─────────────────────────────────────────────────────

describe('Password Reset', () => {
  test('POST /api/forgot-password — returns error when SMTP not configured', async () => {
    // Clear SMTP settings to ensure not configured
    const { setSetting } = require('../server');
    setSetting('smtp_host', '');
    setSetting('smtp_user', '');
    setSetting('smtp_password', '');

    const res = await request(app).post('/api/forgot-password')
      .send({ email: 'test@test.com' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not available/i);
  });

  test('GET /api/reset-password/:token — invalid token returns false', async () => {
    const res = await request(app).get('/api/reset-password/invalidtoken123');
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(false);
  });

  test('POST /api/reset-password — invalid token rejected', async () => {
    const res = await request(app).post('/api/reset-password')
      .send({ token: 'invalidtoken123', newPassword: 'newpass123' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid|expired/i);
  });

  test('POST /api/reset-password — valid token resets password', async () => {
    const { cookie } = await registerUser('resetuser', 'password123', 'reset@test.com');
    const me = await request(app).get('/api/me').set('Cookie', cookie);

    // Manually insert a reset token
    const token = require('crypto').randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000).toISOString();
    db.prepare('INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(me.body.id, token, expiresAt);

    // Validate token
    const validate = await request(app).get(`/api/reset-password/${token}`);
    expect(validate.body.valid).toBe(true);
    expect(validate.body.username).toBe('resetuser');

    // Reset password
    const res = await request(app).post('/api/reset-password')
      .send({ token, newPassword: 'newresetpass' });
    expect(res.status).toBe(200);

    // Old password fails
    const loginOld = await request(app).post('/api/login')
      .send({ username: 'resetuser', password: 'password123' });
    expect(loginOld.status).toBe(401);

    // New password works
    const loginNew = await request(app).post('/api/login')
      .send({ username: 'resetuser', password: 'newresetpass' });
    expect(loginNew.status).toBe(200);

    // Token is now used
    const reuse = await request(app).get(`/api/reset-password/${token}`);
    expect(reuse.body.valid).toBe(false);
  });
});
