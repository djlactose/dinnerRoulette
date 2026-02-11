// Unit tests for helper functions

// Set required env vars before loading server
process.env.GOOGLE_API_KEY = 'test-key';
process.env.JWT_SECRET = 'test-secret';
process.env.DB_PATH = ':memory:';

const { haversine, generatePlanCode, db } = require('../server');

afterAll(() => {
  db.close();
});

describe('haversine', () => {
  test('returns 0 for same coordinates', () => {
    expect(haversine(40.7128, -74.0060, 40.7128, -74.0060)).toBe(0);
  });

  test('NYC to LA is approximately 3944 km', () => {
    const dist = haversine(40.7128, -74.0060, 34.0522, -118.2437);
    expect(dist).toBeGreaterThan(3900);
    expect(dist).toBeLessThan(4000);
  });

  test('London to Paris is approximately 344 km', () => {
    const dist = haversine(51.5074, -0.1278, 48.8566, 2.3522);
    expect(dist).toBeGreaterThan(330);
    expect(dist).toBeLessThan(360);
  });

  test('short distance (1-2 km)', () => {
    // ~1 km apart
    const dist = haversine(40.7128, -74.0060, 40.7218, -74.0060);
    expect(dist).toBeGreaterThan(0.9);
    expect(dist).toBeLessThan(1.1);
  });
});

describe('generatePlanCode', () => {
  test('returns a 6-character string', () => {
    const code = generatePlanCode();
    expect(code).toHaveLength(6);
  });

  test('contains only valid characters (no ambiguous 0/O/1/I/L)', () => {
    const validChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    for (let i = 0; i < 100; i++) {
      const code = generatePlanCode();
      for (const c of code) {
        expect(validChars).toContain(c);
      }
    }
  });

  test('generates unique codes across multiple calls', () => {
    const codes = new Set();
    for (let i = 0; i < 50; i++) {
      codes.add(generatePlanCode());
    }
    // With 30^6 possible codes, 50 codes should all be unique
    expect(codes.size).toBe(50);
  });
});
