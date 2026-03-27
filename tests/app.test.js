const request = require('supertest');
const bcrypt = require('bcryptjs');

// Mock the database so tests don't need a real PostgreSQL connection
jest.mock('../db', () => {
  const users = new Map();
  const links = new Map();
  const submissions = [];
  let idCounter = 1;

  return {
    init: jest.fn().mockResolvedValue(),
    pool: { query: jest.fn() },

    createUser: jest.fn(async (displayName, email, passwordHash) => {
      const id = idCounter++;
      users.set(email, { id, display_name: displayName, email, password_hash: passwordHash });
      return { id };
    }),
    getUserByEmail: jest.fn(async (email) => users.get(email) || null),
    getUserById: jest.fn(async (id) => {
      for (const u of users.values()) if (u.id === id) return u;
      return null;
    }),
    emailExists: jest.fn(async (email) => users.has(email)),
    updatePassword: jest.fn(async (id, hash) => {
      for (const u of users.values()) if (u.id === id) u.password_hash = hash;
    }),

    createResetToken: jest.fn().mockResolvedValue(),
    getResetToken: jest.fn().mockResolvedValue(null),
    markResetTokenUsed: jest.fn().mockResolvedValue(),

    createFeedbackLink: jest.fn(async (userId, token) => {
      links.set(token, { id: idCounter++, user_id: userId, token, used: false });
      return { id: links.get(token).id };
    }),
    getLinkByToken: jest.fn(async (token) => links.get(token) || null),
    markLinkUsed: jest.fn(async (token) => {
      if (links.has(token)) links.get(token).used = true;
    }),

    createSubmission: jest.fn(async (linkId, data) => {
      submissions.push({ id: idCounter++, link_id: linkId, ...data });
      return { id: idCounter - 1 };
    }),
    getSubmissionsByUserId: jest.fn(async () => submissions),
  };
});

const app = require('../server');

// ─── AUTH ────────────────────────────────────────────────────────────

describe('Signup', () => {
  it('rejects missing fields', async () => {
    const res = await request(app).post('/signup').send({ email: 'a@b.com' });
    expect(res.status).toBe(200);
    expect(res.text).toContain('All fields are required');
  });

  it('rejects short password', async () => {
    const res = await request(app).post('/signup').send({
      display_name: 'Kim', email: 'kim@test.com', password: '123', password_confirm: '123'
    });
    expect(res.text).toContain('at least 6 characters');
  });

  it('rejects mismatched passwords', async () => {
    const res = await request(app).post('/signup').send({
      display_name: 'Kim', email: 'kim@test.com', password: 'abc123', password_confirm: 'xyz999'
    });
    expect(res.text).toContain('do not match');
  });

  it('creates account and redirects to dashboard', async () => {
    const res = await request(app).post('/signup').send({
      display_name: 'Kim', email: 'kim@test.com', password: 'abc123', password_confirm: 'abc123'
    });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard');
  });

  it('rejects duplicate email', async () => {
    const res = await request(app).post('/signup').send({
      display_name: 'Kim2', email: 'kim@test.com', password: 'abc123', password_confirm: 'abc123'
    });
    expect(res.text).toContain('already exists');
  });
});

describe('Login', () => {
  it('rejects missing fields', async () => {
    const res = await request(app).post('/login').send({ email: 'kim@test.com' });
    expect(res.text).toContain('email and password');
  });

  it('rejects unknown email', async () => {
    const res = await request(app).post('/login').send({
      email: 'nobody@test.com', password: 'abc123'
    });
    expect(res.text).toContain('No account found');
  });

  it('rejects wrong password', async () => {
    const res = await request(app).post('/login').send({
      email: 'kim@test.com', password: 'wrongpass'
    });
    expect(res.text).toContain('Incorrect password');
  });

  it('logs in with correct credentials', async () => {
    const res = await request(app).post('/login').send({
      email: 'kim@test.com', password: 'abc123'
    });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard');
  });
});

// ─── FEEDBACK LINKS ──────────────────────────────────────────────────

describe('Feedback form', () => {
  it('returns 200 for a valid unused link', async () => {
    const db = require('../db');
    db.getLinkByToken.mockResolvedValueOnce({ id: 1, user_id: 1, token: 'abc', used: false });
    db.getUserById.mockResolvedValueOnce({ id: 1, display_name: 'Kim', email: 'kim@test.com' });

    const res = await request(app).get('/f/abc');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Peer Feedback Form');
  });

  it('shows already-used page for a used link', async () => {
    const db = require('../db');
    db.getLinkByToken.mockResolvedValueOnce({ id: 1, user_id: 1, token: 'used', used: true });

    const res = await request(app).get('/f/used');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Already submitted');
  });

  it('shows not-found page for unknown token', async () => {
    const db = require('../db');
    db.getLinkByToken.mockResolvedValueOnce(null);

    const res = await request(app).get('/f/doesnotexist');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Link not found');
  });

  it('rejects submission with missing required fields', async () => {
    const db = require('../db');
    db.getLinkByToken.mockResolvedValueOnce({ id: 1, user_id: 1, token: 'abc2', used: false });
    db.getUserById.mockResolvedValueOnce({ id: 1, display_name: 'Kim', email: 'kim@test.com' });

    const res = await request(app).post('/f/abc2').send({
      what_working_well: 'Great!',
      // missing other required fields
    });
    expect(res.text).toContain('fill in all required fields');
  });

  it('accepts a valid full submission', async () => {
    const db = require('../db');
    db.getLinkByToken
      .mockResolvedValueOnce({ id: 2, user_id: 1, token: 'abc3', used: false })
      .mockResolvedValueOnce({ id: 2, user_id: 1, token: 'abc3', used: false });
    db.getUserById.mockResolvedValueOnce({ id: 1, display_name: 'Kim', email: 'kim@test.com' });

    const res = await request(app).post('/f/abc3').send({
      what_working_well: 'Great communication',
      strengths: 'Very collaborative',
      growth_opportunities: 'Could delegate more',
      actionable_suggestions: 'Try weekly planning',
      collaboration: 'Very smooth',
      looking_ahead: 'Keep growing',
    });
    expect(res.status).toBe(200);
    expect(res.text).toContain('Thank you');
  });
});

// ─── DASHBOARD AUTH GUARD ─────────────────────────────────────────────

describe('Dashboard', () => {
  it('redirects to login when not authenticated', async () => {
    const res = await request(app).get('/dashboard');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/');
  });
});
