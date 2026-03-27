const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function init() {
  // Migrations for existing tables
  await pool.query(`ALTER TABLE feedback_submissions ALTER COLUMN it_would_help DROP NOT NULL`).catch(() => {});
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT`).catch(() => {});
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT TRUE`).catch(() => {});

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      display_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS feedback_links (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      token TEXT UNIQUE NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS feedback_submissions (
      id SERIAL PRIMARY KEY,
      link_id INTEGER NOT NULL REFERENCES feedback_links(id),
      what_working_well TEXT,
      strengths TEXT,
      growth_opportunities TEXT,
      actionable_suggestions TEXT,
      collaboration TEXT,
      looking_ahead TEXT,
      anything_else TEXT,
      submitter_name TEXT,
      it_would_help TEXT,
      support_offers TEXT[],
      support_other TEXT,
      submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

module.exports = {
  init,
  pool,

  async createUser(displayName, email, passwordHash) {
    const result = await pool.query(
      'INSERT INTO users (display_name, email, password_hash) VALUES ($1, $2, $3) RETURNING id',
      [displayName, email, passwordHash]
    );
    return result.rows[0];
  },

  async getUserByEmail(email) {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return result.rows[0] || null;
  },

  async getUserById(id) {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0] || null;
  },

  async emailExists(email) {
    const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    return result.rows.length > 0;
  },

  async createResetToken(userId, token, expiresAt) {
    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [userId, token, expiresAt]
    );
  },

  async getResetToken(token) {
    const result = await pool.query(
      'SELECT * FROM password_reset_tokens WHERE token = $1 AND used = FALSE AND expires_at > NOW()',
      [token]
    );
    return result.rows[0] || null;
  },

  async markResetTokenUsed(token) {
    await pool.query('UPDATE password_reset_tokens SET used = TRUE WHERE token = $1', [token]);
  },

  async updatePassword(userId, passwordHash) {
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, userId]);
  },

  async createFeedbackLink(userId, token) {
    const result = await pool.query(
      'INSERT INTO feedback_links (user_id, token) VALUES ($1, $2) RETURNING id',
      [userId, token]
    );
    return result.rows[0];
  },

  async getLinkByToken(token) {
    const result = await pool.query('SELECT * FROM feedback_links WHERE token = $1', [token]);
    return result.rows[0] || null;
  },

  async markLinkUsed(token) {
    await pool.query('UPDATE feedback_links SET used = TRUE WHERE token = $1', [token]);
  },

  async createSubmission(linkId, data) {
    const result = await pool.query(
      `INSERT INTO feedback_submissions
        (link_id, what_working_well, strengths, growth_opportunities,
         actionable_suggestions, collaboration, looking_ahead, anything_else,
         submitter_name, it_would_help, support_offers, support_other)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING id`,
      [
        linkId,
        data.what_working_well,
        data.strengths,
        data.growth_opportunities,
        data.actionable_suggestions,
        data.collaboration,
        data.looking_ahead,
        data.anything_else || null,
        data.submitter_name || null,
        data.it_would_help || null,
        data.support_offers || [],
        data.support_other || null
      ]
    );
    return result.rows[0];
  },

  async getSubmissionsByUserId(userId) {
    const result = await pool.query(
      `SELECT fs.*, fl.token
       FROM feedback_submissions fs
       JOIN feedback_links fl ON fs.link_id = fl.id
       WHERE fl.user_id = $1
       ORDER BY fs.submitted_at DESC`,
      [userId]
    );
    return result.rows;
  }
};
