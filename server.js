require('dotenv').config();
const express = require('express');
const session = require('express-session');
const connectPg = require('connect-pg-simple');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const path = require('path');
const db = require('./db');

const app = express();
const PgSession = connectPg(session);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  store: new PgSession({ pool: db.pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'kawaii-feedback-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/');
}

let transporter = null;
if (process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

// ─── ROUTES ────────────────────────────────────────────────────────

app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('login', { error: null, success: null, tab: 'login' });
});

// POST /login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.render('login', { error: 'Please enter your email and password.', success: null, tab: 'login' });

  const user = await db.getUserByEmail(email.trim().toLowerCase());
  if (!user || !user.password_hash)
    return res.render('login', { error: 'No account found with that email.', success: null, tab: 'login' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match)
    return res.render('login', { error: 'Incorrect password. Please try again.', success: null, tab: 'login' });

  req.session.userId = user.id;
  req.session.displayName = user.display_name;
  res.redirect('/dashboard');
});

// POST /signup
app.post('/signup', async (req, res) => {
  const { display_name, email, password, password_confirm } = req.body;

  if (!display_name || !email || !password)
    return res.render('login', { error: 'All fields are required.', success: null, tab: 'signup' });

  if (password.length < 6)
    return res.render('login', { error: 'Password must be at least 6 characters.', success: null, tab: 'signup' });

  if (password !== password_confirm)
    return res.render('login', { error: 'Passwords do not match.', success: null, tab: 'signup' });

  const existingUser = await db.getUserByEmail(email.trim().toLowerCase());

  if (existingUser && existingUser.password_hash)
    return res.render('login', { error: 'An account with that email already exists.', success: null, tab: 'signup' });

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    if (existingUser && !existingUser.password_hash) {
      // Legacy account — upgrade it with a password
      await db.updatePassword(existingUser.id, passwordHash);
      req.session.userId = existingUser.id;
      req.session.displayName = existingUser.display_name;
    } else {
      const user = await db.createUser(display_name.trim(), email.trim().toLowerCase(), passwordHash);
      req.session.userId = user.id;
      req.session.displayName = display_name.trim();
    }

    res.redirect('/dashboard');
  } catch {
    res.render('login', { error: 'Something went wrong. Please try again.', success: null, tab: 'signup' });
  }
});

// GET /logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// GET /dashboard
app.get('/dashboard', requireAuth, async (req, res) => {
  const [user, submissions] = await Promise.all([
    db.getUserById(req.session.userId),
    db.getSubmissionsByUserId(req.session.userId)
  ]);
  const newToken = req.session.newToken || null;
  delete req.session.newToken;
  const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
  res.render('dashboard', { user, submissions, newToken, baseUrl });
});

// POST /generate-link
app.post('/generate-link', requireAuth, async (req, res) => {
  const token = uuidv4();
  await db.createFeedbackLink(req.session.userId, token);
  req.session.newToken = token;
  res.redirect('/dashboard');
});

// GET /forgot
app.get('/forgot', (req, res) => {
  res.render('forgot', { error: null, success: null });
});

// POST /forgot
app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.render('forgot', { error: 'Please enter your email.', success: null });

  const user = await db.getUserByEmail(email.trim().toLowerCase());
  const successMsg = 'If that email is registered, a reset link has been sent.';

  if (!user) return res.render('forgot', { error: null, success: successMsg });

  if (!transporter)
    return res.render('forgot', { error: 'Email is not configured on this server. Please contact the admin.', success: null });

  const token = uuidv4();
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  await db.createResetToken(user.id, token, expiresAt);

  const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
  const resetUrl = `${baseUrl}/reset/${token}`;

  try {
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: user.email,
      subject: '🌸 Reset your feedMe password',
      html: `
        <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;background:#FFF0F5;border-radius:16px;">
          <h2 style="color:#FF69B4;">🌸 Reset your password</h2>
          <p>Hi <strong>${user.display_name}</strong>!</p>
          <p>Click the button below to reset your password. This link expires in 1 hour.</p>
          <a href="${resetUrl}" style="display:inline-block;margin:20px 0;padding:14px 28px;background:#FF69B4;color:#fff;border-radius:50px;text-decoration:none;font-weight:bold;">Reset my password</a>
          <p style="color:#aaa;font-size:12px;">If you didn't request this, you can ignore this email.</p>
        </div>
      `
    });
    res.render('forgot', { error: null, success: successMsg });
  } catch {
    res.render('forgot', { error: 'Failed to send email. Please try again.', success: null });
  }
});

// GET /reset/:token
app.get('/reset/:token', async (req, res) => {
  const record = await db.getResetToken(req.params.token);
  if (!record) return res.render('reset', { token: null, error: 'This reset link is invalid or has expired.' });
  res.render('reset', { token: req.params.token, error: null });
});

// POST /reset/:token
app.post('/reset/:token', async (req, res) => {
  const record = await db.getResetToken(req.params.token);
  if (!record) return res.render('reset', { token: null, error: 'This reset link is invalid or has expired.' });

  const { password, password_confirm } = req.body;
  if (!password || password.length < 6)
    return res.render('reset', { token: req.params.token, error: 'Password must be at least 6 characters.' });
  if (password !== password_confirm)
    return res.render('reset', { token: req.params.token, error: 'Passwords do not match.' });

  const passwordHash = await bcrypt.hash(password, 12);
  await db.updatePassword(record.user_id, passwordHash);
  await db.markResetTokenUsed(req.params.token);

  res.render('login', { error: null, success: 'Password updated! You can now log in.', tab: 'login' });
});

// GET /f/:token
app.get('/f/:token', async (req, res) => {
  const link = await db.getLinkByToken(req.params.token);
  if (!link) return res.render('thankyou', { state: 'notfound' });
  if (link.used) return res.render('thankyou', { state: 'used' });
  const recipient = await db.getUserById(link.user_id);
  res.render('feedback', { token: req.params.token, recipient, error: null });
});

// POST /f/:token
app.post('/f/:token', async (req, res) => {
  const link = await db.getLinkByToken(req.params.token);
  if (!link) return res.render('thankyou', { state: 'notfound' });
  if (link.used) return res.render('thankyou', { state: 'used' });

  const {
    what_working_well, strengths, growth_opportunities,
    actionable_suggestions, collaboration, looking_ahead,
    anything_else, submitter_name, it_would_help,
    support_offers, support_other
  } = req.body;

  if (!what_working_well || !strengths || !growth_opportunities ||
      !actionable_suggestions || !collaboration || !looking_ahead) {
    const recipient = await db.getUserById(link.user_id);
    return res.render('feedback', { token: req.params.token, recipient, error: 'Please fill in all required fields.' });
  }

  const offersArray = !support_offers ? [] :
    Array.isArray(support_offers) ? support_offers : [support_offers];

  await db.createSubmission(link.id, {
    what_working_well, strengths, growth_opportunities,
    actionable_suggestions, collaboration, looking_ahead,
    anything_else, submitter_name, it_would_help,
    support_offers: offersArray, support_other
  });

  await db.markLinkUsed(req.params.token);
  res.render('thankyou', { state: 'success' });
});

// ─── START ──────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

db.init().then(() => {
  app.listen(PORT, () => console.log(`🌸 feedMe running on port ${PORT}`));
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
