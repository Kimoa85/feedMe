require('dotenv').config();
const express = require('express');
const session = require('express-session');
const connectPg = require('connect-pg-simple');
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

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/');
}

// Email transporter (optional)
let transporter = null;
if (process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

// ─── ROUTES ────────────────────────────────────────────────────────

// GET / — Login/Signup
app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('login', { error: null, success: null, tab: 'login' });
});

// POST /login
app.post('/login', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.render('login', { error: 'Please enter your code.', success: null, tab: 'login' });

  const user = await db.getUserByCode(code.trim());
  if (!user) return res.render('login', { error: 'Invalid code. Please try again.', success: null, tab: 'login' });

  req.session.userId = user.id;
  req.session.displayName = user.display_name;
  res.redirect('/dashboard');
});

// POST /signup
app.post('/signup', async (req, res) => {
  const { display_name, code, email } = req.body;

  if (!display_name || !code) {
    return res.render('login', { error: 'Name and code are required.', success: null, tab: 'signup' });
  }
  if (code.trim().length < 4) {
    return res.render('login', { error: 'Code must be at least 4 characters.', success: null, tab: 'signup' });
  }
  if (await db.codeExists(code.trim())) {
    return res.render('login', { error: 'That code is already taken. Please choose another.', success: null, tab: 'signup' });
  }

  try {
    const user = await db.createUser(display_name.trim(), code.trim(), email?.trim() || null);
    req.session.userId = user.id;
    req.session.displayName = display_name.trim();
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

  const user = await db.getUserByEmail(email.trim());

  // Always show same message to avoid email enumeration
  if (!user) {
    return res.render('forgot', { error: null, success: 'If that email is registered, your code has been sent.' });
  }

  if (!transporter) {
    return res.render('forgot', { error: 'Email is not configured on this server. Please contact the admin.', success: null });
  }

  try {
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: user.email,
      subject: '🌸 Your Feedback App Login Code',
      html: `
        <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;background:#FFF0F5;border-radius:16px;">
          <h2 style="color:#FF69B4;margin-bottom:8px;">🌸 Your Login Code</h2>
          <p>Hi <strong>${user.display_name}</strong>! Here is your login code:</p>
          <div style="background:#fff;padding:20px;border-radius:12px;font-size:28px;text-align:center;letter-spacing:4px;font-weight:bold;color:#FF69B4;margin:20px 0;border:2px solid #FFB7C5;">
            ${user.code}
          </div>
          <p style="color:#aaa;font-size:12px;">If you didn't request this, you can ignore this email.</p>
        </div>
      `
    });
    res.render('forgot', { error: null, success: 'Your code has been sent to your email!' });
  } catch {
    res.render('forgot', { error: 'Failed to send email. Please try again.', success: null });
  }
});

// GET /f/:token — Feedback form
app.get('/f/:token', async (req, res) => {
  const link = await db.getLinkByToken(req.params.token);

  if (!link) return res.render('thankyou', { state: 'notfound' });
  if (link.used) return res.render('thankyou', { state: 'used' });

  const recipient = await db.getUserById(link.user_id);
  res.render('feedback', { token: req.params.token, recipient, error: null });
});

// POST /f/:token — Submit feedback
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
    return res.render('feedback', {
      token: req.params.token, recipient,
      error: 'Please fill in all required fields.'
    });
  }

  // support_offers comes as string or array from checkboxes
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
  app.listen(PORT, () => {
    console.log(`🌸 Feedback app running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
