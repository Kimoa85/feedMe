require('dotenv').config();
const express = require('express');
const session = require('express-session');
const connectPg = require('connect-pg-simple');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const db = require('./db');

const app = express();
const PgSession = connectPg(session);

// Refuse to start in production without a real session secret
if (!process.env.SESSION_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: SESSION_SECRET environment variable is not set. Refusing to start.');
    process.exit(1);
  } else {
    console.warn('WARNING: SESSION_SECRET not set — using insecure default. Set this before deploying!');
  }
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1); // Required for secure cookies behind Railway's proxy

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    }
  }
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  store: new PgSession({ pool: db.pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'kawaii-feedback-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax',
    httpOnly: true,
    secure: 'auto'
  }
}));

// Wrap async route handlers so any thrown error goes to the global error handler
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/');
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  handler: (req, res) => res.render('login', {
    error: 'Too many login attempts. Please wait 15 minutes and try again.',
    success: null, tab: 'login'
  })
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  handler: (req, res) => res.render('login', {
    error: 'Too many sign up attempts. Please try again later.',
    success: null, tab: 'signup'
  })
});

const forgotLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  handler: (req, res) => res.render('forgot', {
    error: 'Too many requests. Please wait an hour and try again.',
    success: null
  })
});

const MAX_INPUT_LENGTH = 5000;

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
app.post('/login', loginLimiter, asyncHandler(async (req, res) => {
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
  req.session.save((err) => {
    if (err) return res.render('login', { error: 'Login failed. Please try again.', success: null, tab: 'login' });
    res.redirect('/dashboard');
  });
}));

// POST /signup
app.post('/signup', signupLimiter, asyncHandler(async (req, res) => {
  const { display_name, email, password, password_confirm } = req.body;

  if (!display_name || !email || !password)
    return res.render('login', { error: 'All fields are required.', success: null, tab: 'signup' });

  if (password.length < 6)
    return res.render('login', { error: 'Password must be at least 6 characters.', success: null, tab: 'signup' });

  if (password !== password_confirm)
    return res.render('login', { error: 'Passwords do not match.', success: null, tab: 'signup' });

  const existingUser = await db.getUserByEmail(email.trim().toLowerCase());

  if (existingUser && existingUser.password_hash)
    return res.render('login', { error: 'An account with that email already exists. Try logging in instead.', success: null, tab: 'signup' });

  const passwordHash = await bcrypt.hash(password, 12);

  if (existingUser && !existingUser.password_hash) {
    // Legacy account — upgrade with a password
    await db.updatePassword(existingUser.id, passwordHash);
    req.session.userId = existingUser.id;
    req.session.displayName = existingUser.display_name;
  } else {
    const user = await db.createUser(display_name.trim(), email.trim().toLowerCase(), passwordHash);
    req.session.userId = user.id;
    req.session.displayName = display_name.trim();
  }

  req.session.save((err) => {
    if (err) return res.render('login', { error: 'Something went wrong. Please try again.', success: null, tab: 'signup' });
    res.redirect('/dashboard');
  });
}));

// GET /logout
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Session destroy error:', err);
    res.redirect('/');
  });
});

// GET /dashboard
app.get('/dashboard', requireAuth, asyncHandler(async (req, res) => {
  const [user, submissions] = await Promise.all([
    db.getUserById(req.session.userId),
    db.getSubmissionsByUserId(req.session.userId)
  ]);
  const newToken = req.session.newToken || null;
  delete req.session.newToken;
  const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
  res.render('dashboard', { user, submissions, newToken, baseUrl });
}));

// POST /generate-link
app.post('/generate-link', requireAuth, asyncHandler(async (req, res) => {
  const token = uuidv4();
  await db.createFeedbackLink(req.session.userId, token);
  req.session.newToken = token;
  req.session.save((err) => {
    if (err) console.error('Session save error:', err);
    res.redirect('/dashboard');
  });
}));

// GET /forgot
app.get('/forgot', (req, res) => {
  res.render('forgot', { error: null, success: null });
});

// POST /forgot
app.post('/forgot', forgotLimiter, asyncHandler(async (req, res) => {
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

  const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
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
}));

// GET /reset/:token
app.get('/reset/:token', asyncHandler(async (req, res) => {
  const record = await db.getResetToken(req.params.token);
  if (!record) return res.render('reset', { token: null, error: 'This reset link is invalid or has expired.' });
  res.render('reset', { token: req.params.token, error: null });
}));

// POST /reset/:token
app.post('/reset/:token', asyncHandler(async (req, res) => {
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
}));

// GET /f/:token
app.get('/f/:token', asyncHandler(async (req, res) => {
  const link = await db.getLinkByToken(req.params.token);
  if (!link) return res.render('thankyou', { state: 'notfound' });
  if (link.used) return res.render('thankyou', { state: 'used' });
  const recipient = await db.getUserById(link.user_id);
  res.render('feedback', { token: req.params.token, recipient, error: null });
}));

// POST /f/:token
app.post('/f/:token', asyncHandler(async (req, res) => {
  const link = await db.getLinkByToken(req.params.token);
  if (!link) return res.render('thankyou', { state: 'notfound' });
  if (link.used) return res.render('thankyou', { state: 'used' });

  const {
    what_working_well, strengths, growth_opportunities,
    actionable_suggestions, collaboration, looking_ahead,
    anything_else, submitter_name, support_offers, support_other
  } = req.body;

  if (!what_working_well || !strengths || !growth_opportunities ||
      !actionable_suggestions || !collaboration || !looking_ahead) {
    const recipient = await db.getUserById(link.user_id);
    return res.render('feedback', { token: req.params.token, recipient, error: 'Please fill in all required fields.' });
  }

  const fields = [what_working_well, strengths, growth_opportunities, actionable_suggestions,
    collaboration, looking_ahead, anything_else, support_other];
  if (fields.some(f => f && f.length > MAX_INPUT_LENGTH)) {
    const recipient = await db.getUserById(link.user_id);
    return res.render('feedback', { token: req.params.token, recipient, error: `Please keep each answer under ${MAX_INPUT_LENGTH} characters.` });
  }

  const offersArray = !support_offers ? [] :
    Array.isArray(support_offers) ? support_offers : [support_offers];

  await db.createSubmission(link.id, {
    what_working_well, strengths, growth_opportunities,
    actionable_suggestions, collaboration, looking_ahead,
    anything_else, submitter_name, support_offers: offersArray, support_other
  });

  await db.markLinkUsed(req.params.token);
  res.render('thankyou', { state: 'success' });
}));

// ─── GLOBAL ERROR HANDLER ────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).send(
    '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>feedMe — Error</title>' +
    '<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#FFF0F5;}' +
    '.box{text-align:center;padding:40px;max-width:400px;}h2{color:#FF69B4;}p{color:#7A5040;}</style></head>' +
    '<body><div class="box"><h2>🍰 Something went wrong</h2>' +
    '<p>We hit an unexpected error. Please try again or go back.</p>' +
    '<a href="/" style="color:#FF69B4;">← Back to home</a></div></body></html>'
  );
});

// ─── START ──────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

if (require.main === module) {
  db.init().then(() => {
    app.listen(PORT, () => console.log(`🌸 feedMe running on port ${PORT}`));
  }).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
}

module.exports = app;
