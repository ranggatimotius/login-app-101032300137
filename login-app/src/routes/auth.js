const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const xss = require('xss');
const { body, validationResult } = require('express-validator');
const db = require('../config/db');
const { isAuthenticated, isGuest } = require('../middleware/auth');

router.get('/', (req, res) => res.redirect('/login'));

// ─── LOGIN PAGE ───────────────────────────────────────────────
router.get('/login', isGuest, (req, res) => {
  res.send(renderLoginPage({ error: null, success: null }));
});

router.post('/login', isGuest, [
  body('username').trim().isLength({ min: 3, max: 50 }).withMessage('Username harus antara 3–50 karakter')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username hanya boleh huruf, angka, dan underscore'),
  body('password').isLength({ min: 6, max: 128 }).withMessage('Password harus antara 6–128 karakter')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).send(renderLoginPage({ error: errors.array()[0].msg, success: null }));

  const username = xss(req.body.username.trim());
  const password = req.body.password;

  try {
    const [rows] = await db.execute('SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1', [username]);
    if (rows.length === 0) return res.status(401).send(renderLoginPage({ error: 'Username atau password salah', success: null }));

    const isMatch = await bcrypt.compare(password, rows[0].password_hash);
    if (!isMatch) return res.status(401).send(renderLoginPage({ error: 'Username atau password salah', success: null }));

    req.session.regenerate((err) => {
      if (err) throw err;
      req.session.userId = rows[0].id;
      req.session.username = rows[0].username;
      res.redirect('/home');
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send(renderLoginPage({ error: 'Terjadi kesalahan server', success: null }));
  }
});

// ─── REGISTER PAGE ────────────────────────────────────────────
router.get('/register', isGuest, (req, res) => {
  res.send(renderRegisterPage({ error: null, success: null }));
});

router.post('/register', isGuest, [
  body('username').trim().isLength({ min: 3, max: 50 }).withMessage('Username harus antara 3–50 karakter')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username hanya boleh huruf, angka, dan underscore'),
  body('email').trim().isEmail().withMessage('Format email tidak valid').isLength({ max: 100 }).withMessage('Email maksimal 100 karakter'),
  body('password').isLength({ min: 6, max: 128 }).withMessage('Password harus antara 6–128 karakter'),
  body('confirm_password').custom((value, { req }) => {
    if (value !== req.body.password) throw new Error('Konfirmasi password tidak cocok');
    return true;
  })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).send(renderRegisterPage({ error: errors.array()[0].msg, success: null }));

  const username = xss(req.body.username.trim());
  const email    = xss(req.body.email.trim().toLowerCase());
  const password = req.body.password;

  try {
    const [existingUser] = await db.execute('SELECT id FROM users WHERE username = ? LIMIT 1', [username]);
    if (existingUser.length > 0) return res.status(409).send(renderRegisterPage({ error: 'Username sudah digunakan', success: null }));

    const [existingEmail] = await db.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
    if (existingEmail.length > 0) return res.status(409).send(renderRegisterPage({ error: 'Email sudah terdaftar', success: null }));

    const password_hash = await bcrypt.hash(password, 12);
    await db.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, password_hash]);

    res.send(renderLoginPage({ error: null, success: `Akun berhasil dibuat! Silakan login, ${username}.` }));
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).send(renderRegisterPage({ error: 'Terjadi kesalahan server', success: null }));
  }
});

// ─── HOME PAGE ────────────────────────────────────────────────
router.get('/home', isAuthenticated, (req, res) => {
  res.send(renderHomePage({ username: xss(req.session.username) }));
});

// ─── LOGOUT ───────────────────────────────────────────────────
router.post('/logout', isAuthenticated, (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.redirect('/login');
  });
});

// ═══════════════════════════════════════════════════════════════
// SHARED STYLES
// ═══════════════════════════════════════════════════════════════
const sharedStyles = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', sans-serif;
    background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
  }
  .card {
    background: rgba(255,255,255,0.06);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 20px;
    padding: 40px 36px;
    width: 100%; max-width: 420px;
    box-shadow: 0 30px 60px rgba(0,0,0,0.4);
  }
  .logo { text-align: center; margin-bottom: 28px; }
  .logo-icon {
    width: 60px; height: 60px;
    background: linear-gradient(135deg, #667eea, #764ba2);
    border-radius: 16px;
    display: flex; align-items: center; justify-content: center;
    margin: 0 auto 14px; font-size: 26px;
  }
  h1 { color: #fff; font-size: 22px; margin-bottom: 4px; }
  .subtitle { color: rgba(255,255,255,0.45); font-size: 13px; }
  .form-group { margin-bottom: 16px; }
  label {
    display: block; color: rgba(255,255,255,0.65); font-size: 12px;
    margin-bottom: 7px; font-weight: 500; letter-spacing: 0.5px; text-transform: uppercase;
  }
  .input-wrap { position: relative; }
  .input-icon {
    position: absolute; left: 13px; top: 50%;
    transform: translateY(-50%); font-size: 15px;
    opacity: 0.5; pointer-events: none;
  }
  input {
    width: 100%; padding: 11px 14px 11px 38px;
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.13);
    border-radius: 10px; color: #fff; font-size: 14px; outline: none;
    transition: border-color 0.2s, background 0.2s;
  }
  input:focus { border-color: #667eea; background: rgba(102,126,234,0.1); }
  input::placeholder { color: rgba(255,255,255,0.25); }
  .btn {
    width: 100%; padding: 13px;
    background: linear-gradient(135deg, #667eea, #764ba2);
    border: none; border-radius: 10px; color: #fff;
    font-size: 15px; font-weight: 600; cursor: pointer;
    transition: opacity 0.2s, transform 0.1s; margin-top: 6px;
  }
  .btn:hover { opacity: 0.88; transform: translateY(-1px); }
  .btn:active { transform: translateY(0); }
  .alert {
    padding: 10px 14px; border-radius: 9px; font-size: 13px;
    margin-bottom: 18px; display: flex; align-items: center; gap: 8px;
  }
  .alert-error { background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.35); color: #fca5a5; }
  .alert-success { background: rgba(34,197,94,0.12); border: 1px solid rgba(34,197,94,0.35); color: #86efac; }
  .divider {
    display: flex; align-items: center; gap: 12px; margin: 20px 0;
    color: rgba(255,255,255,0.25); font-size: 12px;
  }
  .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: rgba(255,255,255,0.1); }
  .link-btn {
    display: block; text-align: center; padding: 11px;
    border: 1px solid rgba(255,255,255,0.15); border-radius: 10px;
    color: rgba(255,255,255,0.7); font-size: 14px; text-decoration: none;
    transition: background 0.2s, color 0.2s;
  }
  .link-btn:hover { background: rgba(255,255,255,0.07); color: #fff; }
  .link-btn span { color: #a78bfa; font-weight: 500; }
  .secure-badge {
    text-align: center; margin-top: 20px;
    color: rgba(255,255,255,0.25); font-size: 11px; letter-spacing: 0.3px;
  }
  .secure-badge b { color: #4ade80; font-weight: 500; }
`;

// ─── LOGIN TEMPLATE ───────────────────────────────────────────
function renderLoginPage({ error, success }) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login — SecureApp</title>
  <style>${sharedStyles}</style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <div class="logo-icon">🔐</div>
      <h1>Selamat Datang</h1>
      <p class="subtitle">Masuk ke akun Anda</p>
    </div>
    ${error   ? `<div class="alert alert-error">⚠️ ${error}</div>` : ''}
    ${success ? `<div class="alert alert-success">✅ ${success}</div>` : ''}
    <form method="POST" action="/login" autocomplete="off">
      <div class="form-group">
        <label>Username</label>
        <div class="input-wrap">
          <span class="input-icon">👤</span>
          <input type="text" name="username" placeholder="Masukkan username" maxlength="50" required>
        </div>
      </div>
      <div class="form-group">
        <label>Password</label>
        <div class="input-wrap">
          <span class="input-icon">🔑</span>
          <input type="password" name="password" placeholder="Masukkan password" maxlength="128" required>
        </div>
      </div>
      <button type="submit" class="btn">Masuk →</button>
    </form>
    <div class="divider">atau</div>
    <a href="/register" class="link-btn">Belum punya akun? <span>Daftar sekarang</span></a>
    <p class="secure-badge"><b>🔒 HTTPS</b> · Koneksi Aman · Bcrypt Encrypted</p>
  </div>
</body>
</html>`;
}

// ─── REGISTER TEMPLATE ───────────────────────────────────────
function renderRegisterPage({ error, success }) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Daftar — SecureApp</title>
  <style>${sharedStyles}</style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <div class="logo-icon">✨</div>
      <h1>Buat Akun Baru</h1>
      <p class="subtitle">Daftar untuk mulai menggunakan SecureApp</p>
    </div>
    ${error   ? `<div class="alert alert-error">⚠️ ${error}</div>` : ''}
    ${success ? `<div class="alert alert-success">✅ ${success}</div>` : ''}
    <form method="POST" action="/register" autocomplete="off">
      <div class="form-group">
        <label>Username</label>
        <div class="input-wrap">
          <span class="input-icon">👤</span>
          <input type="text" name="username" placeholder="Pilih username unik" maxlength="50" required>
        </div>
      </div>
      <div class="form-group">
        <label>Email</label>
        <div class="input-wrap">
          <span class="input-icon">📧</span>
          <input type="email" name="email" placeholder="contoh@email.com" maxlength="100" required>
        </div>
      </div>
      <div class="form-group">
        <label>Password</label>
        <div class="input-wrap">
          <span class="input-icon">🔑</span>
          <input type="password" name="password" placeholder="Minimal 6 karakter" maxlength="128" required>
        </div>
      </div>
      <div class="form-group">
        <label>Konfirmasi Password</label>
        <div class="input-wrap">
          <span class="input-icon">🔒</span>
          <input type="password" name="confirm_password" placeholder="Ulangi password" maxlength="128" required>
        </div>
      </div>
      <button type="submit" class="btn">Daftar Sekarang →</button>
    </form>
    <div class="divider">atau</div>
    <a href="/login" class="link-btn">Sudah punya akun? <span>Masuk di sini</span></a>
    <p class="secure-badge"><b>🔒 HTTPS</b> · Koneksi Aman · Bcrypt Encrypted</p>
  </div>
</body>
</html>`;
}

// ─── HOME TEMPLATE ────────────────────────────────────────────
function renderHomePage({ username }) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Home — SecureApp</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
      min-height: 100vh; display: flex; flex-direction: column;
    }
    header {
      background: rgba(0,0,0,0.25); backdrop-filter: blur(12px);
      border-bottom: 1px solid rgba(255,255,255,0.08);
      padding: 14px 32px; display: flex; align-items: center; justify-content: space-between;
    }
    .brand { color: #fff; font-size: 18px; font-weight: 700; }
    .brand span { color: #a78bfa; }
    .user-info { display: flex; align-items: center; gap: 12px; }
    .avatar {
      width: 36px; height: 36px;
      background: linear-gradient(135deg, #667eea, #764ba2);
      border-radius: 10px; display: flex; align-items: center; justify-content: center;
      color: #fff; font-weight: 700; font-size: 15px;
    }
    .username { color: rgba(255,255,255,0.75); font-size: 14px; }
    .btn-logout {
      padding: 7px 16px; background: rgba(167,139,250,0.15);
      border: 1px solid rgba(167,139,250,0.35); border-radius: 8px;
      color: #a78bfa; font-size: 13px; cursor: pointer; transition: background 0.2s;
    }
    .btn-logout:hover { background: rgba(167,139,250,0.28); }
    main { flex: 1; display: flex; align-items: center; justify-content: center; padding: 40px 20px; }
    .welcome-card { text-align: center; max-width: 520px; }
    .welcome-icon { font-size: 68px; margin-bottom: 20px; }
    h1 { color: #fff; font-size: 30px; margin-bottom: 10px; }
    h1 span { color: #a78bfa; }
    p { color: rgba(255,255,255,0.55); font-size: 15px; line-height: 1.7; }
    .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-top: 30px; }
    .stat-card {
      background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.09);
      border-radius: 14px; padding: 18px 12px;
    }
    .stat-value { font-size: 26px; margin-bottom: 6px; }
    .stat-label { color: rgba(255,255,255,0.45); font-size: 11px; letter-spacing: 0.3px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">Secure<span>App</span></div>
    <div class="user-info">
      <div class="avatar">${username.charAt(0).toUpperCase()}</div>
      <span class="username">${username}</span>
      <form method="POST" action="/logout" style="margin:0">
        <button type="submit" class="btn-logout">Keluar</button>
      </form>
    </div>
  </header>
  <main>
    <div class="welcome-card">
      <div class="welcome-icon">🎉</div>
      <h1>Halo, <span>${username}</span>!</h1>
      <p>Login berhasil. Anda sekarang berada di halaman utama aplikasi yang dilindungi dengan keamanan berlapis.</p>
      <div class="stats">
        <div class="stat-card"><div class="stat-value">🔐</div><div class="stat-label">HTTPS Aktif</div></div>
        <div class="stat-card"><div class="stat-value">🛡️</div><div class="stat-label">XSS Protected</div></div>
        <div class="stat-card"><div class="stat-value">💉</div><div class="stat-label">SQLi Blocked</div></div>
      </div>
    </div>
  </main>
</body>
</html>`;
}

module.exports = router;
