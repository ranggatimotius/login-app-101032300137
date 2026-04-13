const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const xss = require('xss');
const { body, validationResult } = require('express-validator');
const db = require('../config/db');
const { isAuthenticated, isGuest } = require('../middleware/auth');

// ─── LOGIN PAGE ───────────────────────────────────────────────
router.get('/login', isGuest, (req, res) => {
  res.send(renderLoginPage({ error: null }));
});

// ─── LOGIN HANDLER ────────────────────────────────────────────
router.post('/login',
  isGuest,
  [
    // Input validation & length limiting (prevents buffer overflow)
    body('username')
      .trim()
      .isLength({ min: 3, max: 50 })
      .withMessage('Username harus antara 3–50 karakter')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username hanya boleh huruf, angka, dan underscore'),

    body('password')
      .isLength({ min: 6, max: 128 })
      .withMessage('Password harus antara 6–128 karakter')
  ],
  async (req, res) => {
    // Validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMsg = errors.array()[0].msg;
      return res.status(400).send(renderLoginPage({ error: errorMsg }));
    }

    // XSS sanitasi input
    const username = xss(req.body.username.trim());
    const password = req.body.password;

    try {
      // Prepared statement → proteksi SQL Injection
      const [rows] = await db.execute(
        'SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1',
        [username]
      );

      if (rows.length === 0) {
        return res.status(401).send(renderLoginPage({ error: 'Username atau password salah' }));
      }

      const user = rows[0];

      // Verifikasi password dengan bcrypt
      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) {
        return res.status(401).send(renderLoginPage({ error: 'Username atau password salah' }));
      }

      // Buat session
      req.session.regenerate((err) => {
        if (err) throw err;
        req.session.userId = user.id;
        req.session.username = user.username;
        res.redirect('/home');
      });

    } catch (err) {
      console.error('Login error:', err);
      res.status(500).send(renderLoginPage({ error: 'Terjadi kesalahan server' }));
    }
  }
);

// ─── HOME PAGE ────────────────────────────────────────────────
router.get('/home', isAuthenticated, (req, res) => {
  const username = xss(req.session.username);
  res.send(renderHomePage({ username }));
});

// ─── LOGOUT ───────────────────────────────────────────────────
router.post('/logout', isAuthenticated, (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.redirect('/login');
  });
});

// Root redirect
router.get('/', (req, res) => res.redirect('/login'));

// ─── HTML TEMPLATES ───────────────────────────────────────────
function renderLoginPage({ error }) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .card {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 25px 45px rgba(0,0,0,0.3);
    }
    .logo {
      text-align: center;
      margin-bottom: 30px;
    }
    .logo-icon {
      width: 64px;
      height: 64px;
      background: linear-gradient(135deg, #e94560, #0f3460);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 16px;
      font-size: 28px;
    }
    h1 { color: #fff; font-size: 24px; margin-bottom: 4px; }
    .subtitle { color: rgba(255,255,255,0.5); font-size: 14px; }
    .form-group { margin-bottom: 20px; }
    label { display: block; color: rgba(255,255,255,0.7); font-size: 13px; margin-bottom: 8px; font-weight: 500; }
    input {
      width: 100%;
      padding: 12px 16px;
      background: rgba(255,255,255,0.08);
      border: 1px solid rgba(255,255,255,0.15);
      border-radius: 8px;
      color: #fff;
      font-size: 15px;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus { border-color: #e94560; }
    input::placeholder { color: rgba(255,255,255,0.3); }
    .btn {
      width: 100%;
      padding: 13px;
      background: linear-gradient(135deg, #e94560, #c0392b);
      border: none;
      border-radius: 8px;
      color: #fff;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s, transform 0.1s;
      margin-top: 8px;
    }
    .btn:hover { opacity: 0.9; transform: translateY(-1px); }
    .btn:active { transform: translateY(0); }
    .error {
      background: rgba(233,69,96,0.15);
      border: 1px solid rgba(233,69,96,0.4);
      color: #ff6b6b;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      margin-bottom: 20px;
    }
    .secure-badge {
      text-align: center;
      margin-top: 20px;
      color: rgba(255,255,255,0.3);
      font-size: 12px;
    }
    .secure-badge span { color: #4ade80; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <div class="logo-icon">🔐</div>
      <h1>Selamat Datang</h1>
      <p class="subtitle">Masuk ke akun Anda</p>
    </div>
    ${error ? `<div class="error">⚠️ ${error}</div>` : ''}
    <form method="POST" action="/login" autocomplete="off">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username"
          placeholder="Masukkan username"
          maxlength="50" required>
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password"
          placeholder="Masukkan password"
          maxlength="128" required>
      </div>
      <button type="submit" class="btn">Masuk →</button>
    </form>
    <p class="secure-badge"><span>🔒 HTTPS</span> · Koneksi Aman · Bcrypt Encrypted</p>
  </div>
</body>
</html>`;
}

function renderHomePage({ username }) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Home</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: rgba(0,0,0,0.3);
      backdrop-filter: blur(10px);
      border-bottom: 1px solid rgba(255,255,255,0.1);
      padding: 16px 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .brand { color: #fff; font-size: 18px; font-weight: 700; }
    .brand span { color: #e94560; }
    .user-info { display: flex; align-items: center; gap: 12px; }
    .avatar {
      width: 38px; height: 38px;
      background: linear-gradient(135deg, #e94560, #0f3460);
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      color: #fff; font-weight: 700; font-size: 16px;
    }
    .username { color: rgba(255,255,255,0.8); font-size: 14px; }
    .btn-logout {
      padding: 8px 16px;
      background: rgba(233,69,96,0.2);
      border: 1px solid rgba(233,69,96,0.4);
      border-radius: 6px;
      color: #e94560;
      font-size: 13px;
      cursor: pointer;
      transition: background 0.2s;
    }
    .btn-logout:hover { background: rgba(233,69,96,0.35); }
    main {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px 20px;
    }
    .welcome-card {
      text-align: center;
      max-width: 500px;
    }
    .welcome-icon { font-size: 72px; margin-bottom: 24px; }
    h1 { color: #fff; font-size: 32px; margin-bottom: 12px; }
    h1 span { color: #e94560; }
    p { color: rgba(255,255,255,0.6); font-size: 16px; line-height: 1.6; }
    .stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      margin-top: 32px;
    }
    .stat-card {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      padding: 20px;
    }
    .stat-value { color: #e94560; font-size: 28px; font-weight: 700; }
    .stat-label { color: rgba(255,255,255,0.5); font-size: 12px; margin-top: 4px; }
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
      <p>Login berhasil. Anda sekarang berada di halaman utama aplikasi yang dilindungi.</p>
      <div class="stats">
        <div class="stat-card">
          <div class="stat-value">🔐</div>
          <div class="stat-label">HTTPS Aktif</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">🛡️</div>
          <div class="stat-label">XSS Protected</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">💉</div>
          <div class="stat-label">SQLi Blocked</div>
        </div>
      </div>
    </div>
  </main>
</body>
</html>`;
}

module.exports = router;
