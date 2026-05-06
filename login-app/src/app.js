const https = require('https');
const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require ('express-rate-limit');

const authRoutes = require('./routes/auth');

const app = express();

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: JSON.stringify({error: 'Terlalu banyak percobaan login'}),
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      // Tampilkan halaman HTML bukan JSON mentah
        res.status(429).send(`<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login — SecureApp</title>
  <style>
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
      text-align: center;
    }
    .icon { font-size: 64px; margin-bottom: 20px; }
    h1 { color: #fff; font-size: 22px; margin-bottom: 12px; }
    p { color: rgba(255,255,255,0.6); font-size: 14px; line-height: 1.6; margin-bottom: 24px; }
    .alert {
      background: rgba(239,68,68,0.12);
      border: 1px solid rgba(239,68,68,0.35);
      color: #fca5a5;
      padding: 12px 16px;
      border-radius: 9px;
      font-size: 13px;
      margin-bottom: 20px;
    }
    .btn {
      display: inline-block;
      padding: 11px 24px;
      background: linear-gradient(135deg, #667eea, #764ba2);
      border-radius: 10px;
      color: #fff;
      font-size: 14px;
      text-decoration: none;
      transition: opacity 0.2s;
    }
    .btn:hover { opacity: 0.85; }
    .timer { color: #a78bfa; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🚫</div>
    <h1>Akses Diblokir Sementara</h1>
    <div class="alert">
      ⚠️ Terlalu banyak percobaan login yang gagal dari IP kamu
    </div>
    <p>Demi keamanan akun, login dari IP ini diblokir sementara.<br>
    Silakan coba lagi dalam <span class="timer">15 menit</span>.</p>
    <a href="/login" class="btn">← Kembali ke Login</a>
    <p style="margin-top:16px;font-size:11px;color:rgba(255,255,255,0.25)">
      🔒 Brute Force Protection Aktif
    </p>
  </div>
</body>
</html>`);
    }
});

app.use('/login', loginLimiter);

// ─── SECURITY MIDDLEWARE ──────────────────────────────────────
// Helmet: sets secure HTTP headers (XSS filter, HSTS, nosniff, etc.)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// ─── BODY PARSING ─────────────────────────────────────────────
app.use(express.urlencoded({ extended: false, limit: '10kb' })); // limit body size
app.use(express.json({ limit: '10kb' }));

// ─── SESSION ──────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || 'SuperSecretKey_101032300137_ChangeInProduction!',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,       // JS tidak bisa akses cookie
    secure: true,         // Hanya via HTTPS
    sameSite: 'strict',   // Proteksi CSRF
    maxAge: 1000 * 60 * 60 // 1 jam
  }
}));

// ─── ROUTES ───────────────────────────────────────────────────
app.use('/', authRoutes);

// ─── 404 HANDLER ──────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).send('<h1 style="font-family:sans-serif;text-align:center;margin-top:100px;color:#e94560">404 - Halaman tidak ditemukan</h1>');
});

// ─── START HTTPS SERVER ───────────────────────────────────────
const PORT = process.env.PORT || 3000;

const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, '../ssl/server.key')),
  cert: fs.readFileSync(path.join(__dirname, '../ssl/server.cert'))
};

// HTTP server untuk testing Snort (port 8000)
const http = require('http');
http.createServer(app).listen(8000, () => {
  console.log('HTTP server (testing): http://localhost:8000');
});

https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`\n✅ Server berjalan di https://localhost:${PORT}`);
  console.log(`🔐 HTTPS aktif dengan SSL self-signed certificate`);
  console.log(`🛡️  Helmet security middleware aktif`);
});
