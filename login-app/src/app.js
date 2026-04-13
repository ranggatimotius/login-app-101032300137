const https = require('https');
const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');

const authRoutes = require('./routes/auth');

const app = express();

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

https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`\n✅ Server berjalan di https://localhost:${PORT}`);
  console.log(`🔐 HTTPS aktif dengan SSL self-signed certificate`);
  console.log(`🛡️  Helmet security middleware aktif`);
});
