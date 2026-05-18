// ═══════════════════════════════════════════════════════════════
// middleware/ips.js
// IPS — Intrusion Prevention System (Software-based)
// NIM: 101032300137
// ═══════════════════════════════════════════════════════════════

'use strict';

// ─── IN-MEMORY STORE ──────────────────────────────────────────
// { ip: { count, firstSeen, blockedAt, reason } }
const failedAttempts = new Map();

// { ip: { blockedAt, reason, expiresAt } }
const blockedIPs = new Map();

// Ring buffer: max 100 alert entries
const alertLog = [];
const MAX_ALERTS = 100;

// ─── CONFIG ───────────────────────────────────────────────────
const CONFIG = {
  // Brute-force: max gagal login dalam window
  MAX_FAILED_LOGINS : 5,
  LOGIN_WINDOW_MS   : 60 * 1000,       // 1 menit
  BLOCK_DURATION_MS : 10 * 60 * 1000,  // 10 menit

  // Rate-limit umum: max req dalam window
  MAX_REQUESTS      : 60,
  RATE_WINDOW_MS    : 60 * 1000,       // 1 menit per IP
};

// ─── PATTERN DETEKSI ──────────────────────────────────────────
const PATTERNS = {
  sqli: [
    /(\b(union|select|insert|update|delete|drop|alter|create|exec|execute|xp_|sp_)\b)/i,
    /('|")\s*(or|and)\s*('|"|\d)/i,
    /--\s|;--|\/\*[\s\S]*?\*\//,
    /\b(sleep|benchmark|waitfor|delay)\s*\(/i,
    /0x[0-9a-f]{2,}/i,
  ],
  xss: [
    /<script[\s>]/i,
    /javascript\s*:/i,
    /on\w+\s*=/i,
    /<iframe|<object|<embed|<svg/i,
    /expression\s*\(/i,
  ],
  pathTraversal: [
    /\.\.[/\\]/,
    /%2e%2e[%2f%5c]/i,
    /\.\.(\/|%2f)/i,
  ],
  cmdInjection: [
    /[;&|`]\s*(ls|cat|rm|wget|curl|bash|sh|python|nc)\b/i,
    /\$\(.*\)/,
    /`[^`]+`/,
  ],
};

// ─── HELPER: SIMPAN ALERT ─────────────────────────────────────
function pushAlert({ ip, type, detail, path, method }) {
  const entry = {
    id      : Date.now() + Math.random().toString(36).slice(2, 6),
    ts      : new Date().toISOString(),
    ip,
    type,
    detail,
    path,
    method,
  };
  alertLog.unshift(entry);          // terbaru di depan
  if (alertLog.length > MAX_ALERTS) alertLog.pop();

  // Log ke console juga
  console.warn(
    `🚨 [IPS] BLOCKED | ${type.toUpperCase()} | IP: ${ip} | ${method} ${path} | ${detail}`
  );
  return entry;
}

// ─── HELPER: CEK PATTERN ──────────────────────────────────────
function detectPattern(str) {
  if (typeof str !== 'string') return null;
  for (const [type, patterns] of Object.entries(PATTERNS)) {
    for (const re of patterns) {
      if (re.test(str)) return type;
    }
  }
  return null;
}

// ─── HELPER: SCAN SELURUH REQUEST ────────────────────────────
function scanRequest(req) {
  const targets = [];

  // Query string
  for (const v of Object.values(req.query || {})) targets.push(String(v));

  // Body (sudah di-parse express)
  if (req.body && typeof req.body === 'object') {
    for (const v of Object.values(req.body)) targets.push(String(v));
  }

  // URL path
  targets.push(req.path);

  for (const t of targets) {
    const hit = detectPattern(t);
    if (hit) return { hit, snippet: t.slice(0, 80) };
  }
  return null;
}

// ─── HELPER: DAPATKAN IP ─────────────────────────────────────
function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

// ─── MAIN IPS MIDDLEWARE ──────────────────────────────────────
function ipsMiddleware(req, res, next) {
  const ip  = getIP(req);
  const now = Date.now();

  // 1. Cek apakah IP sudah diblokir
  if (blockedIPs.has(ip)) {
    const block = blockedIPs.get(ip);
    if (now < block.expiresAt) {
      const sisaMenit = Math.ceil((block.expiresAt - now) / 60000);
      console.warn(`🚫 [IPS] Blocked IP ${ip} mencoba akses ${req.path}`);
      return res.status(403).send(renderBlockPage(ip, block.reason, sisaMenit));
    } else {
      // Masa blokir habis, hapus
      blockedIPs.delete(ip);
      failedAttempts.delete(ip);
    }
  }

  // 2. Scan payload / URL untuk serangan
  const scan = scanRequest(req);
  if (scan) {
    pushAlert({
      ip,
      type  : scan.hit,
      detail: `Payload terdeteksi: "${scan.snippet}"`,
      path  : req.path,
      method: req.method,
    });

    // Blokir IP langsung
    blockedIPs.set(ip, {
      blockedAt: now,
      expiresAt: now + CONFIG.BLOCK_DURATION_MS,
      reason   : `${scan.hit.toUpperCase()} Attack`,
    });

    const sisaMenit = Math.ceil(CONFIG.BLOCK_DURATION_MS / 60000);
    return res.status(403).send(renderBlockPage(ip, `${scan.hit.toUpperCase()} Attack`, sisaMenit));
  }

  // 3. Rate-limiting umum
  const rateKey = `rate_${ip}`;
  if (!failedAttempts.has(rateKey)) {
    failedAttempts.set(rateKey, { count: 1, firstSeen: now });
  } else {
    const entry = failedAttempts.get(rateKey);
    if (now - entry.firstSeen < CONFIG.RATE_WINDOW_MS) {
      entry.count++;
      if (entry.count > CONFIG.MAX_REQUESTS) {
        pushAlert({
          ip,
          type  : 'rate-limit',
          detail: `Terlalu banyak request: ${entry.count} req/menit`,
          path  : req.path,
          method: req.method,
        });
        blockedIPs.set(ip, {
          blockedAt: now,
          expiresAt: now + CONFIG.BLOCK_DURATION_MS,
          reason   : 'Rate Limit Exceeded',
        });
        return res.status(429).send(renderBlockPage(ip, 'Rate Limit Exceeded', Math.ceil(CONFIG.BLOCK_DURATION_MS / 60000)));
      }
    } else {
      // Reset window
      failedAttempts.set(rateKey, { count: 1, firstSeen: now });
    }
  }

  next();
}

// ─── BRUTE-FORCE TRACKER (dipanggil dari route login) ─────────
function recordFailedLogin(ip) {
  const now = Date.now();
  if (!failedAttempts.has(ip)) {
    failedAttempts.set(ip, { count: 1, firstSeen: now });
  } else {
    const entry = failedAttempts.get(ip);
    if (now - entry.firstSeen > CONFIG.LOGIN_WINDOW_MS) {
      // Reset jika window sudah lewat
      failedAttempts.set(ip, { count: 1, firstSeen: now });
    } else {
      entry.count++;
      if (entry.count >= CONFIG.MAX_FAILED_LOGINS) {
        // BLOKIR
        blockedIPs.set(ip, {
          blockedAt: now,
          expiresAt: now + CONFIG.BLOCK_DURATION_MS,
          reason   : 'Brute-Force Login',
        });
        pushAlert({
          ip,
          type  : 'brute-force',
          detail: `${entry.count} kali gagal login dalam ${CONFIG.LOGIN_WINDOW_MS / 1000}s`,
          path  : '/login',
          method: 'POST',
        });
        return true; // sudah diblokir
      }
    }
  }
  return false;
}

function resetLoginAttempts(ip) {
  failedAttempts.delete(ip);
}

// ─── GETTER UNTUK API ─────────────────────────────────────────
function getAlerts()     { return alertLog; }
function getBlockedIPs() { return [...blockedIPs.entries()].map(([ip, v]) => ({ ip, ...v })); }
function getStats() {
  return {
    totalBlocked : blockedIPs.size,
    totalAlerts  : alertLog.length,
    recentAlerts : alertLog.slice(0, 5),
  };
}

// ─── HALAMAN BLOKIR (HTML) ────────────────────────────────────
function renderBlockPage(ip, reason, sisaMenit) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🚫 Akses Diblokir — IPS</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(239,68,68,0.35);
      border-radius: 24px;
      padding: 48px 40px;
      width: 100%; max-width: 480px;
      box-shadow: 0 0 60px rgba(239,68,68,0.15), 0 30px 60px rgba(0,0,0,0.5);
      text-align: center;
      animation: fadeIn 0.4s ease;
    }
    @keyframes fadeIn { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
    .shield-icon {
      font-size: 72px;
      margin-bottom: 20px;
      display: block;
      filter: drop-shadow(0 0 20px rgba(239,68,68,0.6));
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%,100%{transform:scale(1);} 50%{transform:scale(1.08);} }
    h1 { color: #fca5a5; font-size: 26px; font-weight: 800; margin-bottom: 8px; }
    .subtitle { color: rgba(255,255,255,0.45); font-size: 14px; margin-bottom: 28px; }
    .info-box {
      background: rgba(239,68,68,0.08);
      border: 1px solid rgba(239,68,68,0.25);
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 20px;
      text-align: left;
    }
    .info-row {
      display: flex; justify-content: space-between; align-items: center;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      font-size: 13px;
    }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: rgba(255,255,255,0.45); }
    .info-value { color: #fca5a5; font-weight: 600; font-family: monospace; }
    .badge-blocked {
      display: inline-flex; align-items: center; gap: 6px;
      background: rgba(239,68,68,0.2); border: 1px solid rgba(239,68,68,0.4);
      color: #fca5a5; padding: 4px 12px; border-radius: 100px; font-size: 12px; font-weight: 600;
      margin-bottom: 20px;
    }
    .timer-box {
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px; padding: 14px;
      color: rgba(255,255,255,0.55); font-size: 13px;
      margin-bottom: 24px;
    }
    .timer-box strong { color: #fbbf24; }
    .footer { color: rgba(255,255,255,0.2); font-size: 11px; margin-top: 8px; }
    .footer b { color: #4ade80; }
  </style>
</head>
<body>
  <div class="card">
    <span class="shield-icon">🛡️</span>
    <div class="badge-blocked">🚫 IPS — AKSES DIBLOKIR</div>
    <h1>Koneksi Anda Diblokir</h1>
    <p class="subtitle">Sistem keamanan IPS mendeteksi aktivitas mencurigakan dari IP Anda</p>

    <div class="info-box">
      <div class="info-row">
        <span class="info-label">IP Address</span>
        <span class="info-value">${ip}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Alasan Blokir</span>
        <span class="info-value">${reason}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Waktu Blokir</span>
        <span class="info-value">${new Date().toLocaleString('id-ID')}</span>
      </div>
    </div>

    <div class="timer-box">
      ⏳ Blokir akan berakhir dalam <strong>±${sisaMenit} menit</strong>.<br>
      Jika Anda merasa ini adalah kesalahan, hubungi administrator.
    </div>

    <p class="footer"><b>🔒 IPS</b> · Intrusion Prevention System · NIM 101032300137</p>
  </div>
</body>
</html>`;
}

module.exports = {
  ipsMiddleware,
  recordFailedLogin,
  resetLoginAttempts,
  getAlerts,
  getBlockedIPs,
  getStats,
  getIP,
};
