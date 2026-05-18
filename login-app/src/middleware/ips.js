// ═══════════════════════════════════════════════════════════════
// middleware/ips.js
// IPS — Intrusion Prevention System (Software-based)
// NIM: 101032300137
// ═══════════════════════════════════════════════════════════════

'use strict';

// ─── IN-MEMORY STORE ──────────────────────────────────────────
const failedAttempts = new Map();
const blockedIPs     = new Map();
const alertLog       = [];
const MAX_ALERTS     = 100;

// ─── CONFIG ───────────────────────────────────────────────────
const CONFIG = {
  MAX_FAILED_LOGINS : 5,
  LOGIN_WINDOW_MS   : 60 * 1000,
  BLOCK_DURATION_MS : 10 * 60 * 1000,
  MAX_REQUESTS      : 60,
  RATE_WINDOW_MS    : 60 * 1000,
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
    id    : Date.now() + Math.random().toString(36).slice(2, 6),
    ts    : new Date().toISOString(),
    ip, type, detail, path, method,
  };
  alertLog.unshift(entry);
  if (alertLog.length > MAX_ALERTS) alertLog.pop();
  console.warn(`🚨 [IPS] BLOCKED | ${type.toUpperCase()} | IP: ${ip} | ${method} ${path} | ${detail}`);
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
  for (const v of Object.values(req.query || {})) targets.push(String(v));
  if (req.body && typeof req.body === 'object') {
    for (const v of Object.values(req.body)) targets.push(String(v));
  }
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
      const sisaDetik = Math.ceil((block.expiresAt - now) / 1000);
      console.warn(`🚫 [IPS] Blocked IP ${ip} mencoba akses ${req.path}`);
      return res.status(403).send(renderBlockPage(ip, block.reason, sisaDetik));
    } else {
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
    blockedIPs.set(ip, {
      blockedAt: now,
      expiresAt: now + CONFIG.BLOCK_DURATION_MS,
      reason   : `${scan.hit.toUpperCase()} Attack`,
    });
    const sisaDetik = Math.ceil(CONFIG.BLOCK_DURATION_MS / 1000);
    return res.status(403).send(renderBlockPage(ip, `${scan.hit.toUpperCase()} Attack`, sisaDetik));
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
        pushAlert({ ip, type: 'rate-limit', detail: `${entry.count} req/menit`, path: req.path, method: req.method });
        blockedIPs.set(ip, { blockedAt: now, expiresAt: now + CONFIG.BLOCK_DURATION_MS, reason: 'Rate Limit Exceeded' });
        return res.status(429).send(renderBlockPage(ip, 'Rate Limit Exceeded', Math.ceil(CONFIG.BLOCK_DURATION_MS / 1000)));
      }
    } else {
      failedAttempts.set(rateKey, { count: 1, firstSeen: now });
    }
  }

  next();
}

// ─── BRUTE-FORCE TRACKER ──────────────────────────────────────
function recordFailedLogin(ip) {
  const now = Date.now();
  if (!failedAttempts.has(ip)) {
    failedAttempts.set(ip, { count: 1, firstSeen: now });
  } else {
    const entry = failedAttempts.get(ip);
    if (now - entry.firstSeen > CONFIG.LOGIN_WINDOW_MS) {
      failedAttempts.set(ip, { count: 1, firstSeen: now });
    } else {
      entry.count++;
      if (entry.count >= CONFIG.MAX_FAILED_LOGINS) {
        blockedIPs.set(ip, {
          blockedAt: now,
          expiresAt: now + CONFIG.BLOCK_DURATION_MS,
          reason   : 'Brute-Force Login',
        });
        pushAlert({
          ip, type: 'brute-force',
          detail: `${entry.count} kali gagal login dalam ${CONFIG.LOGIN_WINDOW_MS / 1000}s`,
          path: '/login', method: 'POST',
        });
        return true;
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

// ─── HALAMAN BLOKIR — dengan Alert Banner + Countdown ─────────
function renderBlockPage(ip, reason, sisaDetik) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🚫 Akses Diblokir — IPS</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }
    /* ── ALERT BANNER (notif di atas) ── */
    .ips-banner {
      position: fixed; top: 0; left: 0; right: 0; z-index: 9999;
      background: linear-gradient(90deg, #dc2626, #b91c1c);
      color: #fff; padding: 13px 24px;
      display: flex; align-items: center; justify-content: space-between; gap: 10px;
      font-size: 14px; font-weight: 600;
      box-shadow: 0 4px 24px rgba(220,38,38,0.55);
      animation: slideDown 0.5s ease;
    }
    @keyframes slideDown { from{transform:translateY(-100%);opacity:0;} to{transform:translateY(0);opacity:1;} }
    .ips-banner .tag {
      background: rgba(255,255,255,0.2); border-radius: 6px;
      padding: 2px 8px; font-size: 11px; letter-spacing: 0.5px; flex-shrink:0;
    }
    .ips-banner .left { display:flex; align-items:center; gap:10px; flex:1; }
    .ips-banner .close-btn {
      background:none; border:none; color:rgba(255,255,255,0.7);
      font-size:18px; cursor:pointer; flex-shrink:0;
    }
    .ips-banner .close-btn:hover { color:#fff; }
    /* ── CARD ── */
    .card {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(239,68,68,0.35);
      border-radius: 24px; padding: 48px 40px;
      width: 100%; max-width: 480px;
      box-shadow: 0 0 60px rgba(239,68,68,0.15), 0 30px 60px rgba(0,0,0,0.5);
      text-align: center;
      margin-top: 56px;
      animation: fadeIn 0.4s ease;
    }
    @keyframes fadeIn { from{opacity:0;transform:translateY(20px);}to{opacity:1;transform:translateY(0);} }
    .shield { font-size:72px; display:block; margin-bottom:20px;
      filter:drop-shadow(0 0 20px rgba(239,68,68,0.6)); animation:pulse 2s infinite; }
    @keyframes pulse { 0%,100%{transform:scale(1);}50%{transform:scale(1.08);} }
    h1 { color:#fca5a5; font-size:26px; font-weight:800; margin-bottom:8px; }
    .sub { color:rgba(255,255,255,0.45); font-size:14px; margin-bottom:28px; }
    .badge {
      display:inline-flex; align-items:center; gap:6px;
      background:rgba(239,68,68,0.2); border:1px solid rgba(239,68,68,0.4);
      color:#fca5a5; padding:4px 12px; border-radius:100px;
      font-size:12px; font-weight:600; margin-bottom:20px;
    }
    .info-box {
      background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.25);
      border-radius:14px; padding:20px; margin-bottom:20px; text-align:left;
    }
    .row {
      display:flex; justify-content:space-between; align-items:center;
      padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.06); font-size:13px;
    }
    .row:last-child { border-bottom:none; }
    .lbl { color:rgba(255,255,255,0.45); }
    .val { color:#fca5a5; font-weight:600; font-family:monospace; }
    .timer-box {
      background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08);
      border-radius:12px; padding:18px; margin-bottom:24px;
      color:rgba(255,255,255,0.55); font-size:13px;
    }
    #countdown { font-size:32px; font-weight:800; color:#fbbf24; display:block; margin:8px 0 6px; }
    .footer { color:rgba(255,255,255,0.2); font-size:11px; }
    .footer b { color:#4ade80; }
  </style>
</head>
<body>

  <!-- ✅ NOTIFIKASI ALERT IPS — muncul otomatis di atas -->
  <div class="ips-banner" id="ipsBanner">
    <div class="left">
      <span>🚨</span>
      <span class="tag">IPS ALERT</span>
      <span>
        IPS berhasil memblokir serangan <strong>${reason}</strong> dari IP
        <code style="background:rgba(255,255,255,0.15);padding:1px 6px;border-radius:4px;font-size:13px;">${ip}</code>
      </span>
    </div>
    <button class="close-btn" onclick="document.getElementById('ipsBanner').style.display='none'">✕</button>
  </div>

  <div class="card">
    <span class="shield">🛡️</span>
    <div class="badge">🚫 IPS — AKSES DIBLOKIR</div>
    <h1>Koneksi Anda Diblokir</h1>
    <p class="sub">Sistem keamanan IPS mendeteksi aktivitas mencurigakan</p>

    <div class="info-box">
      <div class="row">
        <span class="lbl">IP Address</span>
        <span class="val">${ip}</span>
      </div>
      <div class="row">
        <span class="lbl">Jenis Serangan</span>
        <span class="val">${reason}</span>
      </div>
      <div class="row">
        <span class="lbl">Waktu Deteksi</span>
        <span class="val">${new Date().toLocaleString('id-ID')}</span>
      </div>
    </div>

    <div class="timer-box">
      ⏳ Akses kembali dalam:
      <span id="countdown">${sisaDetik}s</span>
      <small style="color:rgba(255,255,255,0.3);display:block;">Hubungi administrator jika ini kesalahan.</small>
    </div>

    <p class="footer"><b>🔒 IPS</b> · Intrusion Prevention System · NIM 101032300137</p>
  </div>

  <script>
    let sisa = ${sisaDetik};
    const el = document.getElementById('countdown');
    const iv = setInterval(() => {
      sisa--;
      if (sisa <= 0) { clearInterval(iv); el.textContent = 'Silakan coba lagi'; return; }
      const m = Math.floor(sisa / 60);
      const s = sisa % 60;
      el.textContent = m > 0 ? m + 'm ' + s + 's' : s + 's';
    }, 1000);
  </script>

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
