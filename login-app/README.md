# 🔐 Secure Login Application
**NIM: 101032300137**

Aplikasi web login aman menggunakan Node.js + Express + MySQL dengan Docker.

---

## 📁 Struktur Folder

```
login-app/
├── src/
│   ├── app.js                  # Entry point, HTTPS server, middleware
│   ├── config/
│   │   └── db.js               # Konfigurasi koneksi MySQL (connection pool)
│   ├── middleware/
│   │   └── auth.js             # Middleware autentikasi session
│   └── routes/
│       └── auth.js             # Route login, logout, home + HTML templates
├── ssl/
│   └── generate-cert.sh        # Script generate SSL self-signed certificate
├── mysql-init/
│   └── 01_init.sql             # SQL: buat database, tabel, user, data demo
├── Dockerfile                  # Multi-stage build image Node.js
├── docker-compose.yml          # Orkestrasi 2 container
├── .dockerignore
├── package.json
└── README.md
```

---

## 🛡️ Fitur Keamanan

| Keamanan | Implementasi |
|---|---|
| **Hashing Password** | `bcryptjs` dengan salt rounds 12 |
| **SQL Injection** | Prepared statements via `mysql2` |
| **XSS** | Sanitasi input dengan library `xss` |
| **Buffer Overflow** | Validasi panjang input (username max 50, password max 128 char) |
| **HTTP Security Headers** | `helmet` (CSP, HSTS, X-Frame-Options, dll) |
| **HTTPS** | SSL self-signed certificate via `openssl` |
| **Session Secure** | `httpOnly`, `secure`, `sameSite: strict` |
| **Body Size Limit** | Express body parser dibatasi `10kb` |
| **Least Privilege DB** | User `appuser` hanya punya akses SELECT/INSERT/UPDATE |

---

## 🚀 Cara Menjalankan

### Prasyarat
- Docker Desktop / Docker Engine terinstall
- Docker Compose terinstall

### Langkah 1 — Clone / Salin Project
```bash
cd /path/ke/folder/anda
# Pastikan semua file sudah ada sesuai struktur di atas
```

### Langkah 2 — Build dan Jalankan
```bash
docker-compose up --build -d
```

Output yang diharapkan:
```
✅ db-101032300137 ... Started
✅ web-101032300137 ... Started
```

### Langkah 3 — Cek Status Container
```bash
docker ps
# Harus muncul 2 container: web-101032300137 dan db-101032300137
```

### Langkah 4 — Akses Aplikasi
Buka browser, pergi ke:
```
https://localhost:3000
```
> ⚠️ Browser akan memberi peringatan SSL karena self-signed certificate.
> Klik **"Advanced" → "Proceed to localhost"** untuk melanjutkan.

### Langkah 5 — Login dengan Akun Demo
```
Username : admin
Password : Password123!

Username : demouser
Password : Password123!
```

---

## 🗄️ Contoh Query Database

```sql
-- 1. LOGIN (Prepared Statement - anti SQL Injection)
SELECT id, username, password_hash
FROM users
WHERE username = ?
LIMIT 1;

-- 2. DAFTAR SEMUA USER
SELECT id, username, email, created_at, last_login, is_active
FROM users;

-- 3. BUAT USER BARU (hash dulu password dengan bcrypt!)
INSERT INTO users (username, password_hash, email)
VALUES ('newuser', '$2a$12$...hashbcrypt...', 'new@example.com');

-- 4. AUDIT LOG LOGIN
SELECT username, ip_address, status, attempted_at
FROM login_logs
ORDER BY attempted_at DESC
LIMIT 20;
```

---

## 🔧 Perintah Berguna

```bash
# Lihat log web app
docker logs -f web-101032300137

# Lihat log database
docker logs -f db-101032300137

# Masuk ke container web
docker exec -it web-101032300137 sh

# Masuk ke MySQL
docker exec -it db-101032300137 mysql -u appuser -pAppPassword123! loginapp

# Hentikan semua container
docker-compose down

# Hentikan dan hapus volume (reset database)
docker-compose down -v

# Rebuild ulang
docker-compose up --build -d
```

---

## 🌐 Port

| Service | Port |
|---|---|
| Web App (HTTPS) | `3000` |
| MySQL | `3306` |

---

## ⚙️ Environment Variables

| Variabel | Default | Keterangan |
|---|---|---|
| `PORT` | `3000` | Port HTTPS server |
| `DB_HOST` | `db-101032300137` | Hostname database |
| `DB_USER` | `appuser` | User MySQL |
| `DB_PASSWORD` | `AppPassword123!` | Password MySQL |
| `DB_NAME` | `loginapp` | Nama database |
| `SESSION_SECRET` | *(lihat compose)* | Secret untuk session |

> **⚠️ Produksi:** Ganti semua password dan session secret di `docker-compose.yml`!
