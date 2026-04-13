-- ============================================================
-- Database Initialization Script
-- Aplikasi Login Aman - NIM: 101032300137
-- ============================================================

CREATE DATABASE IF NOT EXISTS loginapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE loginapp;

-- Buat user aplikasi dengan hak akses minimal
CREATE USER IF NOT EXISTS 'appuser'@'%' IDENTIFIED BY 'AppPassword123!';
GRANT SELECT, INSERT, UPDATE ON loginapp.* TO 'appuser'@'%';
FLUSH PRIVILEGES;

-- ─── TABEL USERS ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  username      VARCHAR(50)      NOT NULL,
  password_hash VARCHAR(255)     NOT NULL,   -- bcrypt hash (60 char)
  email         VARCHAR(100)         NULL,
  created_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login    DATETIME             NULL,
  is_active     TINYINT(1)       NOT NULL DEFAULT 1,
  PRIMARY KEY (id),
  UNIQUE KEY uq_username (username),
  UNIQUE KEY uq_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ─── TABEL LOGIN AUDIT ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS login_logs (
  id          INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  user_id     INT UNSIGNED      NULL,
  username    VARCHAR(50)   NOT NULL,
  ip_address  VARCHAR(45)       NULL,
  status      ENUM('success','failed') NOT NULL,
  attempted_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX idx_username (username),
  INDEX idx_attempted_at (attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ─── DATA DEMO ────────────────────────────────────────────────
-- Password untuk semua user demo: "Password123!"
-- Hash dibuat dengan: bcrypt.hash("Password123!", 12)

INSERT INTO users (username, password_hash, email) VALUES
  ('admin',    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lfSXqDkDfBvSvWZ5e', 'admin@example.com'),
  ('demouser', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/lfSXqDkDfBvSvWZ5e', 'demo@example.com')
ON DUPLICATE KEY UPDATE id=id;

-- ─── CONTOH QUERY YANG DIGUNAKAN APLIKASI ────────────────────
-- 1. Login (Prepared Statement - AMAN dari SQL Injection):
--    SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1;
--
-- 2. Audit log:
--    INSERT INTO login_logs (user_id, username, ip_address, status) VALUES (?, ?, ?, ?);
--
-- 3. Update last login:
--    UPDATE users SET last_login = NOW() WHERE id = ?;
