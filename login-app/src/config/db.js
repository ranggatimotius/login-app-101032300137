const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'db-101032300137',
  user: process.env.DB_USER || 'appuser',
  password: process.env.DB_PASSWORD || 'AppPassword123!',
  database: process.env.DB_NAME || 'loginapp',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
