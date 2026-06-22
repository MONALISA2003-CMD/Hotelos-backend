// db.js — PostgreSQL connection pool + auto-migration on boot.
// Railway injects DATABASE_URL automatically when you attach a Postgres plugin to this service.
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is not set. Attach a PostgreSQL database to this service in Railway.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Railway's internal Postgres doesn't need SSL; their public proxy URL does.
  // This handles both without you needing to know which one you're using.
  ssl: process.env.DATABASE_URL.includes('railway.internal') ? false : { rejectUnauthorized: false }
});

pool.on('error', (err) => {
  console.error('Unexpected database pool error', err);
});

async function migrate() {
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
  console.log('✅ Database schema verified/applied');
}

async function query(text, params) {
  const start = Date.now();
  const res = await pool.query(text, params);
  const duration = Date.now() - start;
  if (duration > 500) console.warn(`Slow query (${duration}ms): ${text.slice(0, 80)}`);
  return res;
}

module.exports = { pool, query, migrate };
