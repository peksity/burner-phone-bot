const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function check() {
  try {
    const result = await pool.query("SELECT column_name, table_name FROM information_schema.columns WHERE table_name IN ('fingerprint_bans', 'device_fingerprints')");
    console.log('Columns found:');
    result.rows.forEach(r => console.log(r.table_name + '.' + r.column_name));
    if (result.rows.length === 0) {
      console.log('NO TABLES FOUND - tables do not exist!');
    }
    process.exit(0);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

check();
