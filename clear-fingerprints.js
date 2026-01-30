const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function run() {
  // Delete unrealdirector's fingerprint
  const r1 = await pool.query(`DELETE FROM device_fingerprints WHERE discord_tag LIKE '%unrealdirector%'`);
  console.log('Deleted unrealdirector fingerprints:', r1.rowCount);
  
  // Also delete jmudford so you can test fresh
  const r2 = await pool.query(`DELETE FROM device_fingerprints WHERE discord_tag LIKE '%jmudford%'`);
  console.log('Deleted jmudford fingerprints:', r2.rowCount);
  
  // Show what's left
  const remaining = await pool.query(`SELECT discord_tag, fingerprint_hash FROM device_fingerprints`);
  console.log('\nRemaining fingerprints:', remaining.rows);
  
  process.exit(0);
}

run().catch(e => { console.error(e); process.exit(1); });
