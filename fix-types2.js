const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function fix() {
  try {
    // Drop the foreign key constraint first
    await pool.query('ALTER TABLE fingerprint_bans DROP CONSTRAINT IF EXISTS fingerprint_bans_fingerprint_id_fkey');
    console.log('Dropped foreign key constraint');
    
    // Fix column types
    await pool.query('ALTER TABLE fingerprint_bans ALTER COLUMN fingerprint_hash TYPE VARCHAR(128) USING fingerprint_hash::VARCHAR');
    console.log('Fixed fingerprint_bans.fingerprint_hash to VARCHAR');
    
    console.log('Done!');
    process.exit(0);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}

fix();