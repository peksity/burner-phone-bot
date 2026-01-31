const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function fix() {
  try {
    console.log('Fixing discord_id column to allow NULL...\n');
    
    await pool.query(`
      ALTER TABLE users ALTER COLUMN discord_id DROP NOT NULL
    `);
    
    console.log('✅ Fixed! discord_id can now be NULL for email signups.');
    console.log('\nYour mod can try signing up again!');
    
  } catch (e) {
    console.log('Error:', e.message);
  } finally {
    pool.end();
  }
}

fix();
