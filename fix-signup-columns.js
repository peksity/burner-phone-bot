// Run this to fix signup - adds missing columns
// Usage: node fix-signup-columns.js

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function migrate() {
  try {
    console.log('Adding missing columns for signup...\n');
    
    // Add signup_ip column
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS signup_ip VARCHAR(50)
    `);
    console.log('✅ signup_ip column added');
    
    // Add last_ip column
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip VARCHAR(50)
    `);
    console.log('✅ last_ip column added');
    
    // Add password_hash column (in case it's missing)
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255)
    `);
    console.log('✅ password_hash column added');
    
    // Create login_logs table if not exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS login_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        email VARCHAR(255),
        ip_address VARCHAR(50),
        success BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ login_logs table ready');
    
    // Create banned_ips table if not exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS banned_ips (
        id SERIAL PRIMARY KEY,
        ip_address VARCHAR(50) NOT NULL UNIQUE,
        reason TEXT,
        banned_by VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ banned_ips table ready');
    
    console.log('\n🎉 Done! Signup should work now.');
    
  } catch (err) {
    console.error('❌ Error:', err.message);
  } finally {
    await pool.end();
  }
}

migrate();
