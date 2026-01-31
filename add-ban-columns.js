// Run this to add ban and IP tracking columns
// Usage: node add-ban-columns.js

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function migrate() {
  try {
    console.log('Adding ban and IP tracking columns...');
    
    // Add banned column
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE
    `);
    console.log('✅ banned column added');
    
    // Add ban reason
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT
    `);
    console.log('✅ ban_reason column added');
    
    // Add banned_at timestamp
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_at TIMESTAMP
    `);
    console.log('✅ banned_at column added');
    
    // Add last_ip for tracking
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip VARCHAR(50)
    `);
    console.log('✅ last_ip column added');
    
    // Add signup_ip for tracking original signup
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS signup_ip VARCHAR(50)
    `);
    console.log('✅ signup_ip column added');
    
    // Create banned_ips table for IP bans
    await pool.query(`
      CREATE TABLE IF NOT EXISTS banned_ips (
        id SERIAL PRIMARY KEY,
        ip_address VARCHAR(50) NOT NULL,
        reason TEXT,
        banned_by VARCHAR(30),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ banned_ips table created');
    
    // Create login_logs table to track all logins
    await pool.query(`
      CREATE TABLE IF NOT EXISTS login_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        email VARCHAR(255),
        discord_id VARCHAR(30),
        ip_address VARCHAR(50),
        user_agent TEXT,
        success BOOLEAN,
        fail_reason TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ login_logs table created');
    
    console.log('\n🎉 Migration complete! Ban system is now enabled.');
    
  } catch (err) {
    console.error('❌ Migration error:', err.message);
  } finally {
    await pool.end();
  }
}

migrate();
