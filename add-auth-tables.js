// Run this to add password reset tokens table
// Usage: node add-auth-tables.js

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function migrate() {
  try {
    console.log('Creating auth tables...\n');
    
    // Password reset tokens table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        token VARCHAR(64) NOT NULL UNIQUE,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ password_reset_tokens table created');
    
    // Email verification tokens table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_verification_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        email VARCHAR(255) NOT NULL,
        token VARCHAR(64) NOT NULL UNIQUE,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ email_verification_tokens table created');
    
    // Add email_verified column to users if not exists
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE
    `);
    console.log('✅ email_verified column added to users');
    
    // Add failed_login_attempts column
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0
    `);
    console.log('✅ failed_login_attempts column added');
    
    // Add locked_until column for account lockout
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP
    `);
    console.log('✅ locked_until column added');
    
    // Sessions table for tracking active sessions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        token VARCHAR(64) NOT NULL UNIQUE,
        device_info TEXT,
        ip_address VARCHAR(50),
        last_active TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ user_sessions table created');
    
    // Create indexes for performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_reset_tokens_token ON password_reset_tokens(token);
      CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON password_reset_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
    `);
    console.log('✅ Indexes created');
    
    console.log('\n🎉 Migration complete! All auth tables are ready.');
    
  } catch (err) {
    console.error('❌ Migration error:', err.message);
  } finally {
    await pool.end();
  }
}

migrate();
