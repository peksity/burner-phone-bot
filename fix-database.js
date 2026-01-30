const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function fix() {
  try {
    // Drop old table if exists
    console.log('Dropping old verification_logs table...');
    await pool.query(`DROP TABLE IF EXISTS verification_logs;`);
    
    // Create new table with all columns
    console.log('Creating new verification_logs table...');
    await pool.query(`
      CREATE TABLE verification_logs (
        id SERIAL PRIMARY KEY,
        discord_id VARCHAR(32) NOT NULL,
        discord_tag VARCHAR(64),
        guild_id VARCHAR(32) NOT NULL,
        result VARCHAR(20) NOT NULL,
        fingerprint_hash VARCHAR(128),
        alt_of_discord_id VARCHAR(32),
        alt_of_discord_tag VARCHAR(64),
        ip_address VARCHAR(45),
        ip_risk_score INTEGER DEFAULT 0,
        ip_vpn BOOLEAN DEFAULT FALSE,
        ip_proxy BOOLEAN DEFAULT FALSE,
        ip_tor BOOLEAN DEFAULT FALSE,
        ip_bot_score INTEGER DEFAULT 0,
        ip_country VARCHAR(64),
        ip_city VARCHAR(64),
        ip_isp VARCHAR(128),
        ip_abuse_reports INTEGER DEFAULT 0,
        timezone_mismatch BOOLEAN DEFAULT FALSE,
        browser_timezone VARCHAR(64),
        ip_timezone VARCHAR(64),
        behavior_data JSONB,
        gpu_data JSONB,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('✅ Created verification_logs table');

    // Create indexes
    await pool.query(`CREATE INDEX idx_verification_logs_guild ON verification_logs(guild_id);`);
    await pool.query(`CREATE INDEX idx_verification_logs_result ON verification_logs(result);`);
    await pool.query(`CREATE INDEX idx_verification_logs_created ON verification_logs(created_at DESC);`);
    await pool.query(`CREATE INDEX idx_verification_logs_discord ON verification_logs(discord_id);`);
    console.log('✅ Created indexes');

    // Also add banned_by column to fingerprint_bans if missing
    console.log('Adding banned_by column to fingerprint_bans...');
    try {
      await pool.query(`ALTER TABLE fingerprint_bans ADD COLUMN IF NOT EXISTS banned_by VARCHAR(64);`);
      console.log('✅ Added banned_by column');
    } catch (e) {
      console.log('banned_by column already exists or error:', e.message);
    }

    console.log('\n🎉 Database fix complete!');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exit(1);
  }
}

fix();
