const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function setup() {
  try {
    // Verification logs - tracks ALL attempts (success, blocked, duplicate)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS verification_logs (
        id SERIAL PRIMARY KEY,
        discord_id VARCHAR(32) NOT NULL,
        discord_tag VARCHAR(64),
        guild_id VARCHAR(32) NOT NULL,
        result VARCHAR(20) NOT NULL,
        fingerprint_hash VARCHAR(128),
        alt_of_discord_id VARCHAR(32),
        alt_of_discord_tag VARCHAR(64),
        ip_address VARCHAR(45),
        ip_risk_score INTEGER,
        ip_vpn BOOLEAN DEFAULT FALSE,
        ip_proxy BOOLEAN DEFAULT FALSE,
        ip_tor BOOLEAN DEFAULT FALSE,
        ip_bot_score INTEGER,
        ip_country VARCHAR(64),
        ip_city VARCHAR(64),
        ip_isp VARCHAR(128),
        ip_abuse_reports INTEGER,
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

    // Index for faster queries
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_verification_logs_guild ON verification_logs(guild_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_verification_logs_result ON verification_logs(result);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_verification_logs_created ON verification_logs(created_at DESC);`);
    console.log('✅ Created indexes');

    console.log('\n🎉 Database setup complete!');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exit(1);
  }
}

setup();
