const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function setup() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS device_fingerprints (
        id SERIAL PRIMARY KEY,
        discord_id VARCHAR(255) NOT NULL,
        discord_tag VARCHAR(255),
        fingerprint_hash VARCHAR(255) NOT NULL,
        fingerprint_data JSONB,
        guild_id VARCHAR(255),
        verified_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(discord_id, guild_id)
      );
    `);
    console.log('Created device_fingerprints table');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS fingerprint_bans (
        id SERIAL PRIMARY KEY,
        fingerprint_hash VARCHAR(255) NOT NULL,
        banned_discord_id VARCHAR(255),
        banned_discord_tag VARCHAR(255),
        banned_by VARCHAR(255),
        reason TEXT,
        guild_id VARCHAR(255),
        banned_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('Created fingerprint_bans table');

    console.log('Database setup complete!');
    process.exit(0);
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
}

setup();
