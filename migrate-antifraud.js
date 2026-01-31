/**
 * Database Migration: Anti-Fraud Security Features
 * Run this once to add new columns for security tracking
 */

require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function migrate() {
  console.log('Starting anti-fraud database migration...\n');
  
  const migrations = [
    // Add Discord account age tracking
    {
      name: 'Add discord_account_age_days to users',
      sql: `ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_account_age_days INTEGER DEFAULT NULL`
    },
    
    // Add login method tracking
    {
      name: 'Add login_method to login_logs',
      sql: `ALTER TABLE login_logs ADD COLUMN IF NOT EXISTS login_method VARCHAR(50) DEFAULT 'unknown'`
    },
    
    // Create security_alerts table if not exists
    {
      name: 'Create security_alerts table',
      sql: `CREATE TABLE IF NOT EXISTS security_alerts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        alert_type VARCHAR(50) NOT NULL,
        severity VARCHAR(20) DEFAULT 'medium',
        details JSONB,
        ip_address VARCHAR(50),
        resolved BOOLEAN DEFAULT FALSE,
        resolved_by VARCHAR(100),
        resolved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )`
    },
    
    // Create banned_fingerprints table if not exists
    {
      name: 'Create banned_fingerprints table',
      sql: `CREATE TABLE IF NOT EXISTS banned_fingerprints (
        id SERIAL PRIMARY KEY,
        fingerprint VARCHAR(100) UNIQUE NOT NULL,
        reason TEXT,
        banned_by VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
      )`
    },
    
    // Add fingerprint unique constraint to fingerprints table
    {
      name: 'Add unique constraint to fingerprints',
      sql: `CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprints_user_fp ON fingerprints(user_id, fingerprint)`
    },
    
    // Add last_seen to fingerprints
    {
      name: 'Add last_seen to fingerprints',
      sql: `ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT NOW()`
    },
    
    // Create device_whitelist table for approved devices
    {
      name: 'Create device_whitelist table',
      sql: `CREATE TABLE IF NOT EXISTS device_whitelist (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        fingerprint VARCHAR(100) NOT NULL,
        device_name VARCHAR(100),
        approved BOOLEAN DEFAULT FALSE,
        approved_at TIMESTAMP,
        last_used TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, fingerprint)
      )`
    },
    
    // Add indexes for faster queries
    {
      name: 'Add index on security_alerts',
      sql: `CREATE INDEX IF NOT EXISTS idx_security_alerts_user ON security_alerts(user_id)`
    },
    {
      name: 'Add index on security_alerts type',
      sql: `CREATE INDEX IF NOT EXISTS idx_security_alerts_type ON security_alerts(alert_type)`
    },
    {
      name: 'Add index on login_logs created_at',
      sql: `CREATE INDEX IF NOT EXISTS idx_login_logs_created ON login_logs(created_at DESC)`
    }
  ];
  
  let success = 0;
  let failed = 0;
  
  for (const migration of migrations) {
    try {
      await pool.query(migration.sql);
      console.log(`[OK] ${migration.name}`);
      success++;
    } catch (e) {
      if (e.message.includes('already exists') || e.message.includes('duplicate')) {
        console.log(`[SKIP] ${migration.name} (already exists)`);
        success++;
      } else {
        console.log(`[FAIL] ${migration.name}: ${e.message}`);
        failed++;
      }
    }
  }
  
  console.log(`\n========================================`);
  console.log(`Migration complete: ${success} succeeded, ${failed} failed`);
  console.log(`========================================\n`);
  
  await pool.end();
}

migrate().catch(console.error);
