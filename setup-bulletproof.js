// 
// BULLETPROOF SECURITY DATABASE SETUP
// Run: node setup-bulletproof.js
// 

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function setup() {
  console.log('');
  console.log(' ');
  console.log('   BULLETPROOF SECURITY SETUP');
  console.log(' ');
  console.log('');

  try {
    // 1. ADD SECURITY COLUMNS TO USERS TABLE
    console.log('[1/6] Adding security columns to users...');
    
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS fingerprint_data JSONB`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'none'`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS total_paid INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS chargeback_count INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS flagged BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS flag_reason TEXT`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER DEFAULT 0`);
    console.log('    Security columns added');

    // 2. LOGIN FINGERPRINTS TABLE
    console.log('[2/6] Creating login_fingerprints table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS login_fingerprints (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        discord_id VARCHAR(255) NOT NULL,
        fingerprint VARCHAR(64),
        fingerprint_data JSONB,
        ip_address VARCHAR(50),
        user_agent TEXT,
        is_suspicious BOOLEAN DEFAULT FALSE,
        suspicion_reason TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_lfp_discord ON login_fingerprints(discord_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_lfp_fp ON login_fingerprints(fingerprint)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_lfp_ip ON login_fingerprints(ip_address)`);
    console.log('    login_fingerprints ready');

    // 3. PAYMENTS TABLE
    console.log('[3/6] Creating payments table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        discord_id VARCHAR(255) NOT NULL,
        stripe_payment_id VARCHAR(255),
        stripe_subscription_id VARCHAR(255),
        stripe_customer_id VARCHAR(255),
        amount INTEGER NOT NULL,
        currency VARCHAR(10) DEFAULT 'usd',
        plan VARCHAR(50),
        status VARCHAR(50) DEFAULT 'pending',
        fingerprint VARCHAR(64),
        ip_address VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_pay_discord ON payments(discord_id)`);
    console.log('    payments ready');

    // 4. CHARGEBACKS TABLE
    console.log('[4/6] Creating chargebacks table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chargebacks (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        discord_id VARCHAR(255),
        payment_id INTEGER,
        stripe_dispute_id VARCHAR(255),
        amount INTEGER,
        reason TEXT,
        status VARCHAR(50) DEFAULT 'open',
        auto_banned BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('    chargebacks ready');

    // 5. RATE LIMITS TABLE
    console.log('[5/6] Creating rate_limits table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        id SERIAL PRIMARY KEY,
        identifier VARCHAR(255) NOT NULL,
        identifier_type VARCHAR(50) DEFAULT 'ip',
        endpoint VARCHAR(255),
        count INTEGER DEFAULT 1,
        window_start TIMESTAMP DEFAULT NOW(),
        blocked_until TIMESTAMP
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_rate_id ON rate_limits(identifier, endpoint)`);
    console.log('    rate_limits ready');

    // 6. LINKED ACCOUNTS TABLE
    console.log('[6/6] Creating linked_accounts table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS linked_accounts (
        id SERIAL PRIMARY KEY,
        fingerprint VARCHAR(64) NOT NULL,
        discord_ids TEXT[] NOT NULL,
        ip_addresses TEXT[],
        account_count INTEGER DEFAULT 1,
        is_suspicious BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_linked_fp ON linked_accounts(fingerprint)`);
    console.log('    linked_accounts ready');

    // 7. URL SCANS TABLE
    console.log('[7/8] Creating url_scans table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS url_scans (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        scanned_by VARCHAR(255),
        scan_type VARCHAR(50) DEFAULT 'basic',
        is_safe BOOLEAN DEFAULT TRUE,
        risk_score INTEGER DEFAULT 0,
        threats JSONB,
        api_results JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_scans_url ON url_scans(url)`);
    console.log('    url_scans ready');

    // 8. REPORTED LINKS TABLE
    console.log('[8/8] Creating reported_links table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reported_links (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        reported_by VARCHAR(255),
        reason TEXT,
        verified BOOLEAN DEFAULT FALSE,
        verified_by VARCHAR(255),
        is_malicious BOOLEAN,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('    reported_links ready');

    // 9. REFERRAL SYSTEM COLUMNS
    console.log('[9/10] Adding referral columns...');
    
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(20) UNIQUE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by VARCHAR(255)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_count INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_earnings INTEGER DEFAULT 0`);
    console.log('    Referral columns added');

    // 10. PAYOUT REQUESTS TABLE
    console.log('[10/10] Creating payout_requests table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS payout_requests (
        id SERIAL PRIMARY KEY,
        discord_id VARCHAR(255) NOT NULL,
        amount INTEGER NOT NULL,
        paypal_email VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending',
        processed_by VARCHAR(255),
        processed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('    payout_requests ready');

    // 11. VERIFICATIONS TABLE (for stats)
    console.log('[11/11] Creating verifications table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS verifications (
        id SERIAL PRIMARY KEY,
        discord_id VARCHAR(255) NOT NULL,
        guild_id VARCHAR(255),
        ip_address VARCHAR(50),
        fingerprint VARCHAR(64),
        vpn_detected BOOLEAN DEFAULT FALSE,
        proxy_detected BOOLEAN DEFAULT FALSE,
        risk_score INTEGER DEFAULT 0,
        passed BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_verify_discord ON verifications(discord_id)`);
    console.log('    verifications ready');

    // 12. SECURITY ALERTS TABLE
    console.log('[12/12] Creating security_alerts table...');
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS security_alerts (
        id SERIAL PRIMARY KEY,
        alert_type VARCHAR(100) NOT NULL,
        severity VARCHAR(20) DEFAULT 'medium',
        discord_id VARCHAR(255),
        ip_address VARCHAR(50),
        fingerprint_hash VARCHAR(64),
        description TEXT,
        resolved BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('    security_alerts ready');

    console.log('');
    console.log(' BULLETPROOF SECURITY SETUP COMPLETE! ');
    console.log('');
    console.log('    [1] Discord-only auth');
    console.log('    [2] Server-side plan check');
    console.log('    [3] Device fingerprinting');
    console.log('    [4] IP + FP logging');
    console.log('    [5] Stripe payments');
    console.log('    [6] Auto-ban chargebacks');
    console.log('    [7] Rate limiting');
    console.log('    [8] URL/Payloader scanning');
    console.log('    [9] Referral system');
    console.log('    [10] Security alerts');
    console.log('');

  } catch (e) {
    console.error(' Error:', e.message);
  } finally {
    await pool.end();
  }
}

setup();
