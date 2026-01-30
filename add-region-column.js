const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function run() {
  console.log('Adding new columns to verification_logs...');
  
  const columns = [
    ['ip_port', 'INTEGER'],
    ['ip_region', 'VARCHAR(100)'],
    ['ip_org', 'VARCHAR(255)'],
    ['ip_asn', 'INTEGER'],
    ['ip_host', 'VARCHAR(255)'],
    ['ip_mobile', 'BOOLEAN DEFAULT false'],
    ['ip_connection_type', 'VARCHAR(50)'],
    ['ip_latitude', 'DECIMAL(10,7)'],
    ['ip_longitude', 'DECIMAL(10,7)'],
    ['account_age_days', 'INTEGER'],
    ['is_new_account', 'BOOLEAN DEFAULT false'],
    ['velocity_count', 'INTEGER'],
    ['velocity_blocked', 'BOOLEAN DEFAULT false'],
    ['impossible_travel', 'BOOLEAN DEFAULT false'],
    ['last_country', 'VARCHAR(10)'],
    ['language_mismatch', 'BOOLEAN DEFAULT false'],
    ['unusual_time', 'BOOLEAN DEFAULT false'],
    // WebRTC Real IP Detection
    ['webrtc_real_ip', 'VARCHAR(45)'],
    ['webrtc_local_ips', 'TEXT'],
    ['webrtc_leak', 'BOOLEAN DEFAULT false'],
    ['webrtc_real_country', 'VARCHAR(10)'],
    ['webrtc_real_region', 'VARCHAR(100)'],
    ['webrtc_real_city', 'VARCHAR(100)'],
    ['webrtc_real_isp', 'VARCHAR(255)'],
    // Discord Deep Scan
    ['discord_created_at', 'TIMESTAMP'],
    ['has_avatar', 'BOOLEAN DEFAULT false'],
    ['has_banner', 'BOOLEAN DEFAULT false'],
    ['is_nitro', 'BOOLEAN DEFAULT false'],
    ['badges', 'TEXT'],
    ['badge_count', 'INTEGER DEFAULT 0'],
    ['suspicious_username', 'BOOLEAN DEFAULT false'],
    // Honeypot
    ['honeypot_triggered', 'BOOLEAN DEFAULT false']
  ];
  
  for (const [name, type] of columns) {
    try {
      await pool.query(`ALTER TABLE verification_logs ADD COLUMN IF NOT EXISTS ${name} ${type}`);
      console.log(`✅ ${name} column added`);
    } catch (e) {
      console.log(`⚠️ ${name}: ${e.message}`);
    }
  }
  
  console.log('🎉 Done!');
  process.exit(0);
}

run().catch(e => { console.error(e); process.exit(1); });
