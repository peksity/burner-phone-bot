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
    ['ip_longitude', 'DECIMAL(10,7)']
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
