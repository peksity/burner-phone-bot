/**
 * Patch: Fix missing columns in fingerprints and security_alerts
 */

require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function patch() {
  console.log('Patching database...\n');
  
  const patches = [
    {
      name: 'Add user_id to fingerprints',
      sql: `ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE CASCADE`
    },
    {
      name: 'Add user_id to security_alerts', 
      sql: `ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL`
    },
    {
      name: 'Add unique constraint to fingerprints',
      sql: `CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprints_user_fp ON fingerprints(user_id, fingerprint)`
    },
    {
      name: 'Add index on security_alerts user_id',
      sql: `CREATE INDEX IF NOT EXISTS idx_security_alerts_user ON security_alerts(user_id)`
    }
  ];
  
  for (const patch of patches) {
    try {
      await pool.query(patch.sql);
      console.log(`[OK] ${patch.name}`);
    } catch (e) {
      console.log(`[FAIL] ${patch.name}: ${e.message}`);
    }
  }
  
  console.log('\nPatch complete!');
  await pool.end();
}

patch().catch(console.error);
