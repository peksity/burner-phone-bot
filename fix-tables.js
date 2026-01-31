const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function check() {
  try {
    // Check login_logs
    const logs = await pool.query("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'login_logs')");
    console.log('login_logs exists:', logs.rows[0].exists);
    
    // Check banned_ips
    const banned = await pool.query("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'banned_ips')");
    console.log('banned_ips exists:', banned.rows[0].exists);
    
    // If missing, create them
    if (!logs.rows[0].exists) {
      await pool.query(`
        CREATE TABLE login_logs (
          id SERIAL PRIMARY KEY,
          user_id INTEGER,
          email VARCHAR(255),
          ip_address VARCHAR(50),
          success BOOLEAN DEFAULT true,
          created_at TIMESTAMP DEFAULT NOW()
        )
      `);
      console.log('✅ Created login_logs table');
    }
    
    if (!banned.rows[0].exists) {
      await pool.query(`
        CREATE TABLE banned_ips (
          id SERIAL PRIMARY KEY,
          ip_address VARCHAR(50) NOT NULL UNIQUE,
          reason TEXT,
          banned_by VARCHAR(255),
          created_at TIMESTAMP DEFAULT NOW()
        )
      `);
      console.log('✅ Created banned_ips table');
    }
    
    console.log('\n✅ All tables ready! Try signup again.');
    
  } catch (e) {
    console.log('Error:', e.message);
  } finally {
    pool.end();
  }
}

check();
