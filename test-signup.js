const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function testSignup() {
  const email = 'test123@test.com';
  const passwordHash = 'testhash123';
  const clientIp = '127.0.0.1';
  
  try {
    console.log('Testing signup insert...\n');
    
    // Try the exact same query the signup uses
    const result = await pool.query(`
      INSERT INTO users (email, password_hash, role, plan, signup_ip, last_ip, created_at, last_login)
      VALUES ($1, $2, 'customer', 'free', $3, $3, NOW(), NOW())
      RETURNING *
    `, [email, passwordHash, clientIp]);
    
    console.log('✅ SUCCESS! User created:', result.rows[0]);
    
    // Clean up test user
    await pool.query('DELETE FROM users WHERE email = $1', [email]);
    console.log('✅ Test user cleaned up');
    
  } catch (e) {
    console.log('❌ ERROR:', e.message);
    console.log('\nFull error:', e);
  } finally {
    pool.end();
  }
}

testSignup();
