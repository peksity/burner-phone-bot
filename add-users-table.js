// Run this script to add the users table
// Usage: node add-users-table.js

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function migrate() {
  const client = await pool.connect();
  
  try {
    console.log('Creating users table...');
    
    // Create users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        discord_id VARCHAR(30) UNIQUE NOT NULL,
        username VARCHAR(100),
        discriminator VARCHAR(10),
        avatar VARCHAR(255),
        email VARCHAR(255),
        role VARCHAR(20) DEFAULT 'customer',
        plan VARCHAR(20) DEFAULT 'free',
        plan_expires_at TIMESTAMP,
        guilds_allowed INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP
      )
    `);
    console.log('✅ users table created');
    
    // Create staff_invites table for invite links
    await client.query(`
      CREATE TABLE IF NOT EXISTS staff_invites (
        id SERIAL PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        created_by VARCHAR(30),
        used_by VARCHAR(30),
        used_at TIMESTAMP,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ staff_invites table created');
    
    // Migrate existing staff_users to users table
    const existingStaff = await client.query(`SELECT * FROM staff_users`);
    console.log(`Found ${existingStaff.rows.length} existing staff users to migrate...`);
    
    for (const staff of existingStaff.rows) {
      await client.query(`
        INSERT INTO users (discord_id, username, avatar, role, created_at, last_login)
        VALUES ($1, $2, $3, 'staff', $4, $5)
        ON CONFLICT (discord_id) DO UPDATE SET role = 'staff'
      `, [staff.discord_id, staff.username, staff.avatar, staff.created_at, staff.last_login]);
      console.log(`  ✅ Migrated staff: ${staff.username}`);
    }
    
    // Set the first admin (YOU) - update this with your Discord ID
    const ADMIN_DISCORD_ID = process.env.ADMIN_DISCORD_ID || '1aboraliern26';
    await client.query(`
      UPDATE users SET role = 'admin' WHERE discord_id = $1
    `, [ADMIN_DISCORD_ID]);
    console.log(`✅ Admin role set for Discord ID: ${ADMIN_DISCORD_ID}`);
    
    console.log('\n🎉 Migration complete!');
    
  } catch (err) {
    console.error('Migration error:', err);
  } finally {
    client.release();
    pool.end();
  }
}

migrate();
