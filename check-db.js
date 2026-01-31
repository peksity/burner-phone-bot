const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.query("SELECT column_name FROM information_schema.columns WHERE table_name='users'")
  .then(r => {
    console.log('Users table columns:');
    console.log(r.rows.map(x => x.column_name));
    pool.end();
  })
  .catch(e => {
    console.log('Error:', e.message);
    pool.end();
  });
