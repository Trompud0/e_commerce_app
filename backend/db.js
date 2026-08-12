require('dotenv').config();
const { Pool } = require('pg');

// Check if a single unified DATABASE_URL string exists (Production/Render)
// Otherwise, fall back to individual variables (Local Development)
const isProduction = process.env.NODE_ENV === 'production' || process.env.DATABASE_URL;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Render will use this
  
  // If DATABASE_URL isn't there, pg uses these fallback fields automatically
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  
  // Render PostgreSQL requires SSL encryption to allow incoming connections
  ssl: isProduction ? { rejectUnauthorized: false } : false
});

module.exports = pool;

