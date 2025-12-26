// /api/receipt.js
const { Pool } = require('pg');

// Create pool outside handler for connection reuse
const pool = new Pool({
  connectionString: process.env.NEON_DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  const { receipt } = req.body || {};

  if (!receipt) {
    return res.status(400).json({ error: "Receipt ID required" });
  }

  // ---- INTENTIONALLY INSECURE QUERY ----
  // Raw string concatenation (by design)
  const queryText = `SELECT id, receipt_id, donor_name, email, amount, currency, country, created_at FROM donations WHERE receipt_id = '${receipt}'`;

  let client;
  
  try {
    if (!process.env.NEON_DATABASE_URL) {
      return res.status(500).json({ error: "Database not configured" });
    }

    client = await pool.connect();
    
    // Execute raw query without parameters
    const result = await client.query(queryText);

    return res.status(200).json({
      success: true,
      data: result.rows
    });

  } catch (e) {
    // Forward error for SQLi lab
    return res.status(500).json({
      error: e.message
    });
  } finally {
    if (client) {
      client.release();
    }
  }
};
