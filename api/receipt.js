// /api/receipt.js
const { neon } = require('@neondatabase/serverless');

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  const { receipt } = req.body || {};

  if (!receipt) {
    return res.status(400).json({ error: "Receipt ID required" });
  }

  // ---- INTENTIONALLY INSECURE QUERY ----
  const queryText = `
    SELECT id, receipt_id, donor_name, email, amount, currency, country, created_at
    FROM donations
    WHERE receipt_id = '${receipt}'
  `;

  try {
    if (!process.env.NEON_DATABASE_URL) {
      return res.status(500).json({ error: "Database not configured" });
    }

    const sql = neon(process.env.NEON_DATABASE_URL);
    const rows = await sql(queryText);

    return res.status(200).json({
      success: true,
      data: rows
    });

  } catch (e) {
    // Forward error for SQLi lab
    return res.status(500).json({
      error: e.message
    });
  }
};
