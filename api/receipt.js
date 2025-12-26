// /api/receipt.js
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
  const query = `
    SELECT id, receipt_id, donor_name, email, amount, currency, country, created_at
    FROM donations
    WHERE receipt_id = '${receipt}'
  `;

  try {
    // Only attempt database query if NEON_HTTP_URL is configured
    if (!process.env.NEON_HTTP_URL) {
      return res.status(500).json({
        error: "Database not configured"
      });
    }

    const neonRes = await fetch(process.env.NEON_HTTP_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.NEON_API_KEY}`
      },
      body: JSON.stringify({
        query
      })
    });

    const result = await neonRes.json();

    // Forward DB errors directly (error-based SQLi)
    if (result.error) {
      return res.status(500).json({
        error: result.error.message || result.error
      });
    }

    return res.status(200).json({
      success: true,
      data: result.rows || []
    });

  } catch (e) {
    return res.status(500).json({
      error: e.message
    });
  }
};
