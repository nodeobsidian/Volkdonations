const nunjucks = require("nunjucks");
const { neon } = require("@neondatabase/serverless");

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }
  
  const { name, email, phone, country, amount } = req.body || {};
  
  if (!name || !email || !phone || !country || !amount) {
    return res.status(400).json({ error: "All fields are required" });
  }
  if (isNaN(amount)) {
    return res.status(400).json({ error: "Invalid donation amount" });
  }
  if (!process.env.NEON_DATABASE_URL) {
    return res.status(500).json({ error: "Database not configured" });
  }
  
  const donationAmount = Number(amount).toFixed(2);
  const date = new Date().toLocaleDateString("en-US");
  
  const formId =
    "VD-FORM-" +
    Math.random().toString(36).substring(2, 6).toUpperCase() +
    "-" +
    Date.now().toString().slice(-5);
  
  try {
    const sql = neon(process.env.NEON_DATABASE_URL);
    await sql`
      insert into forms (form_id, name, email, phone, country, amount)
      values (${formId}, ${name}, ${email}, ${phone}, ${country}, ${donationAmount})
    `;
  } catch (e) {
    return res.status(500).json({ error: "Failed to save donation form" });
  }
  
  const template = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Donation Receipt</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f5f5f5;
      padding: 30px;
    }
    .receipt {
      max-width: 720px;
      background: #ffffff;
      margin: auto;
      padding: 35px;
      border: 1px solid #ddd;
    }
    h1 {
      color: #1a4d2e;
      margin-bottom: 5px;
    }
    .form-id {
      font-size: 14px;
      font-weight: bold;
      color: #444;
      margin-bottom: 20px;
    }
    .section {
      margin-bottom: 14px;
    }
    .label {
      font-weight: bold;
    }
    .footer {
      margin-top: 35px;
      font-size: 12px;
      color: #555;
    }
  </style>
</head>
<body>
  <div class="receipt">
    <h1>Volk Donations</h1>
    <div class="form-id">Donation Form ID: ${formId}</div>
    <div class="section">
      <span class="label">Donor Name:</span> ${name}
    </div>
    <div class="section">
      <span class="label">Email:</span> ${email}
    </div>
    <div class="section">
      <span class="label">Phone:</span> ${phone}
    </div>
    <div class="section">
      <span class="label">Country:</span> ${country}
    </div>
    <div class="section">
      <span class="label">Donation Amount:</span> USD ${donationAmount}
    </div>
    <div class="section">
      <span class="label">Date:</span> ${date}
    </div>
    <div class="footer">
      Volk Donations is a registered nonprofit organization based in the United States.
      This document serves as an official donation receipt for record purposes.
    </div>
  </div>
</body>
</html>
`;

  try {
    res.setHeader("Content-Type", "text/html");
    return res.status(200).send(template);
  } catch (e) {
    return res.status(500).send(e.message);
  }
};
