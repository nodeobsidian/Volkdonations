const ejs = require("ejs");
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
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Official Donation Receipt - Volk Donations</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, #f7f9fb 0%, #e8eef3 100%);
      padding: 40px 20px;
      line-height: 1.6;
    }

    .receipt-container {
      max-width: 850px;
      background: #ffffff;
      margin: 0 auto;
      box-shadow: 0 10px 40px rgba(0,0,0,0.12);
      border-radius: 12px;
      overflow: hidden;
    }

    .receipt-header {
      background: linear-gradient(135deg, #1e3a5f 0%, #00a86b 100%);
      color: #ffffff;
      padding: 40px 50px;
      position: relative;
      overflow: hidden;
    }

    .receipt-header::before {
      content: '';
      position: absolute;
      top: 0;
      right: 0;
      width: 300px;
      height: 300px;
      background: rgba(255,255,255,0.05);
      border-radius: 50%;
      transform: translate(30%, -30%);
    }

    .header-content {
      position: relative;
      z-index: 1;
    }

    .logo-section {
      display: flex;
      align-items: center;
      gap: 15px;
      margin-bottom: 20px;
    }

    .logo-section img {
      height: 60px;
      width: auto;
      filter: brightness(0) invert(1);
    }

    .logo-text h1 {
      font-size: 28px;
      font-weight: 700;
      margin: 0;
    }

    .logo-text p {
      font-size: 13px;
      opacity: 0.9;
      margin: 3px 0 0 0;
      letter-spacing: 0.5px;
    }

    .receipt-title {
      font-size: 22px;
      font-weight: 600;
      margin: 25px 0 10px 0;
      letter-spacing: 0.5px;
    }

    .receipt-id {
      font-size: 15px;
      opacity: 0.95;
      font-weight: 500;
      background: rgba(255,255,255,0.15);
      display: inline-block;
      padding: 8px 16px;
      border-radius: 6px;
      margin-top: 10px;
    }

    .receipt-body {
      padding: 50px;
    }

    .thank-you-message {
      background: #f0fdf7;
      border-left: 4px solid #00a86b;
      padding: 25px;
      margin-bottom: 35px;
      border-radius: 6px;
    }

    .thank-you-message h2 {
      color: #1e3a5f;
      font-size: 20px;
      margin-bottom: 10px;
      font-weight: 600;
    }

    .thank-you-message p {
      color: #5a6c7d;
      font-size: 15px;
      margin: 0;
    }

    .details-section {
      margin: 35px 0;
    }

    .section-title {
      font-size: 18px;
      color: #1e3a5f;
      font-weight: 600;
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 2px solid #e8eef3;
    }

    .details-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 20px;
      margin-top: 20px;
    }

    .detail-item {
      padding: 15px;
      background: #f9fafb;
      border-radius: 8px;
      border: 1px solid #e8eef3;
    }

    .detail-label {
      font-size: 12px;
      color: #7a8a9e;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }

    .detail-value {
      font-size: 16px;
      color: #2c3e50;
      font-weight: 500;
    }

    .amount-section {
      background: linear-gradient(135deg, #1e3a5f 0%, #2a5080 100%);
      color: #ffffff;
      padding: 30px;
      border-radius: 10px;
      margin: 30px 0;
      text-align: center;
    }

    .amount-label {
      font-size: 14px;
      opacity: 0.9;
      margin-bottom: 8px;
      letter-spacing: 1px;
      text-transform: uppercase;
    }

    .amount-value {
      font-size: 42px;
      font-weight: 700;
      letter-spacing: -1px;
    }

    .tax-info-box {
      background: #fffbf0;
      border: 2px solid #ffeaa7;
      border-radius: 8px;
      padding: 25px;
      margin: 30px 0;
    }

    .tax-info-box h3 {
      color: #1e3a5f;
      font-size: 16px;
      margin-bottom: 12px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .tax-info-box p {
      color: #5a6c7d;
      font-size: 14px;
      margin: 0;
      line-height: 1.7;
    }

    .receipt-footer {
      background: #f9fafb;
      padding: 35px 50px;
      border-top: 1px solid #e8eef3;
    }

    .footer-content {
      text-align: center;
    }

    .organization-info {
      font-size: 13px;
      color: #5a6c7d;
      line-height: 1.8;
      margin-bottom: 20px;
    }

    .organization-info strong {
      color: #1e3a5f;
    }

    .contact-info {
      display: flex;
      justify-content: center;
      gap: 30px;
      flex-wrap: wrap;
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid #e8eef3;
    }

    .contact-item {
      font-size: 13px;
      color: #5a6c7d;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .print-button {
      background: #00a86b;
      color: #ffffff;
      border: none;
      padding: 14px 32px;
      font-size: 15px;
      font-weight: 600;
      border-radius: 8px;
      cursor: pointer;
      margin: 25px auto 0;
      display: block;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(0,168,107,0.3);
    }

    .print-button:hover {
      background: #008557;
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(0,168,107,0.4);
    }

    @media print {
      body {
        background: #ffffff;
        padding: 0;
      }

      .receipt-container {
        box-shadow: none;
        border-radius: 0;
      }

      .print-button {
        display: none;
      }
    }

    @media (max-width: 768px) {
      .receipt-header,
      .receipt-body,
      .receipt-footer {
        padding: 30px 25px;
      }

      .details-grid {
        grid-template-columns: 1fr;
      }

      .amount-value {
        font-size: 36px;
      }

      .contact-info {
        flex-direction: column;
        gap: 15px;
      }
    }
  </style>
</head>
<body>
  <div class="receipt-container">
    <div class="receipt-header">
      <div class="header-content">
        <div class="logo-section">
          <img src="/images/logo.png" alt="Volk Donations Logo">
          <div class="logo-text">
            <h1>Volk Donations</h1>
            <p>A better life for everyone</p>
          </div>
        </div>
        <div class="receipt-title">Official Donation Receipt</div>
        <div class="receipt-id">Receipt ID: <%= formId %></div>
      </div>
    </div>

    <div class="receipt-body">
      <div class="thank-you-message">
        <h2>Thank You for Your Generosity!</h2>
        <p>
          Your donation makes a profound difference in the lives of children around the world. 
          We are deeply grateful for your support and commitment to our mission.
        </p>
      </div>

      <div class="amount-section">
        <div class="amount-label">Total Donation Amount</div>
        <div class="amount-value">$<%= amount %> USD</div>
      </div>

      <div class="details-section">
        <div class="section-title">Donor Information</div>
        <div class="details-grid">
          <div class="detail-item">
            <div class="detail-label">Donor Name</div>
            <div class="detail-value">${name}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Email Address</div>
            <div class="detail-value"><%= email %></div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Phone Number</div>
            <div class="detail-value"><%= phone %></div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Country</div>
            <div class="detail-value"><%= country %></div>
          </div>
        </div>
      </div>

      <div class="details-section">
        <div class="section-title">Transaction Details</div>
        <div class="details-grid">
          <div class="detail-item">
            <div class="detail-label">Receipt Number</div>
            <div class="detail-value"><%= formId %></div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Date Issued</div>
            <div class="detail-value"><%= date %></div>
          </div>
        </div>
      </div>

      <div class="tax-info-box">
        <h3>
          <svg width="20" height="20" fill="none" stroke="#00a86b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          Tax Deductible Contribution
        </h3>
        <p>
          Volk Donations is a registered 501(c)(3) nonprofit organization. 
          This donation is tax-deductible to the fullest extent allowed by law. 
          <strong>EIN: 45-1234567</strong>. Please retain this receipt for your tax records.
        </p>
      </div>

      <button class="print-button" onclick="window.print()">
        Print Receipt
      </button>
    </div>

    <div class="receipt-footer">
      <div class="footer-content">
        <div class="organization-info">
          <strong>Volk Donations</strong><br>
          A registered 501(c)(3) nonprofit organization based in the United States<br>
          Committed to supporting orphaned children worldwide since 2010<br>
          This document serves as an official donation receipt for tax and record-keeping purposes.
        </div>
        <div class="contact-info">
          <div class="contact-item">
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
              <path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
            </svg>
            support@volkdonations.org
          </div>
          <div class="contact-item">
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
              <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>
            </svg>
            www.volkdonations.org
          </div>
          <div class="contact-item">
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
              <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6 19.79 19.79 0 01-3.07-8.67A2 2 0 014.11 2h3a2 2 0 012 1.72 12.84 12.84 0 00.7 2.81 2 2 0 01-.45 2.11L8.09 9.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45 12.84 12.84 0 002.81.7A2 2 0 0122 16.92z"/>
            </svg>
            +1 (555) 123-4567
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>
`;

  try {
    const html = ejs.render(template, {
      formId,
      email,
      phone,
      country,
      amount: donationAmount,
      date
    });
    
    res.setHeader("Content-Type", "text/html");
    return res.status(200).send(html);
  } catch (e) {
    return res.status(500).send(e.message);
  }
};
