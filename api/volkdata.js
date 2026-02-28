const { neon } = require("@neondatabase/serverless");

module.exports = async (req, res) => {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  // ---- PARSE COOKIES ----
  const cookieHeader = req.headers.cookie || "";
  const cookies = {};
  cookieHeader.split(";").forEach(c => {
    const [key, ...rest] = c.trim().split("=");
    if (key) cookies[key] = rest.join("=");
  });

  const sessionToken = cookies.admin_session;

  if (!sessionToken) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const sql = neon(process.env.NEON_DATABASE_URL);

  try {
    // ---- VERIFY SESSION AGAINST NEON ----
    const rows = await sql`
      select admin_id, role, expires_at
      from admin_sessions
      where token = ${sessionToken}
        and expires_at > now()
      limit 1;
    `;

    const session = rows[0];

    if (!session) {
      return res.status(401).json({ error: "Invalid or expired session" });
    }

    // ---- ALL SUPABASE FETCHES IN PARALLEL ----
    const [adminRes, adminsCountRes, contactRes, usersRes] = await Promise.all([

      // Verify the acting admin
      fetch(
        `${process.env.SUPABASE_URL}/rest/v1/admins?id=eq.${session.admin_id}&select=id,email,role`,
        {
          headers: {
            apikey: process.env.SUPABASE_SERVICE_KEY,
            Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
          },
        }
      ),

      // Count all admins
      fetch(
        `${process.env.SUPABASE_URL}/rest/v1/admins?select=id`,
        {
          headers: {
            apikey: process.env.SUPABASE_SERVICE_KEY,
            Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
            Prefer: "count=exact",
          },
        }
      ),

      // Contact submissions
      fetch(
        `${process.env.SUPABASE_URL}/rest/v1/contact?select=id,name,email,subject,message,ip_address,status,created_at&order=created_at.desc`,
        {
          headers: {
            apikey: process.env.SUPABASE_SERVICE_KEY,
            Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
          },
        }
      ),

      // Registered users
      fetch(
        `${process.env.SUPABASE_URL}/rest/v1/users?select=id,name,email,is_verified,is_active,created_at,verified_at&order=created_at.desc`,
        {
          headers: {
            apikey: process.env.SUPABASE_SERVICE_KEY,
            Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
          },
        }
      ),

    ]);

    // ---- PARSE ACTING ADMIN ----
    let admins;
    try {
      admins = JSON.parse(await adminRes.text());
    } catch {
      return res.status(500).json({ error: "Server error" });
    }

    if (!Array.isArray(admins) || admins.length === 0) {
      return res.status(401).json({ error: "Invalid session" });
    }

    const admin = admins[0];

    // ---- PARSE TOTAL ADMINS COUNT ----
    // Supabase returns the count in the Content-Range header: "0-4/5"
    const contentRange = adminsCountRes.headers.get("content-range") || "";
    const totalAdmins = contentRange.includes("/")
      ? parseInt(contentRange.split("/")[1], 10) || 0
      : 0;

    // ---- PARSE CONTACTS ----
    let contacts;
    try {
      contacts = JSON.parse(await contactRes.text());
    } catch {
      return res.status(500).json({ error: "Server error" });
    }
    if (!Array.isArray(contacts)) contacts = [];

    // ---- PARSE USERS ----
    let users;
    try {
      users = JSON.parse(await usersRes.text());
    } catch {
      return res.status(500).json({ error: "Server error" });
    }
    if (!Array.isArray(users)) users = [];

    // ---- NEON FETCHES IN PARALLEL ----
    const [donationsRows, formsRows] = await Promise.all([

      sql`
        select
          id,
          receipt_id,
          donor_name,
          email,
          amount,
          currency,
          country,
          created_at
        from donations
        order by created_at desc;
      `,

      sql`
        select
          id,
          form_id,
          name,
          email,
          phone,
          country,
          amount,
          created_at
        from forms
        order by created_at desc;
      `,

    ]);

    const donations = donationsRows || [];
    const forms = formsRows || [];

    // ---- SUMMARY STATS ----
    const totalDonationAmount = donations.reduce((sum, d) => sum + parseFloat(d.amount || 0), 0);
    const totalFormsAmount = forms.reduce((sum, f) => sum + parseFloat(f.amount || 0), 0);

    const stats = {
      total_admins: totalAdmins,
      total_users: users.length,
      verified_users: users.filter(u => u.is_verified).length,
      active_users: users.filter(u => u.is_active).length,
      total_contacts: contacts.length,
      pending_contacts: contacts.filter(c => c.status === "pending").length,
      total_donations: donations.length,
      total_donation_amount: parseFloat(totalDonationAmount.toFixed(2)),
      total_forms: forms.length,
      total_forms_amount: parseFloat(totalFormsAmount.toFixed(2)),
    };

    return res.status(200).json({
      success: true,
      admin: {
        id: admin.id,
        role: session.role,
      },
      stats,
      contacts,
      users,
      donations,
      forms,
    });

  } catch (e) {
    console.error("Dashboard data error:", e.message);
    return res.status(500).json({ error: "Internal server error" });
  }
};
