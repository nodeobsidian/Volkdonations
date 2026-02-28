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
    // ---- VERIFY SESSION AGAINST NEON (same as adminsessionverify) ----
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

    // ---- FETCH ADMIN FROM SUPABASE ----
    const adminRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/admins?id=eq.${session.admin_id}&select=id,email,role`,
      {
        headers: {
          apikey: process.env.SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
        },
      }
    );

    const adminRaw = await adminRes.text();
    let admins;
    try {
      admins = JSON.parse(adminRaw);
    } catch {
      return res.status(500).json({ error: "Server error" });
    }

    if (!Array.isArray(admins) || admins.length === 0) {
      return res.status(401).json({ error: "Invalid session" });
    }

    const admin = admins[0];

    // ---- FETCH VOLKDATA FROM SUPABASE ----
    const volkRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/volkdata?select=*&order=created_at.desc`,
      {
        headers: {
          apikey: process.env.SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
        },
      }
    );

    const volkRaw = await volkRes.text();
    let volkdata;
    try {
      volkdata = JSON.parse(volkRaw);
    } catch {
      return res.status(500).json({ error: "Server error" });
    }

    return res.status(200).json({
      success: true,
      admin: {
        id: admin.id,
        role: session.role,
      },
      data: volkdata,
    });

  } catch (e) {
    console.error("Volkdata error:", e.message);
    return res.status(500).json({ error: "Internal server error" });
  }
};
