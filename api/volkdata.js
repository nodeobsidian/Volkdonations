// /api/volkdata.js
module.exports = async (req, res) => {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  // ---- PARSE COOKIES SAFELY ----
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const cookies = {};
  cookieHeader.split(";").forEach(c => {
    const [key, value] = c.trim().split("=");
    cookies[key] = value;
  });

  const session = cookies.admin_session;
  const role = cookies.role;

  if (!session || !session.startsWith("admin_")) {
    return res.status(401).json({ error: "Invalid session" });
  }

  const adminId = session.replace("admin_", "");

  // ---- VERIFY SESSION AGAINST DB ----
  try {
    const adminRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/admins?id=eq.${encodeURIComponent(adminId)}&select=id,role`,
      {
        headers: {
          apikey: process.env.SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`
        }
      }
    );

    const admins = await adminRes.json();

    if (!admins || admins.length === 0) {
      return res.status(401).json({ error: "Session expired" });
    }

    const admin = admins[0];

    if (!role || role !== admin.role) {
      return res.status(403).json({ error: "Access denied" });
    }

    // ---- FETCH VOLKDATA ----
    const volkRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/volkdata?select=*`,
      {
        headers: {
          apikey: process.env.SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`
        }
      }
    );

    const data = await volkRes.json();

    return res.status(200).json({
      success: true,
      data
    });

  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
};
