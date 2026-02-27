const { neon } = require("@neondatabase/serverless");

const DEBUG = true;
const log = (...args) => { if (DEBUG) console.log("[adminsessionverify]", ...args); };
const err = (...args) => { if (DEBUG) console.error("[adminsessionverify]", ...args); };

module.exports = async (req, res) => {
  log("--- new request ---");
  log("method:", req.method);

  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  const sql = neon(process.env.NEON_DATABASE_URL);

  // ---- EXTRACT SESSION COOKIE ----
  const cookies = req.headers.cookie || "";
  const cookieObj = {};
  cookies.split(";").forEach(cookie => {
    const [key, ...rest] = cookie.trim().split("=");
    if (key) cookieObj[key] = rest.join("=");
  });

  const sessionToken = cookieObj.admin_session;
  log("session token present:", !!sessionToken);
  log("token preview:", sessionToken?.slice(0, 16));

  if (!sessionToken) {
    return res.status(401).json({ authenticated: false, error: "No valid session" });
  }

  // ---- VERIFY SESSION IN NEON ----
  try {
    log("looking up session in neon...");
    const rows = await sql`
      select admin_id, role, expires_at
      from admin_sessions
      where token = ${sessionToken}
        and expires_at > now()
      limit 1;
    `;

    log("session rows:", JSON.stringify(rows));

    const session = rows[0];

    if (!session) {
      log("no valid session found");
      return res.status(401).json({ authenticated: false, error: "Invalid session" });
    }

    log("session valid, admin_id:", session.admin_id, "role:", session.role);

    // ---- FETCH ADMIN FROM SUPABASE ----
    log("fetching admin from supabase...");
    const adminRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/admins?id=eq.${session.admin_id}&select=id,email,name,role`,
      {
        headers: {
          apikey: process.env.SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
        },
      }
    );

    log("supabase status:", adminRes.status);
    const adminRaw = await adminRes.text();
    log("supabase raw response:", adminRaw);

    let admins;
    try {
      admins = JSON.parse(adminRaw);
    } catch (parseErr) {
      err("failed to parse supabase response:", parseErr.message);
      return res.status(500).json({ authenticated: false, error: "Server error" });
    }

    const admin = admins[0];

    if (!admin) {
      log("admin not found in supabase for id:", session.admin_id);
      return res.status(401).json({ authenticated: false, error: "Invalid session" });
    }

    log("admin fetched:", admin.email);

    // ---- SUCCESS ----
    return res.status(200).json({
      authenticated: true,
      admin: {
        id: admin.id,
        email: admin.email,
        name: admin.name,
        role: session.role,
      },
    });

  } catch (e) {
    err("threw:", e.message);
    err("stack:", e.stack);
    return res.status(500).json({ authenticated: false, error: "Server error" });
  }
};
