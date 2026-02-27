module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  // ---- EXTRACT SESSION COOKIE ----
  const cookies = req.headers.cookie || "";
  const cookieObj = {};
  cookies.split(";").forEach(cookie => {
    const [key, ...rest] = cookie.trim().split("=");
    if (key) cookieObj[key] = rest.join("=");
  });

  const sessionToken = cookieObj.admin_session;

  if (!sessionToken) {
    return res.status(401).json({ authenticated: false, error: "No valid session" });
  }

  // ---- VERIFY SESSION AGAINST SERVER-SIDE STORE ----
  try {
    const neonRes = await fetch(process.env.NEON_HTTP_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.NEON_API_KEY}`,
      },
      body: JSON.stringify({
        query: `
          select s.admin_id, s.role, s.expires_at, a.email
          from admin_sessions s
          join admins a on a.id = s.admin_id
          where s.token = $1
            and s.expires_at > now()
          limit 1;
        `,
        params: [sessionToken],
      }),
    });

    const neon = await neonRes.json();
    const session = neon.rows?.[0];

    if (!session) {
      return res.status(401).json({ authenticated: false, error: "Invalid session" });
    }

    // ---- SUCCESS ----
    return res.status(200).json({
      authenticated: true,
      admin: {
        id: session.admin_id,
        email: session.email,
        role: session.role,
      },
    });

  } catch (e) {
    return res.status(500).json({ authenticated: false, error: "Server error" });
  }
};
