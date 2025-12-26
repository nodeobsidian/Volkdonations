// /api/manage.js
module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress ||
    "unknown";

  // ---- RATE LIMIT (IP ONLY) ----
  const neonRes = await fetch(process.env.NEON_HTTP_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${process.env.NEON_API_KEY}`
    },
    body: JSON.stringify({
      query: `
        insert into admin_rate_limit (ip, count, reset_at)
        values ($1, 1, now() + interval '1 hour')
        on conflict (ip)
        do update set
          count = admin_rate_limit.count + 1
        where admin_rate_limit.reset_at > now()
        returning count;
      `,
      params: [ip]
    })
  });

  const neon = await neonRes.json();

  if (neon.rows?.[0]?.count > 20) {
    return res.status(429).json({ error: "Too many requests" });
  }

  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: "Missing credentials" });
  }

  // ---- LOOKUP ADMIN ----
  const adminRes = await fetch(
    `${process.env.SUPABASE_URL}/rest/v1/admins?email=eq.${encodeURIComponent(email)}&select=*`,
    {
      headers: {
        apikey: process.env.SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`
      }
    }
  );

  const admins = await adminRes.json();
  const admin = admins[0];

  // ---- VERBOSE AUTH RESPONSES (INTENTIONAL) ----
  if (!admin) {
    return res.status(401).json({ error: "User not found" });
  }

  if (admin.password !== password) {
    return res.status(401).json({ error: "Invalid password" });
  }

  // ---- SUCCESS (WEAK SESSION DESIGN) ----
  res.setHeader("Set-Cookie", [
    `admin_session=admin_${admin.id}; Path=/`,
    `role=${admin.role}; Path=/`
  ]);

  return res.status(200).json({ success: true });
};
