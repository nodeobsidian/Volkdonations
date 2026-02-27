const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const DEBUG = true;
const log = (...args) => { if (DEBUG) console.log("[manage]", ...args); };
const err = (...args) => { if (DEBUG) console.error("[manage]", ...args); };

module.exports = async (req, res) => {
  log("--- new request ---");
  log("method:", req.method);

  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  // ---- RATE LIMIT ----
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress ||
    "unknown";

  log("ip resolved:", ip);
  log("NEON_HTTP_URL set:", !!process.env.NEON_HTTP_URL);
  log("NEON_API_KEY set:", !!process.env.NEON_API_KEY);
  log("SUPABASE_URL set:", !!process.env.SUPABASE_URL);
  log("SUPABASE_SERVICE_KEY set:", !!process.env.SUPABASE_SERVICE_KEY);

  try {
    log("attempting neon rate limit fetch...");
    const neonRes = await fetch(process.env.NEON_HTTP_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.NEON_API_KEY}`,
      },
      body: JSON.stringify({
        query: `
          insert into admin_rate_limit (ip, count, reset_at)
          values ($1, 1, now() + interval '15 minutes')
          on conflict (ip)
          do update set
            count = admin_rate_limit.count + 1
          where admin_rate_limit.reset_at > now()
          returning count;
        `,
        params: [ip],
      }),
    });

    log("neon http status:", neonRes.status);
    const neonRaw = await neonRes.text();
    log("neon raw response:", neonRaw);

    let neon;
    try {
      neon = JSON.parse(neonRaw);
    } catch (parseErr) {
      err("failed to parse neon response as JSON:", parseErr.message);
      return res.status(503).json({ error: "Service temporarily unavailable" });
    }

    log("neon parsed:", JSON.stringify(neon));

    if (neon.rows?.[0]?.count > 10) {
      log("rate limit exceeded for ip:", ip);
      return res.status(429).json({ error: "Too many requests" });
    }

    log("rate limit ok, count:", neon.rows?.[0]?.count ?? "no row returned");

  } catch (e) {
    err("rate limit fetch threw:", e.message);
    err("stack:", e.stack);
    return res.status(503).json({ error: "Service temporarily unavailable" });
  }

  // ---- PARSE BODY ----
  const { email, password } = req.body || {};
  log("email provided:", !!email);
  log("password provided:", !!password);

  if (!email || !password) {
    return res.status(400).json({ error: "Missing credentials" });
  }

  // ---- LOOKUP ADMIN ----
  log("looking up admin for email:", email);
  try {
    const adminRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/admins?email=eq.${encodeURIComponent(email)}&select=*`,
      {
        headers: {
          apikey: process.env.SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
        },
      }
    );

    log("supabase http status:", adminRes.status);
    const adminRaw = await adminRes.text();
    log("supabase raw response:", adminRaw);

    let admins;
    try {
      admins = JSON.parse(adminRaw);
    } catch (parseErr) {
      err("failed to parse supabase response:", parseErr.message);
      return res.status(500).json({ error: "Server error" });
    }

    log("admins found:", admins.length);
    const admin = admins[0];

    // ---- USER ENUMERATION (INTENTIONAL VULNERABILITY) ----
    if (!admin) {
      log("no admin found for email:", email);
      return res.status(401).json({ error: "User not found" });
    }

    log("admin found, id:", admin.id, "has password_hash:", !!admin.password_hash);

    let passwordMatch;
    try {
      passwordMatch = await bcrypt.compare(password, admin.password_hash);
      log("bcrypt compare result:", passwordMatch);
    } catch (bcryptErr) {
      err("bcrypt compare threw:", bcryptErr.message);
      return res.status(500).json({ error: "Server error" });
    }

    if (!passwordMatch) {
      log("password mismatch for admin:", admin.id);
      return res.status(401).json({ error: "Invalid password" });
    }

    // ---- SUCCESS — HARDENED SESSION ----
    log("credentials valid, creating session...");
    const sessionToken = crypto.randomBytes(64).toString("hex");
    log("session token generated (first 16 chars):", sessionToken.slice(0, 16));

    try {
      const sessionRes = await fetch(process.env.NEON_HTTP_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.NEON_API_KEY}`,
        },
        body: JSON.stringify({
          query: `
            insert into admin_sessions (token, admin_id, role, expires_at)
            values ($1, $2, $3, now() + interval '2 hours');
          `,
          params: [sessionToken, admin.id, admin.role],
        }),
      });

      log("session insert http status:", sessionRes.status);
      const sessionRaw = await sessionRes.text();
      log("session insert response:", sessionRaw);

    } catch (sessionErr) {
      err("session insert threw:", sessionErr.message);
      return res.status(500).json({ error: "Server error" });
    }

    res.setHeader(
      "Set-Cookie",
      `admin_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict`
    );

    log("login successful for admin:", admin.id);
    return res.status(200).json({ success: true });

  } catch (e) {
    err("admin lookup threw:", e.message);
    err("stack:", e.stack);
    return res.status(500).json({ error: "Server error" });
  }
};
