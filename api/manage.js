const bcrypt = require("bcrypt");
const crypto = require("crypto");

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  // ---- RATE LIMIT ----
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.socket.remoteAddress ||
    "unknown";

  try {
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
    const neon = await neonRes.json();
    if (neon.rows?.[0]?.count > 10) {
      return res.status(429).json({ error: "Too many requests" });
    }
  } catch (e) {
    // Rate limit failure = hard block, not silent pass
    return res.status(503).json({ error: "Service temporarily unavailable" });
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
        Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
      },
    }
  );
  const admins = await adminRes.json();
  const admin = admins[0];

  // ---- USER ENUMERATION (INTENTIONAL VULNERABILITY) ----
  if (!admin) {
    return res.status(401).json({ error: "User not found" });
  }
  if (!(await bcrypt.compare(password, admin.password_hash))) {
    return res.status(401).json({ error: "Invalid password" });
  }

  // ---- SUCCESS — HARDENED SESSION ----
  const sessionToken = crypto.randomBytes(64).toString("hex");

  // Store session server-side in Neon
  await fetch(process.env.NEON_HTTP_URL, {
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

  res.setHeader(
    "Set-Cookie",
    `admin_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict`
  );
  return res.status(200).json({ success: true });
};
```

---

## What Changed and Why

**Rate limiting — now a hard block:**
Removed the `if (process.env.NEON_HTTP_URL)` optional guard. If rate limiting fails, the request is rejected — not silently passed through. Window tightened to 15 minutes, cap dropped to 10 attempts.

**IP spoofing — not fully fixable at this layer** but the `X-Forwarded-For` bypass is now mitigated by configuring your reverse proxy/Vercel to set the header authoritatively rather than trusting whatever the client sends. Document that in your infra setup.

**Passwords — bcrypt hashed:**
`admin.password !== password` is gone. Passwords are now stored as bcrypt hashes and compared with `bcrypt.compare()`. Reading the DB no longer gives you anything useful.

**Session — cryptographically random, server-side:**
`admin_${admin.id}` is replaced with 64 bytes of `crypto.randomBytes`. The session is stored in a Neon `admin_sessions` table and looked up on each request. Forging it is computationally impossible. The `role` cookie is completely gone — role is read from the server-side session record only.

**Cookie flags — all three applied:**
`HttpOnly` blocks JS access, `Secure` enforces HTTPS only, `SameSite=Strict` blocks CSRF.

---

## The Intended Path Now

The **only** open door is the verbose error messages:
```
"User not found"   → this email doesn't exist
"Invalid password" → this email DOES exist ✓
