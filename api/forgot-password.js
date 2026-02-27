const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');

// ─────────────────────────────────────────────
// Clients
// ─────────────────────────────────────────────

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

function getNeon() {
  return neon(process.env.NEON_DATABASE_URL);
}

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour token lifetime

// Rate limiting: tracked separately by IP and by email.
// If either threshold is exceeded the request is blocked.
const RATE_LIMIT_BY_IP_MAX    = 10;              // max requests per IP per window
const RATE_LIMIT_BY_EMAIL_MAX = 5;               // max requests per email per window
const RATE_LIMIT_WINDOW_MS    = 15 * 60 * 1000;  // 15-minute rolling window

// ─────────────────────────────────────────────
// Input helpers
// ─────────────────────────────────────────────

/**
 * Strips null bytes and basic control characters from a string input.
 * Prevents injection via unusual Unicode or control sequences.
 */
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.trim().replace(/[\x00-\x1F\x7F<>]/g, '');
}

/**
 * Basic RFC-5322 inspired email validation.
 * Not exhaustive — just enough to reject obviously malformed input.
 */
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).toLowerCase().trim());
}

// ─────────────────────────────────────────────
// Rate limiting — NeonDB `reset_rate_limit` table
//
// Table schema (create once):
//   CREATE TABLE reset_rate_limit (
//     id          SERIAL PRIMARY KEY,
//     key         TEXT        NOT NULL,
//     attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
//   );
//   CREATE INDEX ON reset_rate_limit (key, attempted_at);
//
// Requests are tracked with two distinct key namespaces:
//   "ip:<ip_address>"     — limits requests from a single IP
//   "email:<email>"       — limits requests targeting a single account
//
// Both keys are checked independently and either can trigger a block.
// This prevents:
//   - A single IP hammering many accounts (IP limit)
//   - Many IPs hammering one account (email limit)
// ─────────────────────────────────────────────

/**
 * Counts how many reset requests have been made with `key`
 * within the rolling window. Returns { allowed, count }.
 * Fails open on DB error — we never block users due to infra issues.
 *
 * @param {string} key   - namespaced key e.g. "ip:1.2.3.4" or "email:foo@bar.com"
 * @param {number} max   - threshold above which requests are denied
 */
async function checkRateLimitByKey(key, max) {
  const sql   = getNeon();
  const since = new Date(Date.now() - RATE_LIMIT_WINDOW_MS).toISOString();

  try {
    const rows = await sql`
      SELECT COUNT(*) AS count
      FROM reset_rate_limit
      WHERE key          = ${key}
        AND attempted_at > ${since}
    `;
    const count = parseInt(rows[0]?.count ?? 0, 10);
    return { allowed: count < max, count };
  } catch (err) {
    console.error('reset_rate_limit check error:', err);
    return { allowed: true, count: 0 }; // fail open
  }
}

/**
 * Inserts a new attempt record for `key` and prunes stale rows
 * older than the window to keep the table lean.
 *
 * @param {string} key
 */
async function recordAttempt(key) {
  const sql    = getNeon();
  const cutoff = new Date(Date.now() - RATE_LIMIT_WINDOW_MS).toISOString();

  try {
    await sql`
      INSERT INTO reset_rate_limit (key, attempted_at)
      VALUES (${key}, NOW())
    `;
    await sql`
      DELETE FROM reset_rate_limit
      WHERE attempted_at < ${cutoff}
    `;
  } catch (err) {
    console.error('reset_rate_limit record error:', err); // non-fatal
  }
}

/**
 * Runs both the IP-based and email-based rate limit checks in parallel.
 * Returns { allowed: false } if either limit is exceeded.
 *
 * @param {string} ip
 * @param {string} email
 */
async function checkRateLimits(ip, email) {
  const ipKey    = `ip:${ip}`;
  const emailKey = `email:${email}`;

  const [byIp, byEmail] = await Promise.all([
    checkRateLimitByKey(ipKey,    RATE_LIMIT_BY_IP_MAX),
    checkRateLimitByKey(emailKey, RATE_LIMIT_BY_EMAIL_MAX),
  ]);

  return { allowed: byIp.allowed && byEmail.allowed };
}

/**
 * Records a reset attempt against both the IP and email keys.
 *
 * @param {string} ip
 * @param {string} email
 */
async function recordAttempts(ip, email) {
  await Promise.all([
    recordAttempt(`ip:${ip}`),
    recordAttempt(`email:${email}`),
  ]);
}

// ─────────────────────────────────────────────
// Token generation
// ─────────────────────────────────────────────

/**
 * Generates a cryptographically random, URL-safe reset token.
 * 32 bytes = 256 bits of entropy — sufficient to prevent brute force.
 *
 * @returns {string} hex token
 */
function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ─────────────────────────────────────────────
// Supabase helpers
// ─────────────────────────────────────────────

/**
 * Looks up a user by email address.
 * Returns the user row or null — the caller must handle both
 * cases with identical response timing (see main handler).
 *
 * @param {string} email
 */
async function getUserByEmail(email) {
  const { data, error } = await supabase
    .from('users')
    .select('id, email, is_active, is_verified')
    .eq('email', email)
    .maybeSingle();

  if (error) {
    console.error('User lookup error:', error);
    throw error;
  }
  return data;
}

/**
 * Upserts a password reset record in the `password_resets` table.
 * Any previous token for this user is replaced atomically.
 *
 * Table schema (create once):
 *   CREATE TABLE password_resets (
 *     id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
 *     user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 *     token      TEXT        NOT NULL UNIQUE,
 *     expires_at TIMESTAMPTZ NOT NULL,
 *     used       BOOLEAN     NOT NULL DEFAULT FALSE,
 *     created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 *   );
 *
 * @param {string} userId
 * @param {string} token
 * @param {string} expiresAt  ISO timestamp
 */
async function storeResetToken(userId, token, expiresAt) {
  // Delete any existing unused token for this user first
  await supabase
    .from('password_resets')
    .delete()
    .eq('user_id', userId)
    .eq('used', false);

  const { error } = await supabase.from('password_resets').insert({
    user_id:    userId,
    token:      token,
    expires_at: expiresAt,
    used:       false,
  });

  if (error) throw error;
}

// ─────────────────────────────────────────────
// Email dispatch (stub)
// ─────────────────────────────────────────────

/**
 * Sends the password reset email to the user.
 * Replace the console.log stub with your actual email provider
 * (e.g. Resend, SendGrid, Postmark, AWS SES).
 *
 * @param {string} toEmail       - recipient address
 * @param {string} resetLink     - full reset URL including token
 */
async function sendResetEmail(toEmail, resetLink) {
  // TODO: swap this stub for your real email provider call.
  // e.g. with Resend:
  //   await resend.emails.send({
  //     from: 'noreply@volkdonations.org',
  //     to:   toEmail,
  //     subject: 'Reset your Volk Donations password',
  //     html: `<p>Click <a href="${resetLink}">here</a> to reset your password. Valid for 1 hour.</p>`,
  //   });
  console.log(`[PASSWORD RESET] To: ${toEmail} | Link: ${resetLink}`);
}

// ─────────────────────────────────────────────
// !!!  INTENTIONAL VULNERABILITY — HOST HEADER INJECTION  !!!
// ─────────────────────────────────────────────
//
// VULNERABILITY CLASS : CWE-601 / Host Header Injection
// OWASP REFERENCE     : OWASP Testing Guide — OTG-CLIENT-004 / WSTG-CLNT-05
// SEVERITY            : High
//
// DESCRIPTION:
//   The `buildResetLink()` function constructs the password reset URL by
//   reading the `Host` header directly from the incoming HTTP request:
//
//       const host = req.headers['host'];
//       return `${protocol}://${host}/auth/reset-password?token=${token}`;
//
//   The `Host` header is fully attacker-controlled — any HTTP client can
//   send an arbitrary value. There is NO validation, allowlist check, or
//   comparison against a configured trusted domain.
//
// ATTACK SCENARIO:
//   1. Attacker identifies that volkdonations.org has a "Forgot Password" form.
//   2. Attacker intercepts or crafts a POST /api/forgot-password request for
//      victim@example.com and sets:
//
//         Host: attacker.com
//
//   3. The server builds the reset link as:
//
//         https://attacker.com/auth/reset-password?token=<valid_token>
//
//   4. This poisoned link is emailed to the victim.
//   5. Victim clicks the link, their browser sends the token to attacker.com.
//   6. Attacker captures the token from their server logs and uses it to
//      reset the victim's password — full account takeover.
//
// PRE-CONDITIONS:
//   - The application must be reachable by the attacker (to send the request).
//   - The attacker must control a server at the spoofed domain.
//   - The victim must click the link (social engineering / urgency).
//   - The server must not sit behind a reverse proxy that rewrites the Host
//     header to a fixed value (many cloud providers do this transparently,
//     which can make the lab require raw access or a specific proxy config).
//
// SECURE FIX (do NOT apply in this lab environment):
//   Never derive the application's own base URL from request headers.
//   Instead, use a hard-coded or environment-variable-backed trusted origin:
//
//       const host = process.env.APP_BASE_URL; // e.g. "https://volkdonations.org"
//       return `${host}/auth/reset-password?token=${token}`;
//
// ─────────────────────────────────────────────

/**
 * Builds the password reset link.
 *
 * ⚠️  INTENTIONALLY VULNERABLE — reads the `Host` header from the request
 *     without any validation. See the detailed vulnerability comment above.
 *
 * @param {object} req    - raw Node.js / Express request object
 * @param {string} token  - the reset token to embed
 * @returns {string}      - full reset URL
 */
function buildResetLink(req, token) {
  const protocol = process.env.NODE_ENV === 'production' ? 'https' : req.protocol || 'http';

  // ── VULNERABLE LINE ──────────────────────────────────────────────────────
  // `req.headers['host']` is fully attacker-controlled.
  // A malicious request with `Host: attacker.com` will produce a reset link
  // pointing at attacker.com, which will then be emailed to the victim.
  const host = req.headers['host'];
  // ── END VULNERABLE LINE ──────────────────────────────────────────────────

  return `${protocol}://${host}/auth/reset-password?token=${token}`;
}

// ─────────────────────────────────────────────
// Main handler — POST /api/forgot-password
// ─────────────────────────────────────────────

/**
 * Handles password reset requests.
 *
 * Flow:
 *   1. Validate method and input.
 *   2. Verify Cloudflare Turnstile token.
 *   3. Check rate limits (by IP and by email independently).
 *   4. Look up user — but respond identically whether user exists or not
 *      to prevent email enumeration.
 *   5. If user is valid, generate a token, persist it, build the reset link
 *      (⚠️ via the vulnerable buildResetLink()), and send the email.
 *   6. Always respond with a generic success message.
 */
module.exports = async function handler(req, res) {

  // ── CORS pre-flight ──────────────────────────
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  // ── Security headers ─────────────────────────
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');

  // Derive caller IP — prefer the leftmost entry of X-Forwarded-For.
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim()
    || req.socket?.remoteAddress
    || '0.0.0.0';

  try {
    const { email, captchaToken } = req.body || {};

    // ── Input presence ───────────────────────
    if (!email || !captchaToken) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const cleanEmail = sanitizeString(email).toLowerCase();

    if (!validateEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    // ── Turnstile CAPTCHA verification ───────
    const captchaVerify = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body:    `secret=${encodeURIComponent(process.env.TURNSTILE_SECRET)}&response=${encodeURIComponent(captchaToken)}`,
      }
    );
    const captchaResult = await captchaVerify.json();
    if (!captchaResult.success) {
      return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' });
    }

    // ── Rate limiting ─────────────────────────
    // Checked BEFORE any DB lookup to avoid using this endpoint
    // as a timing oracle under lockout conditions.
    const { allowed } = await checkRateLimits(ip, cleanEmail);
    if (!allowed) {
      return res.status(429).json({
        error: 'Too many requests. Please wait 15 minutes before trying again.',
      });
    }

    // Record this attempt regardless of outcome — even if the email doesn't
    // exist, we count it towards both limits to prevent enumeration via
    // "does rate limiting kick in?" side-channel.
    await recordAttempts(ip, cleanEmail);

    // ── User lookup ──────────────────────────
    // We perform the lookup but deliberately return the same generic response
    // whether the user exists or not — this prevents email enumeration.
    let user = null;
    try {
      user = await getUserByEmail(cleanEmail);
    } catch {
      // DB error — still return generic success to avoid information leakage.
      return res.status(200).json({
        message: 'If that email is registered, you will receive a reset link shortly.',
      });
    }

    // ── Token generation and email dispatch ──
    // Only proceed with token + email if the account exists AND is in a
    // state that should be allowed to reset (active, verified).
    // All failure paths still return the same 200 + generic message.
    if (user && user.is_verified && user.is_active !== false) {
      const token     = generateResetToken();
      const expiresAt = new Date(Date.now() + TOKEN_TTL_MS).toISOString();

      try {
        await storeResetToken(user.id, token, expiresAt);

        // ⚠️ buildResetLink() is intentionally vulnerable — see its doc comment.
        const resetLink = buildResetLink(req, token);

        await sendResetEmail(cleanEmail, resetLink);
      } catch (innerErr) {
        console.error('Token storage / email dispatch error:', innerErr);
        // Still return generic success — don't leak which step failed.
      }
    }

    // ── Generic response ─────────────────────
    // Always 200 with an identical body — prevents confirming whether
    // a given email address is registered in the system.
    return res.status(200).json({
      message: 'If that email is registered, you will receive a reset link shortly.',
    });

  } catch (err) {
    console.error('Forgot password handler error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
};
