const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { neon } = require('@neondatabase/serverless');

// ─────────────────────────────────────────────
// Clients
// ─────────────────────────────────────────────

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

/**
 * Returns a fresh Neon serverless SQL client.
 * Uses NEON_DATABASE_URL from environment variables.
 */
function getNeon() {
  return neon(process.env.NEON_DATABASE_URL);
}

/**
 * Nodemailer transporter configured for Brevo SMTP.
 * Credentials pulled from environment variables:
 *   BREVO_SMTP_USER  — Brevo SMTP username
 *   BREVO_SMTP_KEY   — Brevo SMTP password / API key
 *   BREVO_FROM_EMAIL — verified sender address in Brevo
 */
const transporter = nodemailer.createTransport({
  host:   'smtp-relay.brevo.com',
  port:   587,
  secure: false,
  auth: {
    user: process.env.BREVO_SMTP_USER,
    pass: process.env.BREVO_SMTP_KEY,
  },
});

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour token lifetime

// Rate limiting: tracked separately by IP and by email.
// If either threshold is exceeded the request is blocked.
const RATE_LIMIT_BY_IP_MAX    = 10;             // max requests per IP per window
const RATE_LIMIT_BY_EMAIL_MAX = 5;              // max requests per email per window
const RATE_LIMIT_WINDOW_MS    = 15 * 60 * 1000; // 15-minute rolling window

// ─────────────────────────────────────────────
// Input helpers
// ─────────────────────────────────────────────

/**
 * Strips null bytes, control characters, and angle brackets from a string.
 * Prevents injection via unusual Unicode or control sequences and blocks
 * HTML injection in any context where the value might be rendered.
 *
 * @param {string} str
 * @returns {string}
 */
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.trim().replace(/[\x00-\x1F\x7F<>]/g, '');
}

/**
 * Basic RFC-5322 inspired email validation.
 * Not exhaustive — just enough to reject obviously malformed input.
 *
 * @param {string} email
 * @returns {boolean}
 */
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).toLowerCase().trim());
}

// ─────────────────────────────────────────────
// Rate limiting — NeonDB `reset_rate_limit` table
//
// Table schema (create once):
//   CREATE TABLE reset_rate_limit (
//     id           SERIAL      PRIMARY KEY,
//     key          TEXT        NOT NULL,
//     attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
//   );
//   CREATE INDEX ON reset_rate_limit (key, attempted_at);
//
// Requests are tracked with two distinct key namespaces:
//   "ip:<ip_address>"  — limits requests from a single IP
//   "email:<email>"    — limits requests targeting a single account
//
// Both keys are checked independently and either can trigger a block.
// This prevents:
//   - A single IP hammering many accounts  (IP limit)
//   - Many IPs hammering one account       (email limit)
// ─────────────────────────────────────────────

/**
 * Counts how many reset requests have been made with `key`
 * within the rolling window. Returns { allowed, count }.
 * Fails open on DB error — we never block legitimate users due to infra issues.
 *
 * @param {string} key  - namespaced key e.g. "ip:1.2.3.4" or "email:foo@bar.com"
 * @param {number} max  - threshold above which requests are denied
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
  const [byIp, byEmail] = await Promise.all([
    checkRateLimitByKey(`ip:${ip}`,       RATE_LIMIT_BY_IP_MAX),
    checkRateLimitByKey(`email:${email}`, RATE_LIMIT_BY_EMAIL_MAX),
  ]);
  return { allowed: byIp.allowed && byEmail.allowed };
}

/**
 * Records a reset attempt against both the IP and email keys in parallel.
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
 * Returns the user row or null — the caller handles both cases with
 * identical response timing to prevent email enumeration.
 *
 * @param {string} email
 */
async function getUserByEmail(email) {
  const { data, error } = await supabase
    .from('users')
    .select('id, email, name, is_active, is_verified')
    .eq('email', email)
    .maybeSingle();

  if (error) {
    console.error('User lookup error:', error);
    throw error;
  }
  return data;
}

/**
 * Deletes any existing unused reset tokens for the user then inserts
 * a fresh one, ensuring only one valid token exists at a time.
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
 * @param {string} expiresAt  ISO timestamp string
 */
async function storeResetToken(userId, token, expiresAt) {
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
// !!!  INTENTIONAL VULNERABILITY — HOST HEADER INJECTION  !!!
// ─────────────────────────────────────────────
//
// VULNERABILITY CLASS : CWE-601 / Host Header Injection
// OWASP REFERENCE     : OWASP Testing Guide — WSTG-CLNT-05
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
//   5. Victim clicks the link — their browser sends the token to attacker.com.
//   6. Attacker captures the token from their server logs and uses it to
//      reset the victim's password — full account takeover.
//
// PRE-CONDITIONS:
//   - The attacker must be able to send requests to the server.
//   - The attacker must control a server at the spoofed domain.
//   - The victim must click the link (social engineering / urgency).
//   - The server must not sit behind a reverse proxy that overwrites Host
//     with a fixed value (many cloud providers do this transparently —
//     the lab may require raw/direct access to exercise this).
//
// SECURE FIX (do NOT apply in this lab environment):
//   Never derive the application base URL from request headers.
//   Use a hard-coded or environment-variable-backed trusted origin:
//
//       const base = process.env.APP_BASE_URL; // "https://volkdonations.org"
//       return `${base}/auth/reset-password?token=${token}`;
//
// ─────────────────────────────────────────────

/**
 * Builds the full password reset URL to be embedded in the email.
 *
 * ⚠️  INTENTIONALLY VULNERABLE — reads `Host` from the incoming request
 *     without any validation or allowlist check.
 *     See the detailed vulnerability comment block above.
 *
 * @param {object} req    - raw Node.js / Express request object
 * @param {string} token  - the reset token to embed in the URL
 * @returns {string}      - full reset URL
 */
function buildResetLink(req, token) {
  const protocol = process.env.NODE_ENV === 'production' ? 'https' : (req.protocol || 'http');

  // ── VULNERABLE LINE ──────────────────────────────────────────────────────
  // `req.headers['host']` is fully attacker-controlled.
  // A request with `Host: attacker.com` produces a reset link pointing at
  // attacker.com, which is then delivered to the victim via email.
  const host = req.headers['host'];
  // ── END VULNERABLE LINE ──────────────────────────────────────────────────

  return `${protocol}://${host}/auth/reset-password?token=${token}`;
}

// ─────────────────────────────────────────────
// Email — branded HTML template via SendPulse SMTP
// ─────────────────────────────────────────────

/**
 * Sends a branded password reset email to the user via SendPulse SMTP.
 * Uses nodemailer with the SendPulse transporter defined at module level.
 * The reset link is injected into a fully self-contained HTML template
 * that matches the Volk Donations brand system (navy + green, DM Serif tone).
 *
 * @param {string} toEmail   - recipient email address
 * @param {string} toName    - recipient display name for personalisation
 * @param {string} resetLink - the full reset URL built by buildResetLink()
 */
async function sendResetEmail(toEmail, toName, resetLink) {
  const displayName = toName || 'there';

  const mailOptions = {
    from:    `"Volk Donations" <${process.env.BREVO_FROM_EMAIL}>`,
    to:      toEmail,
    subject: 'Reset your Volk Donations password',
    html: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Reset Your Password</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f4f8;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f4f8;padding:48px 16px;">
    <tr>
      <td align="center">

        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 8px 40px rgba(0,0,0,0.10);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#1e3a5f 0%,#0d5c3a 100%);padding:44px 40px 38px;text-align:center;">
              <table cellpadding="0" cellspacing="0" align="center">
                <tr>
                  <td align="center">
                    <div style="display:inline-block;width:60px;height:60px;border-radius:50%;background:rgba(255,255,255,0.15);border:2px solid rgba(255,255,255,0.4);text-align:center;line-height:60px;font-size:28px;font-weight:800;color:#ffffff;">V</div>
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:14px;text-align:center;">
                    <p style="margin:0;font-size:26px;font-weight:800;color:#ffffff;letter-spacing:0.5px;">Volk Donations</p>
                    <p style="margin:6px 0 0;font-size:12px;color:rgba(255,255,255,0.75);letter-spacing:1.5px;text-transform:uppercase;">A better life for everyone</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Green accent bar -->
          <tr>
            <td style="height:4px;background:#00a86b;"></td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:50px 48px 40px;">

              <!-- Lock icon -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td align="center">
                    <div style="display:inline-block;width:72px;height:72px;border-radius:50%;background:#f0f4f8;border:2px solid #d5e0ec;text-align:center;line-height:72px;font-size:34px;">&#128274;</div>
                  </td>
                </tr>
              </table>

              <!-- Heading + greeting -->
              <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#1e3a5f;text-align:center;">Password Reset Request</p>
              <p style="margin:0 0 28px;font-size:15px;color:#5a6c7d;line-height:1.75;text-align:center;">
                Hi <strong style="color:#1e3a5f;">${displayName}</strong>, we received a request to reset the password associated with your Volk Donations account.
              </p>

              <!-- Divider -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr><td style="border-top:1px solid #e8edf2;"></td></tr>
              </table>

              <!-- CTA block -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td style="background:#f0f4f8;border:1px solid #d5e0ec;border-radius:14px;padding:32px 36px;text-align:center;">
                    <p style="margin:0 0 8px;font-size:11px;font-weight:700;color:#00a86b;letter-spacing:2px;text-transform:uppercase;">Reset your password</p>
                    <p style="margin:0 0 24px;font-size:14px;color:#5a6c7d;line-height:1.65;">
                      Click the button below to choose a new password.<br/>
                      This link is valid for <strong style="color:#1e3a5f;">1 hour</strong> and can only be used once.
                    </p>
                    <table cellpadding="0" cellspacing="0" align="center">
                      <tr>
                        <td style="border-radius:10px;background:linear-gradient(135deg,#1e3a5f 0%,#2a4f7c 100%);box-shadow:0 4px 14px rgba(30,58,95,0.35);">
                          <a href="${resetLink}"
                             style="display:inline-block;padding:15px 44px;font-size:15px;font-weight:700;color:#ffffff;text-decoration:none;letter-spacing:0.3px;border-radius:10px;">
                            Reset My Password
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Fallback plain-text link -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td style="background:#f8fafc;border-left:4px solid #2a4f7c;border-radius:0 8px 8px 0;padding:14px 18px;">
                    <p style="margin:0 0 6px;font-size:12px;font-weight:700;color:#1e3a5f;">Button not working?</p>
                    <p style="margin:0 0 8px;font-size:12px;color:#5a6c7d;line-height:1.6;">Copy and paste this link into your browser:</p>
                    <p style="margin:0;font-size:11px;color:#2a4f7c;word-break:break-all;font-family:monospace;">${resetLink}</p>
                  </td>
                </tr>
              </table>

              <!-- Security warning -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:32px;">
                <tr>
                  <td style="background:#fff8e1;border-left:4px solid #f59e0b;border-radius:0 8px 8px 0;padding:14px 18px;">
                    <p style="margin:0;font-size:13px;color:#78600a;line-height:1.65;">
                      &#9888;&#65039; <strong>Didn't request this?</strong> If you did not request a password reset, you can safely ignore this email. Your current password will remain unchanged.
                    </p>
                  </td>
                </tr>
              </table>

              <!-- Divider -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr><td style="border-top:1px solid #e8edf2;"></td></tr>
              </table>

              <!-- Mission blurb -->
              <table cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td style="background:linear-gradient(135deg,#1e3a5f 0%,#0d5c3a 100%);border-radius:12px;padding:24px 28px;">
                    <p style="margin:0 0 6px;font-size:14px;font-weight:700;color:#ffffff;">Thank you for being part of our mission</p>
                    <p style="margin:0;font-size:13px;color:rgba(255,255,255,0.80);line-height:1.7;">
                      Your generosity helps provide shelter, education, and care to orphaned children across 38 countries. We're glad to have you with us.
                    </p>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#1e3a5f;padding:30px 48px;text-align:center;">
              <p style="margin:0 0 16px;">
                <a href="#" style="display:inline-block;margin:0 6px;color:#ffffff;font-size:12px;text-decoration:none;opacity:0.75;">Facebook</a>
                <span style="color:rgba(255,255,255,0.3);">&#183;</span>
                <a href="#" style="display:inline-block;margin:0 6px;color:#ffffff;font-size:12px;text-decoration:none;opacity:0.75;">Twitter</a>
                <span style="color:rgba(255,255,255,0.3);">&#183;</span>
                <a href="#" style="display:inline-block;margin:0 6px;color:#ffffff;font-size:12px;text-decoration:none;opacity:0.75;">LinkedIn</a>
              </p>
              <p style="margin:0 0 6px;font-size:12px;color:rgba(255,255,255,0.55);">&#169; 2026 Volk Donations &#183; All rights reserved</p>
              <p style="margin:0 0 8px;font-size:11px;color:rgba(255,255,255,0.40);">
                Registered 501(c)(3) Nonprofit &#183; EIN: 45-1234567<br/>
                Making a difference since 2010
              </p>
              <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.30);">
                This email was sent to ${toEmail} because a password reset was requested for this account.
              </p>
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>

</body>
</html>`,
  };

  await transporter.sendMail(mailOptions);
}

// ─────────────────────────────────────────────
// Main handler — POST /api/forgot-password
// ─────────────────────────────────────────────

/**
 * Handles password reset requests.
 *
 * Flow:
 *   1. Validate HTTP method and input fields.
 *   2. Verify Cloudflare Turnstile CAPTCHA token.
 *   3. Check rate limits by IP and email independently.
 *   4. Record this attempt against both rate limit keys.
 *   5. Look up the user — respond identically whether they exist or not
 *      to prevent email enumeration.
 *   6. If the account is valid, generate a token, persist it, build the
 *      reset link via buildResetLink() (⚠️ intentionally vulnerable),
 *      and send the branded email via SendPulse SMTP.
 *   7. Always respond with a generic 200 success message.
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

  // Derive caller IP — prefer leftmost entry of X-Forwarded-For.
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
    // Checked BEFORE any DB lookup to avoid using this endpoint as a
    // timing oracle under lockout conditions.
    const { allowed } = await checkRateLimits(ip, cleanEmail);
    if (!allowed) {
      return res.status(429).json({
        error: 'Too many requests. Please wait 15 minutes before trying again.',
      });
    }

    // Record this attempt regardless of outcome — even unknown emails are
    // counted towards both limits to prevent enumeration via rate-limit
    // side-channel ("does rate limiting kick in for this email?").
    await recordAttempts(ip, cleanEmail);

    // ── User lookup ──────────────────────────
    // Perform lookup but always return an identical response whether the
    // user exists or not — prevents confirming registered email addresses.
    let user = null;
    try {
      user = await getUserByEmail(cleanEmail);
    } catch {
      // DB error — return generic success to avoid leaking information.
      return res.status(200).json({
        message: 'If that email is registered, you will receive a reset link shortly.',
      });
    }

    // ── Token generation and email dispatch ──
    // Only proceed if the account exists, is verified, and is active.
    // All other paths still fall through to the same generic 200 response.
    if (user && user.is_verified && user.is_active !== false) {
      const token     = generateResetToken();
      const expiresAt = new Date(Date.now() + TOKEN_TTL_MS).toISOString();

      try {
        await storeResetToken(user.id, token, expiresAt);

        // ⚠️ buildResetLink() is intentionally vulnerable to Host Header
        // Injection — see its detailed comment block for the full explanation.
        const resetLink = buildResetLink(req, token);

        await sendResetEmail(cleanEmail, user.name, resetLink);
      } catch (innerErr) {
        console.error('Token storage / email dispatch error:', innerErr);
        // Still fall through to generic success — don't leak which step failed.
      }
    }

    // ── Generic response ─────────────────────
    // Always 200 with identical body regardless of whether the email
    // exists, the account state, or whether the email was actually sent.
    return res.status(200).json({
      message: 'If that email is registered, you will receive a reset link shortly.',
    });

  } catch (err) {
    console.error('Forgot password handler error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
};
