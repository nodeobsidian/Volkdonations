const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
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
 * Used to send the post-reset confirmation email.
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

const BCRYPT_ROUNDS = 12; // cost factor — matches signup API

// Rate limiting on this endpoint prevents token brute-force attempts.
// Tokens are 256-bit so brute force is computationally infeasible, but
// we rate-limit anyway as defence-in-depth.
const RATE_LIMIT_MAX       = 10;             // max attempts per IP per window
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15-minute rolling window

// ─────────────────────────────────────────────
// Input helpers
// ─────────────────────────────────────────────

/**
 * Strips null bytes, control characters, and angle brackets.
 * Applied to all string inputs before any processing.
 *
 * @param {string} str
 * @returns {string}
 */
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.trim().replace(/[\x00-\x1F\x7F<>]/g, '');
}

/**
 * Validates that the token is a 64-character lowercase hex string.
 * This matches the format produced by crypto.randomBytes(32).toString('hex')
 * in the forgot-password API. Rejecting tokens that don't match this format
 * before any DB query prevents probing with malformed inputs.
 *
 * @param {string} token
 * @returns {boolean}
 */
function isValidTokenFormat(token) {
  return typeof token === 'string' && /^[a-f0-9]{64}$/.test(token);
}

/**
 * Validates the new password against the same policy as the signup API:
 *   - Minimum 8 characters
 *   - At least one uppercase letter
 *   - At least one lowercase letter
 *   - At least one digit
 *   - At least one special character
 *
 * @param {string} password
 * @returns {boolean}
 */
function isValidPassword(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/.test(password);
}

// ─────────────────────────────────────────────
// Rate limiting — NeonDB `reset_rate_limit` table
//
// Reuses the same table as the forgot-password API, with a different
// key namespace "reset-verify:<ip>" to track this endpoint separately.
//
// This guards against:
//   - Automated token submission attempts
//   - Any theoretical timing side-channel on token lookup
// ─────────────────────────────────────────────

/**
 * Checks whether the given IP has exceeded the rate limit for this endpoint.
 * Fails open on DB error — infrastructure failures never block users.
 *
 * @param {string} ip
 * @returns {{ allowed: boolean }}
 */
async function checkRateLimit(ip) {
  const sql   = getNeon();
  const key   = `reset-verify:${ip}`;
  const since = new Date(Date.now() - RATE_LIMIT_WINDOW_MS).toISOString();

  try {
    const rows = await sql`
      SELECT COUNT(*) AS count
      FROM reset_rate_limit
      WHERE key          = ${key}
        AND attempted_at > ${since}
    `;
    const count = parseInt(rows[0]?.count ?? 0, 10);
    return { allowed: count < RATE_LIMIT_MAX };
  } catch (err) {
    console.error('reset_rate_limit check error:', err);
    return { allowed: true }; // fail open
  }
}

/**
 * Records an attempt for the given IP and prunes stale rows.
 *
 * @param {string} ip
 */
async function recordAttempt(ip) {
  const sql    = getNeon();
  const key    = `reset-verify:${ip}`;
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

// ─────────────────────────────────────────────
// Token lookup
// ─────────────────────────────────────────────

/**
 * Looks up a password reset token record from Supabase.
 * Fetches the associated user in the same query via a join so we can
 * validate user state without a second round-trip.
 *
 * Returns the full record including nested user data, or null if not found.
 *
 * @param {string} token
 */
async function getResetRecord(token) {
  const { data, error } = await supabase
    .from('password_resets')
    .select(`
      id,
      token,
      expires_at,
      used,
      user_id,
      users (
        id,
        email,
        name,
        password_hash,
        is_active,
        is_verified
      )
    `)
    .eq('token', token)
    .maybeSingle();

  if (error) {
    console.error('Token lookup error:', error);
    throw error;
  }
  return data;
}

// ─────────────────────────────────────────────
// Atomic token consumption
// ─────────────────────────────────────────────

/**
 * Marks the reset token as used.
 * This is done BEFORE updating the password so that even if the password
 * update fails, the token cannot be replayed.
 *
 * The update is conditional — it only succeeds if `used` is still false
 * at the time of the update. This provides protection against race
 * conditions where two concurrent requests arrive with the same token:
 * only the first one to execute this update will see rowsAffected > 0.
 *
 * @param {string} tokenId  - UUID primary key of the password_resets row
 * @returns {boolean}       - true if the token was successfully consumed
 */
async function consumeToken(tokenId) {
  const { data, error } = await supabase
    .from('password_resets')
    .update({ used: true })
    .eq('id', tokenId)
    .eq('used', false)  // conditional — prevents double-use race condition
    .select('id');

  if (error) {
    console.error('Token consumption error:', error);
    throw error;
  }

  // If no row was returned, the token was already consumed by a concurrent request
  return Array.isArray(data) && data.length > 0;
}

// ─────────────────────────────────────────────
// Password update
// ─────────────────────────────────────────────

/**
 * Updates the user's password hash in the database.
 *
 * @param {string} userId
 * @param {string} newHash  - bcrypt hash of the new password
 */
async function updatePassword(userId, newHash) {
  const { error } = await supabase
    .from('users')
    .update({ password_hash: newHash })
    .eq('id', userId);

  if (error) {
    console.error('Password update error:', error);
    throw error;
  }
}

// ─────────────────────────────────────────────
// Session invalidation
// ─────────────────────────────────────────────

/**
 * Deletes ALL active sessions for the given user from the sessions table.
 *
 * Enterprise security standard: after a password reset, every existing
 * session — on every device — must be invalidated immediately.
 * Rationale: if the password was compromised, any session tokens issued
 * under the compromised credential are also considered compromised.
 *
 * This forces the user (and any attacker who had a live session) to
 * re-authenticate with the new password.
 *
 * @param {string} userId
 */
async function invalidateAllSessions(userId) {
  const { error } = await supabase
    .from('sessions')
    .delete()
    .eq('user_id', userId);

  if (error) {
    console.error('Session invalidation error:', error);
    throw error;
  }
}

// ─────────────────────────────────────────────
// Post-reset notification email
// ─────────────────────────────────────────────

/**
 * Sends a security notification email informing the user that their
 * password was successfully changed. This is a critical security feature:
 * if the reset was not initiated by the legitimate user, they are alerted
 * immediately and can contact support to recover their account.
 *
 * Sent via Brevo SMTP using the shared nodemailer transporter.
 * Fire-and-forget — failure is logged but does not fail the request,
 * as the password has already been changed successfully at this point.
 *
 * @param {string} toEmail
 * @param {string} toName
 */
async function sendPasswordChangedEmail(toEmail, toName) {
  const displayName = toName || 'there';
  const timestamp   = new Date().toUTCString();

  const mailOptions = {
    from: `"Volk Donations" <${process.env.BREVO_FROM_EMAIL}>`,
    to:      toEmail,
    subject: 'Your Volk Donations password has been changed',
    html: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Password Changed</title>
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

              <!-- Shield icon -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td align="center">
                    <div style="display:inline-block;width:72px;height:72px;border-radius:50%;background:#f0fdf4;border:2px solid rgba(5,150,105,0.25);text-align:center;line-height:72px;font-size:34px;">&#9989;</div>
                  </td>
                </tr>
              </table>

              <!-- Heading -->
              <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#1e3a5f;text-align:center;">Password Successfully Changed</p>
              <p style="margin:0 0 28px;font-size:15px;color:#5a6c7d;line-height:1.75;text-align:center;">
                Hi <strong style="color:#1e3a5f;">${displayName}</strong>, your Volk Donations account password was recently updated.
              </p>

              <!-- Divider -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr><td style="border-top:1px solid #e8edf2;"></td></tr>
              </table>

              <!-- Confirmation box -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td style="background:#f0fdf4;border:1px solid rgba(5,150,105,0.25);border-radius:14px;padding:28px 32px;">
                    <p style="margin:0 0 12px;font-size:12px;font-weight:700;color:#00a86b;letter-spacing:2px;text-transform:uppercase;">Change details</p>
                    <table cellpadding="0" cellspacing="0" width="100%">
                      <tr>
                        <td style="padding:6px 0;font-size:13px;color:#5a6c7d;width:120px;">Account</td>
                        <td style="padding:6px 0;font-size:13px;color:#1e3a5f;font-weight:600;">${toEmail}</td>
                      </tr>
                      <tr>
                        <td style="padding:6px 0;font-size:13px;color:#5a6c7d;">Time</td>
                        <td style="padding:6px 0;font-size:13px;color:#1e3a5f;font-weight:600;">${timestamp}</td>
                      </tr>
                      <tr>
                        <td style="padding:6px 0;font-size:13px;color:#5a6c7d;">Action</td>
                        <td style="padding:6px 0;font-size:13px;color:#1e3a5f;font-weight:600;">All active sessions signed out</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Security warning -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:32px;">
                <tr>
                  <td style="background:#fef2f2;border-left:4px solid #dc2626;border-radius:0 8px 8px 0;padding:14px 18px;">
                    <p style="margin:0;font-size:13px;color:#991b1b;line-height:1.65;">
                      &#128680; <strong>Wasn't you?</strong> If you did not make this change, your account may be compromised. Please contact our support team immediately at <a href="mailto:support@volkdonations.org" style="color:#dc2626;">support@volkdonations.org</a>.
                    </p>
                  </td>
                </tr>
              </table>

              <!-- Divider -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr><td style="border-top:1px solid #e8edf2;"></td></tr>
              </table>

              <!-- CTA to sign in -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td align="center">
                    <p style="margin:0 0 16px;font-size:14px;color:#5a6c7d;">Ready to get back to making a difference?</p>
                    <table cellpadding="0" cellspacing="0" align="center">
                      <tr>
                        <td style="border-radius:10px;background:linear-gradient(135deg,#1e3a5f 0%,#2a4f7c 100%);box-shadow:0 4px 14px rgba(30,58,95,0.35);">
                          <a href="${process.env.APP_BASE_URL || 'https://volkdonations.org'}/auth/login"
                             style="display:inline-block;padding:13px 36px;font-size:14px;font-weight:700;color:#ffffff;text-decoration:none;letter-spacing:0.3px;border-radius:10px;">
                            Sign In to Your Account
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
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
                This security notification was sent to ${toEmail} because your password was changed.
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
// Main handler — POST /api/reset-password
// ─────────────────────────────────────────────

/**
 * Handles the final step of the password reset flow.
 *
 * Security properties of this handler:
 *
 *   1. Rate limited by IP to prevent token brute-force.
 *   2. Token format validated before any DB query.
 *   3. Token looked up and all validity checks (exists, not used, not
 *      expired, user active + verified) performed before any mutation.
 *   4. Token consumed atomically with a conditional update that
 *      guards against race conditions / concurrent replay.
 *   5. New password checked against current hash — same password rejected.
 *   6. Password policy enforced server-side regardless of client validation.
 *   7. Password hashed with bcrypt cost factor 12 before storage.
 *   8. ALL existing sessions invalidated immediately after password update —
 *      enterprise standard, ensures no stale sessions survive a reset.
 *   9. Security notification email sent to the account owner.
 *  10. Generic error messages throughout — no information leakage on
 *      invalid / expired / used tokens.
 *  11. No Turnstile required — the 256-bit token is the auth gate.
 *
 * Flow:
 *   1. Method + input validation.
 *   2. Token format check.
 *   3. Rate limit check + record attempt.
 *   4. Token DB lookup + full validity check.
 *   5. Password policy + same-password check.
 *   6. Atomic token consumption (race-condition safe).
 *   7. Bcrypt new password.
 *   8. Update password in DB.
 *   9. Invalidate ALL sessions.
 *  10. Send security notification email (fire-and-forget).
 *  11. Return 200 success.
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

  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim()
    || req.socket?.remoteAddress
    || '0.0.0.0';

  try {
    const { token, password, confirmPassword } = req.body || {};

    // ── Input presence ───────────────────────
    if (!token || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const cleanToken = sanitizeString(token);

    // ── Token format validation ──────────────
    // Reject anything that doesn't match the expected hex format before
    // touching the database — avoids probing with malformed inputs.
    if (!isValidTokenFormat(cleanToken)) {
      return res.status(400).json({ error: 'Invalid or malformed reset token.' });
    }

    // ── Password match check ─────────────────
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match.' });
    }

    // ── Password length cap ──────────────────
    // bcrypt silently truncates at 72 bytes — enforce the cap explicitly
    // so the user isn't misled about their actual password length.
    if (password.length > 72) {
      return res.status(400).json({ error: 'Password must not exceed 72 characters.' });
    }

    // ── Password policy ──────────────────────
    if (!isValidPassword(password)) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters and include an uppercase letter, lowercase letter, number, and special character.',
      });
    }

    // ── Rate limit ───────────────────────────
    const { allowed } = await checkRateLimit(ip);
    if (!allowed) {
      return res.status(429).json({
        error: 'Too many attempts. Please wait 15 minutes before trying again.',
      });
    }

    // Record attempt before DB work — prevents using this endpoint as a
    // timing oracle under lockout conditions.
    await recordAttempt(ip);

    // ── Token lookup ─────────────────────────
    let record;
    try {
      record = await getResetRecord(cleanToken);
    } catch {
      return res.status(500).json({ error: 'An unexpected error occurred.' });
    }

    // ── Token validity checks ────────────────
    // All failure paths return the same generic message to prevent
    // leaking information about token existence, expiry, or usage state.

    if (!record) {
      return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
    }

    if (record.used) {
      return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
    }

    if (new Date(record.expires_at) < new Date()) {
      return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
    }

    const user = record.users;

    if (!user || !user.is_verified || user.is_active === false) {
      return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
    }

    // ── Same-password check ──────────────────
    // Reject the new password if it matches the current one.
    // Prevents password reset being used as a no-op that bypasses
    // "must change password" policies or satisfies an attacker who
    // already knows the current password.
    const isSamePassword = await bcrypt.compare(password, user.password_hash);
    if (isSamePassword) {
      return res.status(400).json({
        error: 'Your new password cannot be the same as your current password.',
      });
    }

    // ── Atomic token consumption ─────────────
    // Mark the token as used BEFORE updating the password.
    // The conditional update (WHERE used = false) ensures that even if two
    // concurrent requests arrive with the same token, only the first one
    // succeeds — the second will get consumed = false and be rejected.
    let consumed;
    try {
      consumed = await consumeToken(record.id);
    } catch {
      return res.status(500).json({ error: 'An unexpected error occurred.' });
    }

    if (!consumed) {
      // Another concurrent request already consumed this token
      return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
    }

    // ── Hash new password ────────────────────
    const newHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // ── Update password ──────────────────────
    try {
      await updatePassword(user.id, newHash);
    } catch {
      return res.status(500).json({ error: 'Failed to update password. Please try again.' });
    }

    // ── Invalidate ALL sessions ──────────────
    // Enterprise standard: kill every active session after a password reset.
    // If the account was compromised, any existing session tokens are also
    // compromised and must not remain valid under any circumstances.
    try {
      await invalidateAllSessions(user.id);
    } catch {
      // Log but do not fail the request — the password has already been
      // changed. Session invalidation failure is a degraded security state
      // but not a reason to report failure to the user.
      console.error('Session invalidation failed for user:', user.id);
    }

    // ── Security notification email ──────────
    // Fire-and-forget — do not await or let email failure affect the response.
    // The password change has already succeeded at this point.
    sendPasswordChangedEmail(user.email, user.name).catch((err) => {
      console.error('Password changed notification email failed:', err);
    });

    // ── Success ──────────────────────────────
    return res.status(200).json({
      message: 'Your password has been reset successfully. You can now sign in with your new password.',
    });

  } catch (err) {
    console.error('Reset password handler error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
};
