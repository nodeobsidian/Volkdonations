'use strict';

/**
 * /api/verify — Email verification endpoint
 *
 * Rate limiting strategy (NeonDB — verify_rate_limit table):
 *   • Per-IP  : max 5 attempts / 15-minute window  → hard lockout for 15 min
 *   • Per-email: max 8 attempts / 1-hour window     → hard lockout for 1 hour
 *   Both limits are checked independently; either breach blocks the request.
 *
 * Required env vars:
 *   NEON_DATABASE_URL          – NeonDB connection string
 *   SUPABASE_URL               – Supabase project URL
 *   SUPABASE_SERVICE_ROLE_KEY  – Supabase service-role key (server-side only)
 *   ALLOWED_ORIGIN             – Exact origin for CORS (e.g. https://volkdonations.org)
 *
 * NeonDB table DDL (run once):
 * ─────────────────────────────────────────────────────────────────────────────
 *   CREATE TABLE IF NOT EXISTS verify_rate_limit (
 *     id          BIGSERIAL PRIMARY KEY,
 *     key_type    TEXT        NOT NULL,          -- 'ip' | 'email'
 *     key_value   TEXT        NOT NULL,
 *     attempts    INTEGER     NOT NULL DEFAULT 1,
 *     window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 *     locked_until TIMESTAMPTZ
 *   );
 *   CREATE UNIQUE INDEX IF NOT EXISTS idx_vrl_type_value
 *     ON verify_rate_limit (key_type, key_value);
 *   CREATE INDEX IF NOT EXISTS idx_vrl_locked
 *     ON verify_rate_limit (locked_until)
 *     WHERE locked_until IS NOT NULL;
 * ─────────────────────────────────────────────────────────────────────────────
 */

const { createClient } = require('@supabase/supabase-js');
const { neon }         = require('@neondatabase/serverless');
const crypto           = require('crypto');

// ── Constants ────────────────────────────────────────────────────────────────

const IP_MAX_ATTEMPTS      = 5;
const IP_WINDOW_MS         = 15 * 60 * 1000;   // 15 minutes
const IP_LOCKOUT_MS        = 15 * 60 * 1000;   // 15 minutes

const EMAIL_MAX_ATTEMPTS   = 8;
const EMAIL_WINDOW_MS      = 60 * 60 * 1000;   // 1 hour
const EMAIL_LOCKOUT_MS     = 60 * 60 * 1000;   // 1 hour

/** Generic error sent for any authentication/validation failure.
 *  Identical wording prevents user-enumeration via differing messages. */
const GENERIC_FAIL_MSG = 'Invalid or expired verification code.';

// ── Lazy singletons ───────────────────────────────────────────────────────────

let _supabase = null;
let _sql      = null;

function getSupabase() {
  if (!_supabase) {
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
      throw new Error('Supabase env vars not set');
    }
    _supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_ROLE_KEY,
      { auth: { persistSession: false } }
    );
  }
  return _supabase;
}

function getSql() {
  if (!_sql) {
    if (!process.env.NEON_DATABASE_URL) {
      throw new Error('NEON_DATABASE_URL env var not set');
    }
    _sql = neon(process.env.NEON_DATABASE_URL);
  }
  return _sql;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Constant-time string comparison to prevent timing attacks.
 * Returns true only when both strings are equal.
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Still run timingSafeEqual on equal-length dummy buffers
    // to avoid leaking length information via timing.
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Strips everything except digits, then trims to exactly 4 characters.
 * Returns null if the result is not exactly 4 digits.
 */
function sanitizeToken(raw) {
  if (typeof raw !== 'string') return null;
  const digits = raw.replace(/\D/g, '').slice(0, 4);
  return digits.length === 4 ? digits : null;
}

/**
 * Minimal email sanitizer — strips control characters and enforces format.
 * Full validation happens via regex; this just makes it safe to store/log.
 */
function sanitizeEmail(raw) {
  if (typeof raw !== 'string') return '';
  return raw
    .trim()
    .toLowerCase()
    .replace(/[\x00-\x1F\x7F<>'"]/g, '')
    .slice(0, 254);
}

/** Coarse email format check (same regex as signup.js). */
function isValidEmailFormat(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

/**
 * Extracts the real client IP, handling common reverse-proxy headers.
 * Falls back to socket address so it always returns a non-empty string.
 */
function extractIp(req) {
  const cfIp    = req.headers['cf-connecting-ip'];
  const fwd     = req.headers['x-forwarded-for'];
  const realIp  = req.headers['x-real-ip'];
  const socket  = req.socket?.remoteAddress || '0.0.0.0';

  if (cfIp)  return cfIp.trim().split(',')[0].trim();
  if (fwd)   return fwd.trim().split(',')[0].trim();
  if (realIp) return realIp.trim();
  return socket;
}

// ── Rate-limit logic (NeonDB) ─────────────────────────────────────────────────

/**
 * Checks and increments a rate-limit bucket for a given (keyType, keyValue).
 *
 * Algorithm:
 *  1. UPSERT the row — on conflict increment attempts, keep window_start.
 *  2. If an active lockout exists, return { limited: true, retryAfter }.
 *  3. If the window has expired, reset the counter to 1 and clear any lockout.
 *  4. If attempts exceed the limit AFTER incrementing, set locked_until.
 *
 * Returns: { limited: boolean, retryAfter?: number (seconds) }
 */
async function checkRateLimit(keyType, keyValue, maxAttempts, windowMs, lockoutMs) {
  const sql        = getSql();
  const now        = new Date();
  const windowStart = new Date(now.getTime() - windowMs);

  // Fetch current record
  const rows = await sql`
    SELECT attempts, window_start, locked_until
    FROM   verify_rate_limit
    WHERE  key_type  = ${keyType}
    AND    key_value = ${keyValue}
    LIMIT  1
  `;

  const record = rows[0] || null;

  // ── Case 1: Active lockout ──────────────────────────────────────────────────
  if (record?.locked_until) {
    const lockedUntil = new Date(record.locked_until);
    if (lockedUntil > now) {
      const retryAfter = Math.ceil((lockedUntil - now) / 1000);
      return { limited: true, retryAfter };
    }
    // Lockout expired — fall through to reset logic below
  }

  // ── Case 2: Window expired or no record — reset / insert ───────────────────
  if (!record || new Date(record.window_start) < windowStart) {
    await sql`
      INSERT INTO verify_rate_limit (key_type, key_value, attempts, window_start, locked_until)
      VALUES (${keyType}, ${keyValue}, 1, ${now.toISOString()}, NULL)
      ON CONFLICT (key_type, key_value) DO UPDATE
        SET attempts     = 1,
            window_start = ${now.toISOString()},
            locked_until = NULL
    `;
    return { limited: false };
  }

  // ── Case 3: Inside window — increment ──────────────────────────────────────
  const newAttempts = (record.attempts || 0) + 1;

  if (newAttempts >= maxAttempts) {
    // Exceeded — lock the bucket
    const lockedUntil = new Date(now.getTime() + lockoutMs).toISOString();
    await sql`
      UPDATE verify_rate_limit
      SET    attempts     = ${newAttempts},
             locked_until = ${lockedUntil}
      WHERE  key_type  = ${keyType}
      AND    key_value = ${keyValue}
    `;
    const retryAfter = Math.ceil(lockoutMs / 1000);
    return { limited: true, retryAfter };
  }

  // Still within limits
  await sql`
    UPDATE verify_rate_limit
    SET    attempts = ${newAttempts}
    WHERE  key_type  = ${keyType}
    AND    key_value = ${keyValue}
  `;
  return { limited: false };
}

/**
 * Clears the rate-limit buckets for an IP and email on successful verification.
 * Best-effort — failure here does not affect the response.
 */
async function clearRateLimits(ip, email) {
  try {
    const sql = getSql();
    await sql`
      DELETE FROM verify_rate_limit
      WHERE (key_type = 'ip'    AND key_value = ${ip})
         OR (key_type = 'email' AND key_value = ${email})
    `;
  } catch (err) {
    console.error('[verify] Failed to clear rate limits:', err.message);
  }
}

// ── Security headers helper ───────────────────────────────────────────────────

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'DENY');
  res.setHeader('X-XSS-Protection',        '1; mode=block');
  res.setHeader('Referrer-Policy',         'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control',           'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma',                  'no-cache');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
}

// ── Main handler ──────────────────────────────────────────────────────────────

module.exports = async function handler(req, res) {

  // ── CORS ────────────────────────────────────────────────────────────────────
  const allowedOrigin = process.env.ALLOWED_ORIGIN || '';
  const requestOrigin = req.headers['origin'] || '';

  // Preflight
  if (req.method === 'OPTIONS') {
    if (allowedOrigin && requestOrigin === allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin',  allowedOrigin);
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Max-Age',       '600');
    }
    return res.status(204).end();
  }

  // Only allow POST
  if (req.method !== 'POST') {
    setSecurityHeaders(res);
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  // Enforce same-origin (or configured origin) for non-browser clients
  if (allowedOrigin && requestOrigin && requestOrigin !== allowedOrigin) {
    setSecurityHeaders(res);
    return res.status(403).json({ error: 'Forbidden.' });
  }

  if (allowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  }

  setSecurityHeaders(res);

  // ── Content-Type guard ──────────────────────────────────────────────────────
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return res.status(415).json({ error: 'Unsupported Media Type.' });
  }

  // ── Extract & validate inputs ───────────────────────────────────────────────
  const { email: rawEmail, code: rawCode } = req.body || {};

  if (!rawEmail || !rawCode) {
    return res.status(400).json({ error: 'Email and verification code are required.' });
  }

  const email = sanitizeEmail(rawEmail);
  const code  = sanitizeToken(rawCode);

  if (!isValidEmailFormat(email)) {
    return res.status(400).json({ error: 'Invalid email address format.' });
  }

  if (code === null) {
    // Don't reveal expected format details
    return res.status(400).json({ error: GENERIC_FAIL_MSG });
  }

  const ip = extractIp(req);

  // ── Rate limiting — check BOTH IP and email ─────────────────────────────────
  try {
    const [ipLimit, emailLimit] = await Promise.all([
      checkRateLimit('ip',    ip,    IP_MAX_ATTEMPTS,    IP_WINDOW_MS,    IP_LOCKOUT_MS),
      checkRateLimit('email', email, EMAIL_MAX_ATTEMPTS, EMAIL_WINDOW_MS, EMAIL_LOCKOUT_MS),
    ]);

    if (ipLimit.limited) {
      res.setHeader('Retry-After', String(ipLimit.retryAfter));
      return res.status(429).json({
        error:      'Too many attempts from your network. Please try again later.',
        retryAfter: ipLimit.retryAfter,
      });
    }

    if (emailLimit.limited) {
      res.setHeader('Retry-After', String(emailLimit.retryAfter));
      return res.status(429).json({
        error:      'Too many verification attempts for this account. Please try again later.',
        retryAfter: emailLimit.retryAfter,
      });
    }
  } catch (err) {
    // Rate-limit DB failure — fail open with a log (safer than allowing unlimited attempts)
    console.error('[verify] Rate-limit DB error:', err.message);
    return res.status(503).json({ error: 'Service temporarily unavailable. Please try again.' });
  }

  // ── Token lookup ─────────────────────────────────────────────────────────────
  try {
    const supabase = getSupabase();

    // Fetch the user to get their ID (avoids leaking existence via token lookup)
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('id, is_verified')
      .eq('email', email)
      .maybeSingle();

    if (userErr) {
      console.error('[verify] User lookup error:', userErr.message);
      return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
    }

    // Use identical error for "user not found" and "wrong code" to prevent enumeration
    if (!user) {
      return res.status(400).json({ error: GENERIC_FAIL_MSG });
    }

    // Already verified — tell them but don't reveal the token state
    if (user.is_verified) {
      return res.status(200).json({ message: 'Your account is already verified. You can sign in.' });
    }

    // Fetch the most recent unused, non-expired token for this user
    const { data: tokenRow, error: tokenErr } = await supabase
      .from('verification_tokens')
      .select('id, token, expires_at')
      .eq('user_id', user.id)
      .eq('used', false)
      .gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (tokenErr) {
      console.error('[verify] Token lookup error:', tokenErr.message);
      return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
    }

    if (!tokenRow) {
      return res.status(400).json({ error: GENERIC_FAIL_MSG });
    }

    // ── Constant-time token comparison ─────────────────────────────────────────
    if (!safeEqual(tokenRow.token, code)) {
      return res.status(400).json({ error: GENERIC_FAIL_MSG });
    }

    // ── Token matched — mark as used and verify user (atomic-ish) ──────────────

    const { error: markTokenErr } = await supabase
      .from('verification_tokens')
      .update({ used: true })
      .eq('id', tokenRow.id);

    if (markTokenErr) {
      console.error('[verify] Token mark-used error:', markTokenErr.message);
      return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
    }

    const { error: verifyUserErr } = await supabase
      .from('users')
      .update({ is_verified: true, verified_at: new Date().toISOString() })
      .eq('id', user.id);

    if (verifyUserErr) {
      // Roll back token mark if user update fails to keep state consistent
      await supabase
        .from('verification_tokens')
        .update({ used: false })
        .eq('id', tokenRow.id);
      console.error('[verify] User verify error:', verifyUserErr.message);
      return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
    }

    // ── Success — clear rate-limit buckets ──────────────────────────────────────
    await clearRateLimits(ip, email);

    // Invalidate all other unused tokens for this user (good hygiene)
    await supabase
      .from('verification_tokens')
      .update({ used: true })
      .eq('user_id', user.id)
      .eq('used', false);

    return res.status(200).json({
      message: 'Email verified successfully. Welcome to Volk Donations!',
    });

  } catch (err) {
    console.error('[verify] Unhandled error:', err.message, err.stack);
    return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
};
