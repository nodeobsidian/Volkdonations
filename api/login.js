const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
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
const RATE_LIMIT_MAX       = 5;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const SESSION_TTL_MS       = 7 * 24 * 60 * 60 * 1000;
const HMAC_SECRET          = process.env.SESSION_HMAC_SECRET;
const COOKIE_NAME          = 'vdk_session';

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/**
 * Generate a cryptographically random session ID (32 bytes = 64 hex chars)
 * then sign it with HMAC-SHA256 using SESSION_HMAC_SECRET.
 * Cookie value format: <sessionId>.<hmacSignature>
 */
function generateSignedSessionToken() {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const sig = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(sessionId)
    .digest('hex');
  return { sessionId, signedToken: `${sessionId}.${sig}` };
}

/**
 * Verify the signed token from the cookie.
 * Returns sessionId string if valid, null if tampered/invalid.
 */
function verifySignedToken(signedToken) {
  if (!signedToken || typeof signedToken !== 'string') return null;
  const parts = signedToken.split('.');
  if (parts.length !== 2) return null;
  const [sessionId, sig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(sessionId)
    .digest('hex');
  const sigBuf      = Buffer.from(sig, 'hex');
  const expectedBuf = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
  return sessionId;
}

function buildCookieHeader(signedToken, expiresAt) {
  const expires = new Date(expiresAt).toUTCString();
  const parts = [
    `${COOKIE_NAME}=${signedToken}`,
    `Expires=${expires}`,
    'Path=/',
    'HttpOnly',             // ← intentionally off for demo // we can comment these out when we want to do a demo
    'SameSite=Strict',       //← intentionally removed for demo  // we can comment these out when we want to do a demo
  ];
  if (process.env.NODE_ENV === 'production') {
    parts.push('Secure');
  }
  return parts.join('; ');
}

function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.trim().replace(/[\x00-\x1F\x7F<>]/g, '');
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).toLowerCase().trim());
}

// ─────────────────────────────────────────────
// NeonDB rate limiting
// ─────────────────────────────────────────────
async function checkRateLimit(ip, email) {
  const sql = getNeon();
  const key = `login:${ip}:${email}`;
  const since = new Date(Date.now() - RATE_LIMIT_WINDOW_MS).toISOString();

  try {
    const rows = await sql`
      SELECT COUNT(*) AS count
      FROM signup_rate_limit
      WHERE key = ${key}
        AND attempted_at > ${since}
    `;
    const count = parseInt(rows[0]?.count ?? 0, 10);
    return { allowed: count < RATE_LIMIT_MAX, count };
  } catch (err) {
    console.error('Rate limit check error:', err);
    return { allowed: true, count: 0 };
  }
}

async function recordFailedAttempt(ip, email) {
  const sql = getNeon();
  const key = `login:${ip}:${email}`;

  try {
    await sql`
      INSERT INTO signup_rate_limit (key, attempted_at)
      VALUES (${key}, NOW())
    `;

    const cutoff = new Date(Date.now() - RATE_LIMIT_WINDOW_MS).toISOString();
    await sql`
      DELETE FROM signup_rate_limit
      WHERE attempted_at < ${cutoff}
    `;
  } catch (err) {
    console.error('Rate limit record error:', err);
  }
}

async function clearRateLimitOnSuccess(ip, email) {
  const sql = getNeon();
  const key = `login:${ip}:${email}`;
  try {
    await sql`DELETE FROM signup_rate_limit WHERE key = ${key}`;
  } catch (err) {
    console.error('Rate limit clear error:', err);
  }
}

// ─────────────────────────────────────────────
// Session management
// ─────────────────────────────────────────────
async function createSession(userId, sessionId, ip, userAgent, expiresAt) {
  const { error } = await supabase.from('sessions').insert({
    user_id:    userId,
    session_id: sessionId,
    ip_address: ip,
    user_agent: userAgent,
    expires_at: expiresAt,
  });
  return !error;
}

// ─────────────────────────────────────────────
// Main handler: POST /api/login
// ─────────────────────────────────────────────
module.exports = async function handler(req, res) {
  // ── Method guard ────────────────────────────
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  // ── Security headers ────────────────────────
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cache-Control', 'no-store');

  // ── HMAC secret guard ───────────────────────
  if (!HMAC_SECRET || HMAC_SECRET.length < 32) {
    console.error('SESSION_HMAC_SECRET is missing or too short (min 32 chars)');
    return res.status(500).json({ error: 'Server misconfiguration.' });
  }

  const ip        = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket?.remoteAddress || '0.0.0.0';
  const userAgent = req.headers['user-agent'] || '';

  try {
    const { email, password, captchaToken } = req.body || {};

    // ── Input presence ───────────────────────
    if (!email || !password || !captchaToken) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const cleanEmail = sanitizeString(email).toLowerCase();

    if (!validateEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }

    if (typeof password !== 'string' || password.length < 1 || password.length > 72) {
      return res.status(400).json({ error: 'Invalid password.' });
    }

    // ── Turnstile verification ───────────────
    const captchaVerify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${encodeURIComponent(process.env.TURNSTILE_SECRET)}&response=${encodeURIComponent(captchaToken)}`,
    });
    const captchaResult = await captchaVerify.json();
    if (!captchaResult.success) {
      return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' });
    }

    // ── Rate limit check ─────────────────────
    const { allowed } = await checkRateLimit(ip, cleanEmail);
    if (!allowed) {
      return res.status(429).json({
        error: `Too many failed login attempts. Please wait 15 minutes before trying again.`,
      });
    }

    // ── Fetch user ───────────────────────────
    const { data: user, error: fetchError } = await supabase
      .from('users')
      .select('id, email, password_hash, is_verified, is_active')
      .eq('email', cleanEmail)
      .maybeSingle();

    if (fetchError) {
      console.error('User fetch error:', fetchError);
      return res.status(500).json({ error: 'An unexpected error occurred.' });
    }

    // ── Timing-safe invalid credential handling ──
    const DUMMY_HASH = '$2b$12$C6UzMDM.H6dfI/f/IKcEeO6uJQ5Q9s7Rk6u1C5sKX0H1d5FJ7ZK6W';
    const hashToCompare = user ? user.password_hash : DUMMY_HASH;
    const passwordMatch = await bcrypt.compare(password, hashToCompare);

    if (!user || !passwordMatch) {
      if (user || (!user && passwordMatch === false)) {
        await recordFailedAttempt(ip, cleanEmail);
      }
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // ── Account state checks ─────────────────
    if (!user.is_verified) {
      return res.status(403).json({
        error: 'Please verify your email address before logging in.',
        code: 'EMAIL_NOT_VERIFIED',
      });
    }

    if (user.is_active === false) {
      return res.status(403).json({
        error: 'This account has been suspended. Please contact support.',
        code: 'ACCOUNT_SUSPENDED',
      });
    }

    // ── Generate signed session ──────────────
    const { sessionId, signedToken } = generateSignedSessionToken();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

    const sessionCreated = await createSession(user.id, sessionId, ip, userAgent, expiresAt);
    if (!sessionCreated) {
      return res.status(500).json({ error: 'Failed to create session. Please try again.' });
    }

    // ── Clear rate limit on success ──────────
    await clearRateLimitOnSuccess(ip, cleanEmail);

    // ── Set cookie + redirect ────────────────
    res.setHeader('Set-Cookie', buildCookieHeader(signedToken, expiresAt));
    res.setHeader('Location', '/users/dashboard');
    return res.status(302).end();

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
};
