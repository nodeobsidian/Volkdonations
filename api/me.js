'use strict';

/**
 * GET /api/me
 * ─────────────────────────────────────────────────────────────────
 * Verifies the vdk_session cookie, confirms the session exists and
 * is not expired in Supabase, and returns the authenticated user's
 * public profile { name, email, userId }.
 *
 * Used by the dashboard to:
 *  1. Confirm the visitor is authenticated (401 → redirect /auth/login)
 *  2. Hydrate the dashboard with the real user's name and email
 *
 * Required env vars:
 *   SUPABASE_URL               – Supabase project URL
 *   SUPABASE_SERVICE_ROLE_KEY  – Supabase service-role key
 *   SESSION_HMAC_SECRET        – 32+ char secret used to sign session cookies
 *   ALLOWED_ORIGIN             – Exact frontend origin for CORS
 */

const { createClient } = require('@supabase/supabase-js');
const crypto           = require('crypto');

const COOKIE_NAME = 'vdk_session';

// ── Lazy Supabase singleton ───────────────────────────────────────────────────

let _supabase = null;
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

// ── Cookie parser ─────────────────────────────────────────────────────────────

function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx < 0) return;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    cookies[key] = val;
  });
  return cookies;
}

// ── HMAC token verification ───────────────────────────────────────────────────

function verifySignedToken(signedToken) {
  const secret = process.env.SESSION_HMAC_SECRET;
  if (!secret || secret.length < 32) return null;
  if (!signedToken || typeof signedToken !== 'string') return null;

  const dotIdx = signedToken.lastIndexOf('.');
  if (dotIdx === -1) return null;

  const sessionId = signedToken.slice(0, dotIdx);
  const sig       = signedToken.slice(dotIdx + 1);
  if (!sessionId || !sig) return null;

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(sessionId)
    .digest('hex');

  try {
    const sigBuf      = Buffer.from(sig,         'hex');
    const expectedBuf = Buffer.from(expectedSig, 'hex');
    if (sigBuf.length !== expectedBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;
  } catch {
    return null;
  }

  return sessionId;
}

// ── Security headers ──────────────────────────────────────────────────────────

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'DENY');
  res.setHeader('Cache-Control',           'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma',                  'no-cache');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
}

// ── Main handler ──────────────────────────────────────────────────────────────

module.exports = async function handler(req, res) {

  // ── CORS ─────────────────────────────────────────────────────────────────────
  const allowedOrigin = process.env.ALLOWED_ORIGIN || '';
  const requestOrigin = req.headers['origin'] || '';

  if (req.method === 'OPTIONS') {
    if (allowedOrigin && requestOrigin === allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin',      allowedOrigin);
      res.setHeader('Access-Control-Allow-Methods',     'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Max-Age',           '600');
    }
    return res.status(204).end();
  }

  if (req.method !== 'GET') {
    setSecurityHeaders(res);
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  if (allowedOrigin && requestOrigin && requestOrigin !== allowedOrigin) {
    setSecurityHeaders(res);
    return res.status(403).json({ error: 'Forbidden.' });
  }

  if (allowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin',      allowedOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  setSecurityHeaders(res);

  // ── Extract cookie ────────────────────────────────────────────────────────────
  const cookies     = parseCookies(req.headers['cookie'] || '');
  const signedToken = cookies[COOKIE_NAME] || '';

  if (!signedToken) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  // ── Verify HMAC signature ─────────────────────────────────────────────────────
  const sessionId = verifySignedToken(signedToken);
  if (!sessionId) {
    // Tampered or malformed cookie — clear it
    res.setHeader('Set-Cookie',
      `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`
    );
    return res.status(401).json({ error: 'Invalid session.' });
  }

  // ── Look up session in Supabase ───────────────────────────────────────────────
  try {
    const supabase = getSupabase();

    const { data: session, error: sessionErr } = await supabase
      .from('sessions')
      .select('user_id, expires_at')
      .eq('session_id', sessionId)
      .maybeSingle();

    if (sessionErr) {
      console.error('[api/me] Session lookup error:', sessionErr.message);
      return res.status(500).json({ error: 'An unexpected error occurred.' });
    }

    if (!session) {
      // Session not found — clear stale cookie
      res.setHeader('Set-Cookie',
        `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`
      );
      return res.status(401).json({ error: 'Session not found.' });
    }

    // ── Expiry check ──────────────────────────────────────────────────────────
    if (new Date(session.expires_at) < new Date()) {
      // Expired — clean up and clear cookie
      await supabase.from('sessions').delete().eq('session_id', sessionId);
      res.setHeader('Set-Cookie',
        `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`
      );
      return res.status(401).json({ error: 'Session expired. Please sign in again.' });
    }

    // ── Fetch user profile ────────────────────────────────────────────────────
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('id, name, email, is_active')
      .eq('id', session.user_id)
      .maybeSingle();

    if (userErr) {
      console.error('[api/me] User lookup error:', userErr.message);
      return res.status(500).json({ error: 'An unexpected error occurred.' });
    }

    if (!user) {
      return res.status(401).json({ error: 'User not found.' });
    }

    if (user.is_active === false) {
      return res.status(403).json({
        error: 'Account suspended.',
        code:  'ACCOUNT_SUSPENDED',
      });
    }

    // ── Return minimal, safe profile ──────────────────────────────────────────
    return res.status(200).json({
      userId: user.id,
      name:   user.name,
      email:  user.email,
    });

  } catch (err) {
    console.error('[api/me] Unhandled error:', err.message);
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
};
