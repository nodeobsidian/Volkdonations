'use strict';

const { createClient } = require('@supabase/supabase-js');
const crypto           = require('crypto');

const COOKIE_NAME = 'vdk_session';

// ── LAB CONTROL TOGGLE ────────────────────────────────────────────────────────
const CSRF_VULN = true; // ← comment out after demo to disable vulnerable GET

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

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'DENY');
  res.setHeader('Cache-Control',           'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma',                  'no-cache');
  res.setHeader('Content-Security-Policy', "default-src 'none'");
}

function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.trim().replace(/[\x00-\x1F\x7F<>]/g, '');
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).toLowerCase().trim());
}

// ── Shared session resolver ───────────────────────────────────────────────────
async function resolveSession(req, res) {
  const cookies     = parseCookies(req.headers['cookie'] || '');
  const signedToken = cookies[COOKIE_NAME] || '';

  if (!signedToken) {
    res.status(401).json({ error: 'Not authenticated.' });
    return null;
  }

  const sessionId = verifySignedToken(signedToken);
  if (!sessionId) {
    res.setHeader('Set-Cookie',
      `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`
    );
    res.status(401).json({ error: 'Invalid session.' });
    return null;
  }

  const supabase = getSupabase();

  const { data: session, error: sessionErr } = await supabase
    .from('sessions')
    .select('user_id, expires_at')
    .eq('session_id', sessionId)
    .maybeSingle();

  if (sessionErr) {
    console.error('[api/me] Session lookup error:', sessionErr.message);
    res.status(500).json({ error: 'An unexpected error occurred.' });
    return null;
  }

  if (!session) {
    res.setHeader('Set-Cookie',
      `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`
    );
    res.status(401).json({ error: 'Session not found.' });
    return null;
  }

  if (new Date(session.expires_at) < new Date()) {
    await supabase.from('sessions').delete().eq('session_id', sessionId);
    res.setHeader('Set-Cookie',
      `${COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`
    );
    res.status(401).json({ error: 'Session expired. Please sign in again.' });
    return null;
  }

  return { supabase, userId: session.user_id };
}

// ── Main handler ──────────────────────────────────────────────────────────────

module.exports = async function handler(req, res) {

  const allowedOrigin = process.env.ALLOWED_ORIGIN || '';
  const requestOrigin = req.headers['origin'] || '';

  if (req.method === 'OPTIONS') {
    if (allowedOrigin && requestOrigin === allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin',      allowedOrigin);
      res.setHeader('Access-Control-Allow-Methods',     'GET, PATCH, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers',     'Content-Type');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Max-Age',           '600');
    }
    return res.status(204).end();
  }

  if (req.method !== 'GET' && req.method !== 'PATCH') {
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

  try {

    // ── GET /api/me ─────────────────────────────────────────────────────────
    if (req.method === 'GET') {

      // ── CSRF LAB: vulnerable GET profile update ──────────────────────────
      // SameSite=Lax allows cookies on top-level GET navigations.
      // An attacker page navigates the victim's browser here with
      // ?change=1&email=...&name=... and the session cookie is sent
      // automatically — no user interaction required beyond visiting
      // the attacker page. Toggle CSRF_VULN = false after demo.
      if (CSRF_VULN && req.query.change === '1') {
        const auth = await resolveSession(req, res);
        if (!auth) return;

        const { supabase, userId } = auth;
        const updateObj = {};

        if (req.query.email) {
          const cleanEmail = sanitizeString(req.query.email).toLowerCase();
          if (validateEmail(cleanEmail)) updateObj.email = cleanEmail;
        }

        if (req.query.name) {
          const cleanName = sanitizeString(req.query.name);
          if (cleanName.length >= 2 && cleanName.length <= 100) {
            updateObj.name = cleanName;
          }
        }

        if (Object.keys(updateObj).length > 0) {
          await supabase.from('users').update(updateObj).eq('id', userId);
        }

        // Redirect back to attacker page — attacker controls this via
        // return_to param, server never added this, keeping it realistic
        const returnTo = req.query.return_to || '';
        if (returnTo && returnTo.startsWith('https://volkdonations.website')) {
          return res.redirect(302, returnTo);
        }

        // Fallback if no return_to
        return res.status(200).json({ message: 'ok' });
      }

      // ── Normal GET /api/me — session check and profile return ────────────
      const auth = await resolveSession(req, res);
      if (!auth) return;

      const { supabase, userId } = auth;

      const { data: user, error: userErr } = await supabase
        .from('users')
        .select('id, name, email, is_active')
        .eq('id', userId)
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

      return res.status(200).json({
        userId: user.id,
        name:   user.name,
        email:  user.email,
      });
    }

    // ── PATCH /api/me ───────────────────────────────────────────────────────
    if (req.method === 'PATCH') {
      const auth = await resolveSession(req, res);
      if (!auth) return;

      const { supabase, userId } = auth;

      const { firstName, lastName, email } = req.body || {};

      if (!firstName && !lastName && !email) {
        return res.status(400).json({ error: 'No update fields provided.' });
      }

      const updateObj = {};

      if (firstName || lastName) {
        const cleanFirst = sanitizeString(firstName || '');
        const cleanLast  = sanitizeString(lastName  || '');

        if (firstName && cleanFirst.length < 1) {
          return res.status(400).json({ error: 'Invalid first name.' });
        }
        if (lastName && cleanLast.length < 1) {
          return res.status(400).json({ error: 'Invalid last name.' });
        }

        if (!firstName || !lastName) {
          const { data: existing } = await supabase
            .from('users')
            .select('name')
            .eq('id', userId)
            .maybeSingle();

          const parts     = (existing?.name || '').trim().split(/\s+/);
          const existingF = parts[0] || '';
          const existingL = parts.slice(1).join(' ') || '';

          updateObj.name = `${cleanFirst || existingF} ${cleanLast || existingL}`.trim();
        } else {
          updateObj.name = `${cleanFirst} ${cleanLast}`.trim();
        }

        if (updateObj.name.length < 2 || updateObj.name.length > 100) {
          return res.status(400).json({ error: 'Full name must be between 2 and 100 characters.' });
        }
      }

      if (email) {
        const cleanEmail = sanitizeString(email).toLowerCase();
        if (!validateEmail(cleanEmail)) {
          return res.status(400).json({ error: 'Invalid email address.' });
        }

        const { data: existing } = await supabase
          .from('users')
          .select('id')
          .eq('email', cleanEmail)
          .maybeSingle();

        if (existing && existing.id !== userId) {
          return res.status(409).json({ error: 'That email address is already in use.' });
        }

        updateObj.email = cleanEmail;
      }

      const { error: updateErr } = await supabase
        .from('users')
        .update(updateObj)
        .eq('id', userId);

      if (updateErr) {
        console.error('[api/me] Profile update error:', updateErr.message);
        return res.status(500).json({ error: 'Failed to update profile. Please try again.' });
      }

      return res.status(200).json({
        message: 'Profile updated successfully.',
        updated: updateObj,
      });
    }

  } catch (err) {
    console.error('[api/me] Unhandled error:', err.message);
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
};
