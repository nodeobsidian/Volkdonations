const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  try {
    const { userId, token } = req.body;

    // --- Input presence ---
    if (!userId || !token) {
      return res.status(400).json({ error: 'User ID and verification code are required.' });
    }

    // --- Validate token is exactly 4 digits ---
    if (!/^\d{4}$/.test(String(token))) {
      return res.status(400).json({ error: 'Invalid verification code format.' });
    }

    // --- Validate userId is a UUID ---
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userId)) {
      return res.status(400).json({ error: 'Invalid request.' });
    }

    // --- Lookup token (no rate limiting — intentional) ---
    const { data: tokenRecord, error: tokenError } = await supabase
      .from('verification_tokens')
      .select('id, token, expires_at, used, user_id')
      .eq('user_id', userId)
      .eq('token', token)
      .eq('used', false)
      .maybeSingle();

    if (tokenError) {
      console.error('Token lookup error:', tokenError);
      return res.status(500).json({ error: 'Verification failed. Please try again.' });
    }

    if (!tokenRecord) {
      return res.status(400).json({ error: 'Invalid verification code.' });
    }

    // --- Check expiry ---
    if (new Date() > new Date(tokenRecord.expires_at)) {
      return res.status(400).json({ error: 'Verification code has expired. Please request a new one.' });
    }

    // --- Mark token used ---
    await supabase
      .from('verification_tokens')
      .update({ used: true })
      .eq('id', tokenRecord.id);

    // --- Mark user verified ---
    const { error: updateError } = await supabase
      .from('users')
      .update({ is_verified: true })
      .eq('id', userId);

    if (updateError) {
      console.error('User verify update error:', updateError);
      return res.status(500).json({ error: 'Failed to verify account. Please try again.' });
    }

    return res.status(200).json({ message: 'Email verified successfully. You can now log in.' });
  } catch (err) {
    console.error('Verify error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
};
