const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.BREVO_SMTP_USER,
    pass: process.env.BREVO_SMTP_KEY,
  },
});

function generateToken() {
  return String(Math.floor(1000 + Math.random() * 9000));
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required.' });
    }

    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(userId)) {
      return res.status(400).json({ error: 'Invalid request.' });
    }

    // Fetch user
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('id, name, email, is_verified')
      .eq('id', userId)
      .maybeSingle();

    if (userError || !user) {
      return res.status(404).json({ error: 'Account not found.' });
    }

    if (user.is_verified) {
      return res.status(400).json({ error: 'Account is already verified.' });
    }

    // Invalidate existing tokens
    await supabase
      .from('verification_tokens')
      .update({ used: true })
      .eq('user_id', userId)
      .eq('used', false);

    // Generate new token
    const token = generateToken();
    const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString();

    await supabase.from('verification_tokens').insert({
      user_id: userId,
      token,
      expires_at: expiresAt,
    });

    // Send email
    await transporter.sendMail({
      from: `"Volk Donations" <${process.env.BREVO_FROM_EMAIL}>`,
      to: user.email,
      subject: 'Your new Volk Donations verification code',
      html: `
        <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:500px;margin:auto;padding:40px 20px;">
          <h2 style="color:#1e3a5f;">New Verification Code</h2>
          <p style="color:#5a6c7d;">Hi ${user.name}, here is your new verification code:</p>
          <div style="text-align:center;background:#f4f7fb;border:2px dashed #00a86b;border-radius:12px;padding:24px;margin:24px 0;">
            <span style="font-size:48px;font-weight:700;color:#1e3a5f;letter-spacing:12px;">${token}</span>
          </div>
          <p style="color:#8a9ab0;font-size:13px;">Expires in 4 hours. If you didn't request this, ignore this email.</p>
        </div>
      `,
    });

    return res.status(200).json({ message: 'A new verification code has been sent to your email.' });
  } catch (err) {
    console.error('Resend token error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
};
