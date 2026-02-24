const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
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

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase().trim());
}

function validatePassword(password) {
  // Min 8 chars, at least one uppercase, one lowercase, one digit, one special char
  const re = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
  return re.test(password);
}

function generateToken() {
  // 4-digit numeric token — intentionally small space (10,000 combos) for brute-force exercise
  return String(Math.floor(1000 + Math.random() * 9000));
}

function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.trim().replace(/[\x00-\x1F\x7F]/g, '');
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  try {
    const { name, email, password, captchaToken } = req.body;

    // --- Input presence check ---
    if (!name || !email || !password || !captchaToken) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    // --- Sanitize ---
    const cleanName = sanitizeString(name);
    const cleanEmail = sanitizeString(email).toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 100) {
      return res.status(400).json({ error: 'Name must be between 2 and 100 characters.' });
    }

    // --- Email validation ---
    if (!validateEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }

    // --- Password validation ---
    if (!validatePassword(password)) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character.',
      });
    }

    // --- hCaptcha verification ---
    const captchaVerify = await fetch('https://hcaptcha.com/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${encodeURIComponent(process.env.HCAPTCHA_SECRET)}&response=${encodeURIComponent(captchaToken)}`,
    });
    const captchaResult = await captchaVerify.json();
    if (!captchaResult.success) {
      return res.status(400).json({ error: 'CAPTCHA verification failed. Please try again.' });
    }

    // --- Check if email already exists ---
    const { data: existingUser } = await supabase
      .from('users')
      .select('id, is_verified')
      .eq('email', cleanEmail)
      .maybeSingle();

    if (existingUser) {
      if (!existingUser.is_verified) {
        // Re-send a new token if account exists but unverified
        const token = generateToken();
        const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString();

        // Invalidate old tokens
        await supabase
          .from('verification_tokens')
          .update({ used: true })
          .eq('user_id', existingUser.id)
          .eq('used', false);

        await supabase.from('verification_tokens').insert({
          user_id: existingUser.id,
          token,
          expires_at: expiresAt,
        });

        await sendVerificationEmail(cleanEmail, cleanName, token);

        return res.status(200).json({
          message: 'Account pending verification. A new code has been sent to your email.',
          userId: existingUser.id,
        });
      }
      // Vague message — don't leak whether email exists
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    // --- Hash password ---
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // --- Create user ---
    const { data: newUser, error: insertError } = await supabase
      .from('users')
      .insert({ name: cleanName, email: cleanEmail, password_hash: passwordHash })
      .select('id')
      .single();

    if (insertError || !newUser) {
      console.error('User insert error:', insertError);
      return res.status(500).json({ error: 'Failed to create account. Please try again.' });
    }

    // --- Generate & store 4-digit token ---
    const token = generateToken();
    const expiresAt = new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString();

    const { error: tokenError } = await supabase.from('verification_tokens').insert({
      user_id: newUser.id,
      token,
      expires_at: expiresAt,
    });

    if (tokenError) {
      console.error('Token insert error:', tokenError);
      return res.status(500).json({ error: 'Failed to generate verification token.' });
    }

    // --- Send email ---
    await sendVerificationEmail(cleanEmail, cleanName, token);

    return res.status(201).json({
      message: 'Account created. Please check your email for your verification code.',
      userId: newUser.id,
    });
  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
};

async function sendVerificationEmail(email, name, token) {
  const mailOptions = {
    from: `"Volk Donations" <${process.env.BREVO_FROM_EMAIL}>`,
    to: email,
    subject: 'Verify your Volk Donations account',
    html: `
      <!DOCTYPE html>
      <html>
      <head><meta charset="UTF-8"></head>
      <body style="margin:0;padding:0;background:#f4f7fb;font-family:'Segoe UI',Arial,sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f7fb;padding:40px 0;">
          <tr><td align="center">
            <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">
              <tr>
                <td style="background:linear-gradient(135deg,#1e3a5f,#00a86b);padding:40px;text-align:center;">
                  <h1 style="color:#fff;margin:0;font-size:26px;font-weight:700;">Volk Donations</h1>
                  <p style="color:rgba(255,255,255,0.85);margin:6px 0 0;font-size:13px;letter-spacing:0.5px;">A better life for everyone</p>
                </td>
              </tr>
              <tr>
                <td style="padding:50px 50px 40px;">
                  <p style="color:#2c3e50;font-size:16px;margin:0 0 10px;">Hello, <strong>${name}</strong></p>
                  <p style="color:#5a6c7d;font-size:15px;line-height:1.7;margin:0 0 30px;">
                    Thank you for creating an account with Volk Donations. To complete your registration, please enter the verification code below:
                  </p>
                  <div style="text-align:center;margin:0 0 30px;">
                    <div style="display:inline-block;background:#f4f7fb;border:2px dashed #00a86b;border-radius:12px;padding:24px 48px;">
                      <span style="font-size:48px;font-weight:700;color:#1e3a5f;letter-spacing:12px;">${token}</span>
                    </div>
                  </div>
                  <p style="color:#5a6c7d;font-size:14px;line-height:1.7;margin:0 0 10px;">
                    This code expires in <strong>4 hours</strong>. If you did not create an account, you can safely ignore this email.
                  </p>
                </td>
              </tr>
              <tr>
                <td style="background:#f4f7fb;padding:25px 50px;text-align:center;">
                  <p style="color:#8a9ab0;font-size:12px;margin:0;">
                    © 2026 Volk Donations · 501(c)(3) Nonprofit · EIN: 45-1234567
                  </p>
                </td>
              </tr>
            </table>
          </td></tr>
        </table>
      </body>
      </html>
    `,
  };

  await transporter.sendMail(mailOptions);
}
