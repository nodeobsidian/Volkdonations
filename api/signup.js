const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const transporter = nodemailer.createTransport({
  host: 'smtp-pulse.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.SENDPULSE_SMTP_USER,
    pass: process.env.SENDPULSE_SMTP_KEY,
  },
});

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase().trim());
}

function validatePassword(password) {
  const re = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
  return re.test(password);
}

function generateToken() {
  // 4-digit numeric token — intentionally small space (10,000 combos) for brute-force exercise
  return String(Math.floor(1000 + Math.random() * 9000));
}

function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str
    .trim()
    .replace(/[\x00-\x1F\x7F]/g, '')
    .replace(/[<>]/g, '');           // FIX: strip angle brackets to prevent HTML injection in email template
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

    // --- Cloudflare Turnstile verification (replaces hCaptcha) ---
    const captchaVerify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${encodeURIComponent(process.env.TURNSTILE_SECRET)}&response=${encodeURIComponent(captchaToken)}`,
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

        // FIX: userId removed — frontend doesn't need internal DB IDs
        return res.status(200).json({
          message: 'Account pending verification. A new code has been sent to your email.',
        });
      }
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

    // FIX: userId removed — frontend doesn't need internal DB IDs
    return res.status(201).json({
      message: 'Account created. Please check your email for your verification code.',
    });

  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
  }
};

async function sendVerificationEmail(email, name, token) {
  // Split token into individual digits for the boxed digit display
  const digits = token.split('');

  const mailOptions = {
    from: `"Volk Donations" <${process.env.SENDPULSE_FROM_EMAIL}>`,
    to: email,
    subject: 'Your Volk Donations Verification Code',
    html: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Verify Your Account</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f4f8;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f4f8;padding:48px 16px;">
    <tr>
      <td align="center">

        <!-- Outer card -->
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 8px 40px rgba(0,0,0,0.10);">

          <!-- Header banner -->
          <tr>
            <td style="background:linear-gradient(135deg,#1e3a5f 0%,#00a86b 100%);padding:44px 40px 38px;text-align:center;">
              <table cellpadding="0" cellspacing="0" align="center">
                <tr>
                  <td>
                    <!-- Logo mark: circle with V -->
                    <div style="display:inline-block;width:56px;height:56px;border-radius:50%;background:rgba(255,255,255,0.15);border:2px solid rgba(255,255,255,0.4);text-align:center;line-height:56px;font-size:26px;font-weight:800;color:#ffffff;margin-bottom:16px;">V</div>
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:12px;">
                    <p style="margin:0;font-size:26px;font-weight:800;color:#ffffff;letter-spacing:0.5px;">Volk Donations</p>
                    <p style="margin:6px 0 0;font-size:13px;color:rgba(255,255,255,0.80);letter-spacing:1px;text-transform:uppercase;">A better life for everyone</p>
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

              <!-- Greeting -->
              <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#1e3a5f;">Hello, ${name} 👋</p>
              <p style="margin:0 0 32px;font-size:15px;color:#5a6c7d;line-height:1.75;">
                Welcome to Volk Donations! To complete your account registration and start making a difference, please verify your email address using the code below.
              </p>

              <!-- Code box -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:32px;">
                <tr>
                  <td align="center">
                    <table cellpadding="0" cellspacing="0" style="background:#f0f4f8;border:2px solid #00a86b;border-radius:14px;padding:28px 40px;">
                      <tr>
                        <td align="center">
                          <p style="margin:0 0 14px;font-size:11px;font-weight:700;color:#00a86b;letter-spacing:2.5px;text-transform:uppercase;">Verification Code</p>
                          <!-- Individual digit boxes -->
                          <table cellpadding="0" cellspacing="0">
                            <tr>
                              ${digits.map(d => `
                              <td style="padding:0 5px;">
                                <div style="width:52px;height:64px;background:#ffffff;border:2px solid #1e3a5f;border-radius:10px;text-align:center;line-height:64px;font-size:36px;font-weight:800;color:#1e3a5f;display:inline-block;">${d}</div>
                              </td>`).join('')}
                            </tr>
                          </table>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Expiry notice -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:32px;">
                <tr>
                  <td style="background:#fff8e1;border-left:4px solid #f59e0b;border-radius:0 8px 8px 0;padding:14px 18px;">
                    <p style="margin:0;font-size:13px;color:#78600a;">
                      ⏱ This code expires in <strong>4 hours</strong>. If you didn't create an account, you can safely ignore this email.
                    </p>
                  </td>
                </tr>
              </table>

              <!-- Divider -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td style="border-top:1px solid #e8edf2;"></td>
                </tr>
              </table>

              <!-- Mission blurb -->
              <table cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td style="background:linear-gradient(135deg,#1e3a5f,#00a86b);border-radius:12px;padding:24px 28px;">
                    <p style="margin:0 0 6px;font-size:14px;font-weight:700;color:#ffffff;">Why your account matters</p>
                    <p style="margin:0;font-size:13px;color:rgba(255,255,255,0.85);line-height:1.7;">
                      With a Volk Donations account you can track your contributions, manage recurring donations, and see the real-world impact your generosity creates for orphaned children across Africa, Asia, and Latin America.
                    </p>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#1e3a5f;padding:30px 48px;text-align:center;">
              <!-- Social icons (text fallback) -->
              <p style="margin:0 0 16px;">
                <a href="#" style="display:inline-block;margin:0 6px;color:#ffffff;font-size:12px;text-decoration:none;opacity:0.75;">Facebook</a>
                <span style="color:rgba(255,255,255,0.3);">·</span>
                <a href="#" style="display:inline-block;margin:0 6px;color:#ffffff;font-size:12px;text-decoration:none;opacity:0.75;">Twitter</a>
                <span style="color:rgba(255,255,255,0.3);">·</span>
                <a href="#" style="display:inline-block;margin:0 6px;color:#ffffff;font-size:12px;text-decoration:none;opacity:0.75;">LinkedIn</a>
              </p>
              <p style="margin:0 0 6px;font-size:12px;color:rgba(255,255,255,0.55);">© 2026 Volk Donations · All rights reserved</p>
              <p style="margin:0;font-size:11px;color:rgba(255,255,255,0.40);">
                Registered 501(c)(3) Nonprofit · EIN: 45-1234567<br/>
                Making a difference since 2010
              </p>
            </td>
          </tr>

        </table>
        <!-- End outer card -->

      </td>
    </tr>
  </table>

</body>
</html>
    `,
  };

  await transporter.sendMail(mailOptions);
}
