// /api/adminsessionverify.js
module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  // ---- EXTRACT COOKIES ----
  const cookies = req.headers.cookie || "";
  const cookieObj = {};
  
  cookies.split(";").forEach(cookie => {
    const [key, value] = cookie.trim().split("=");
    if (key && value) {
      cookieObj[key] = value;
    }
  });

  const adminSession = cookieObj.admin_session;
  const role = cookieObj.role;

  // ---- CHECK IF SESSION EXISTS ----
  if (!adminSession || !adminSession.startsWith("admin_")) {
    return res.status(401).json({ 
      authenticated: false, 
      error: "No valid session" 
    });
  }

  // ---- EXTRACT ADMIN ID FROM SESSION ----
  const adminId = adminSession.replace("admin_", "");

  // ---- VERIFY ADMIN EXISTS IN DATABASE ----
  try {
    const adminRes = await fetch(
      `${process.env.SUPABASE_URL}/rest/v1/admins?id=eq.${adminId}&select=*`,
      {
        headers: {
          apikey: process.env.SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`
        }
      }
    );

    const admins = await adminRes.json();
    const admin = admins[0];

    if (!admin) {
      return res.status(401).json({ 
        authenticated: false, 
        error: "Invalid session" 
      });
    }

    // ---- SUCCESS ----
    return res.status(200).json({ 
      authenticated: true,
      admin: {
        id: admin.id,
        email: admin.email,
        role: admin.role
      }
    });

  } catch (e) {
    return res.status(500).json({ 
      authenticated: false, 
      error: "Server error" 
    });
  }
};
