 SECURE FLASK REGISTRATION & LOGIN SYSTEM

👤 Developer: Safalta Bhujel  
📚 University of Sunderland – CET324: Advanced CyberSecurity  
📅 Academic Year: 2024/25  

🔐 OVERVIEW

This project is a complete, production-ready **secure user authentication system built using Flask.  
It includes modern security features, intuitive UI design, and best practices for user account management.


📁 PROJECT STRUCTURE


secure_registration/
├── static/
│   ├── css/
│   │   ├── style.css       → Baby pink/white themed styles
│   │   ├── 2fa.js          → Timer/script for 2FA
│   │   └── script.js       → Password strength validator
├── templates/
│   ├── *.html              → All UI templates (register, login, 2FA, dashboard, etc.)
├── .env                    → Environment config (KEEP SECRET)
├── .env.example            → Sample template to guide .env creation
├── app.py                  → Main Flask application logic
├── generate_secret.py      → Tool to generate pyotp secrets for testing
├── requirements.txt        → Python dependencies
├── README.txt              → This project guide
├── users.db                → Primary SQLite DB (user data)
├── site.db                 → (Optional) Secondary DB (unused unless extended)
├── security.log            → Audit trail of user actions
└── V3 Captcha/             → Captcha test/config folder (if using v3)


✨ KEY FEATURES


✅ reCAPTCHA v3 validation (Google)  
✅ Email verification before login allowed  
✅ 2FA (Two-Factor Authentication) via OTP email  
✅ Google OAuth login  
✅ Strong password enforcement  
✅ Password reuse prevention (no reuse of last 3)  
✅ Password expiry every 90 days  
✅ Account lockout after 5 failed login attempts (15 min)  
✅ Password reset via email with token expiry (30 min)  
✅ Audit logging (login, logout, password reset, etc.)  
✅ Flask-Talisman for HTTP security headers  
✅ Mobile responsive UI (baby pink & white theme)  
✅ SQLite backend (users.db)  


ROLE-BASED ACCESS CONTROL (RBAC)

Users are assigned roles (e.g., admin, user) during or after registration

Admins can manage users, view logs, and access protected routes

Regular users have limited access to their own dashboard and profile

Role checks are enforced on protected routes

RBAC is managed in the database and checked during session handling




⚙️ SETUP INSTRUCTIONS


1.  Create Virtual Environment
   > python -m venv venv  
   > venv\Scripts\activate   (Windows)  
   > source venv/bin/activate (Linux/macOS)

2.  Install Dependencies
   > pip install -r requirements.txt

3.  Create .env File (based on .env.example)


4. ▶️ Run the Flask App
   > python app.py  
   Access: http://127.0.0.1:5000/


📌 OPTIONAL FILES

- `generate_secret.py`: Tool to generate test OTP secrets.
- `security.log`: Contains readable logs for major user events.
- `site.db`: Unused unless expanded for separate data needs.


📨 EMAIL NOTES

- Gmail SMTP is used (`smtp.gmail.com`, port 587)
- Use an **App Password** if 2FA is enabled on Gmail
- Ensure `Less secure app access` is allowed if using regular password (not recommended)


🧪 TESTING

- Try registering with a new user.
- Check your email for OTP and verification link.
- Try invalid login attempts to trigger account lockout.
- Use 2FA code sent via email to complete login.
- Check password expiry/reset scenarios.
- Google OAuth works for new or existing Gmail accounts.


📋 AUDIT LOGS

- All user actions like login, logout, reset, 2FA failures, and email verification are logged in `security.log` or SQLite `audit_logs` table.


📱 UI HIGHLIGHTS

🎨 Theme: Soft Baby Pink & White  
💡 Fully mobile responsive  
✅ Clean and modern design  
🚫 Avoids unnecessary purple or dark shades


📦 DEPENDENCIES (requirements.txt)

- Flask  
- Flask-Bcrypt  
- Flask-Mail  
- Flask-Talisman  
- python-dotenv  
- pyotp  
- qrcode  
- requests  
- Authlib  
- sqlite3 (built-in)


🛡️ SECURITY PRACTICES FOLLOWED

✔️ Hashed passwords (bcrypt)  
✔️ Email verification before login  
✔️ 2FA using email OTP  
✔️ reCAPTCHA v2  
✔️ HTTPS headers via Flask-Talisman  
✔️ Login lockout + audit logs  
✔️ Secure session cookie attributes  
✔️ Password reuse prevention  
✔️ Token-based reset/verification with expiry


📝 FINAL NOTES

- This system is production-level secure.
- The `users.db` is self-initialized on first run.
- All templates are self-contained and themed.
- Email must be functional for reset and OTP features.
- Remember to keep `.env` secret and out of version control.

