import io
import base64
import os
import sqlite3
import re
import requests
import pyotp
import qrcode
import secrets
import threading
import time

from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from urllib.parse import urlparse, urljoin
from datetime import timedelta, datetime
from flask_talisman import Talisman
from werkzeug.utils import secure_filename
from flask_login import login_required
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from datetime import datetime


# Load .env file
load_dotenv()

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  

app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_default_secret')
app.permanent_session_lifetime = timedelta(minutes=15)

# Flask-Talisman for security headers
Talisman(app, content_security_policy=None) 
# Email setup
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.getenv('MAIL_USERNAME'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

bcrypt = Bcrypt(app)
mail = Mail(app)

# Google OAuth setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account'  # Force Gmail account chooser
    }
)

UPLOAD_FOLDER = 'static/profile_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY')
SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
DB_FILE = 'users.db'
# SQLite Database
DB_FILE = 'users.db'
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            otp_secret TEXT NOT NULL,
            last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            previous_password_hash TEXT,
            previous_password_hash2 TEXT,
            previous_password_hash3 TEXT,
            reset_token TEXT,
            reset_token_expiry TIMESTAMP,
            email_verified INTEGER DEFAULT 0,
            verification_token TEXT,
            verification_token_expiry TIMESTAMP,
            failed_login_attempts INTEGER DEFAULT 0,
            lockout_time TIMESTAMP,
            last_login DATETIME,
            role TEXT DEFAULT 'user',
            is_enabled INTEGER DEFAULT 1,
            profile_image TEXT DEFAULT NULL
        )''')

        db.execute('''CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            permissions TEXT NOT NULL
        )''')

        db.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            event TEXT,
            ip TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        existing_roles = db.execute('SELECT COUNT(*) AS count FROM roles').fetchone()['count']
        if existing_roles == 0:
            db.execute('''INSERT INTO roles (name, permissions) VALUES
                ('admin', 'manage_users,edit_posts,delete_posts,change_roles,enable_disable_users'),
                ('moderator', 'edit_posts'),
                ('user', '')''')
        db.commit()

init_db()


def get_all_users():
    db = get_db()
    return db.execute('SELECT * FROM users ORDER BY id').fetchall()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash("Access denied.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') != 'admin':
                flash("Permission denied.", "danger")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper


class User(UserMixin):
    def __init__(self, user_row): 
        self.id = user_row['id']
        self.username = user_row['username']
        self.email = user_row['email']
        self.role = user_row['role']


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return User(row) if row else None



@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    user = None
    if 'user' in session:
        user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    return render_template('admin_dashboard.html', user=user)

@app.route('/admin/manage_users')
@admin_required
@permission_required('manage_users')
def manage_users():
    users = get_all_users()
    return render_template('admin/users.html', users=users)

@app.route('/admin/manage_roles')
@admin_required
@permission_required('change_roles')
def manage_roles():
    db = get_db()
    roles = db.execute('SELECT * FROM roles').fetchall()
    return render_template('admin_roles.html', roles=roles)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_event(username, event):
    ip = request.remote_addr or 'unknown'
    ua = request.headers.get('User-Agent') or 'unknown'
    with get_db() as db:
        db.execute('INSERT INTO audit_logs (username, event, ip, user_agent) VALUES (?, ?, ?, ?)',
                   (username, event, ip, ua))

def verify_captcha(token):
    try:
        resp = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': SECRET_KEY, 'response': token}
        )
        return resp.json().get('success', False)
    except:
        return False

def password_score(pw):
    return sum([
        len(pw) >= 8,
        bool(re.search(r'[A-Z]', pw)),
        bool(re.search(r'[a-z]', pw)),
        bool(re.search(r'\d', pw)),
        bool(re.search(r'[\W_]', pw))
    ])

def check_password_reuse(db, user_id, new_password):
    user = db.execute('SELECT previous_password_hash, previous_password_hash2, previous_password_hash3 FROM users WHERE id = ?', (user_id,)).fetchone()
    for phash in [user['previous_password_hash'], user['previous_password_hash2'], user['previous_password_hash3']]:
        if phash and bcrypt.check_password_hash(phash, new_password):
            return True
    return False


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user' not in session:
                flash('Login required.', 'warning')
                return redirect(url_for('login'))

            db = get_db()
            user = db.execute('SELECT role FROM users WHERE username = ?', (session['user'],)).fetchone()
            if not user:
                flash('User not found.', 'danger')
                return redirect(url_for('login'))

            role = db.execute('SELECT permissions FROM roles WHERE name = ?', (user['role'],)).fetchone()
            if not role:
                flash('Role not found.', 'danger')
                return redirect(url_for('dashboard'))

            if permission not in role['permissions'].split(','):
                log_event(session['user'], f'permission_denied:{permission}')
                flash('Permission denied.', 'danger')
                return redirect(url_for('dashboard'))

            return f(*args, **kwargs)
        return wrapped
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Login required.', 'warning')
            return redirect(url_for('login'))
        db = get_db()
        u = db.execute('SELECT role FROM users WHERE username = ?', (session['user'],)).fetchone()
        if not u or u['role'] != 'admin':
            flash('Admin access only.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def send_reset_email(to_email, reset_link):
    msg = Message('Password Reset Request', recipients=[to_email])
    msg.body = f'To reset your password, visit:\n{reset_link}'
    mail.send(msg)

def send_otp_email(to_email, code):
    msg = Message('Your 2FA Code', recipients=[to_email])
    msg.body = f'Your 2FA code: {code}'
    mail.send(msg)

def send_verification_email(to_email, username, token):
    link = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify your Email', recipients=[to_email])
    msg.body = f'Hi {username},\nPlease verify your email by clicking this link:\n{link}\nLink expires in 24 hours.'
    mail.send(msg)

def check_password_reuse(db, user_id, new_password):
    user = db.execute('SELECT previous_password_hash, previous_password_hash2, previous_password_hash3 FROM users WHERE id = ?', (user_id,)).fetchone()
    for phash in [user['previous_password_hash'], user['previous_password_hash2'], user['previous_password_hash3']]:
        if phash and bcrypt.check_password_hash(phash, new_password):
            return True
    return False

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Login required.', 'warning')
            return redirect(url_for('login'))
        row = get_db().execute('SELECT role FROM users WHERE username = ?', (session['user'],)).fetchone()
        if not row or row['role'] != 'admin':
            flash('Admin access only.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_permissions():
    role_permissions = {
        'admin': ['manage_users', 'edit_posts', 'delete_posts', 'change_roles', 'enable_disable_users'],
        'moderator': ['edit_posts'],
        'user': []

    }
    user_role = session.get('role', 'user')
    return dict(role_permissions=role_permissions, user_role=user_role)

@app.route('/admin/ajax_toggle_user', methods=['POST'])
@admin_required
@permission_required('enable_disable_users')
def ajax_toggle_user():
    user_id = request.json.get('user_id')
    db = get_db()
    u = db.execute('SELECT username, is_enabled FROM users WHERE id = ?', (user_id,)).fetchone()
    if u:
        new_status = 0 if u['is_enabled'] else 1
        db.execute('UPDATE users SET is_enabled = ? WHERE id = ?', (new_status, user_id))
        db.commit()
        log_event(session['user'], f'ajax_toggle_user:{u["username"]}')
        return {'status': 'success', 'new_status': new_status}
    return {'status': 'error'}, 400


@app.route('/admin/change_role/<int:user_id>/<new_role>')
@admin_required
@permission_required('change_roles')
def change_role(user_id, new_role):
    if new_role not in ('admin', 'user', 'moderator'):
        flash('Invalid role.', 'danger')
        return redirect(url_for('manage_users'))

    db = get_db()
    user = db.execute('SELECT username, role FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('manage_users'))

    if user['role'] == new_role:
        flash(f'User {user["username"]} already has the role {new_role}.', 'info')
        return redirect(url_for('manage_users'))

    db.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    db.commit()
    log_event(session['user'], f'changed_role:{user["username"]} to {new_role}')
    flash(f'User {user["username"]} role changed to {new_role}.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (session['user'],)).fetchone()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('login'))

    session['role'] = user['role']

    # Handle profile image upload on POST
    if request.method == 'POST':
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                    # Save file to static/profile_images/
                    save_path = os.path.join(app.root_path, 'static', 'profile_images', filename)
                    file.save(save_path)

                    # Update user's profile image in DB
                    db.execute('UPDATE users SET profile_image = ? WHERE username = ?', (filename, session['user']))
                    db.commit()

                    flash("Profile image updated!", "success")
                    return redirect(url_for('dashboard'))
                else:
                    flash("Invalid file type. Please upload PNG, JPG, or JPEG images.", "error")
            else:
                flash("No file selected.", "error")

    # Set profile image to show (default if none)
    profile_image = user['profile_image'] if user['profile_image'] else 'default.png'

    last_login_row = db.execute(
        "SELECT timestamp FROM audit_logs WHERE username = ? AND event = 'login_2fa_success' ORDER BY timestamp DESC LIMIT 1",
        (session['user'],)
    ).fetchone()
    last_login = last_login_row['timestamp'] if last_login_row else None

    return render_template('dashboard.html',
                           user=user,
                           username=user['username'],
                           profile_image=profile_image,
                           last_login=last_login,
                           role=user['role'])


@app.route('/admin/toggle_user/<int:user_id>')
@admin_required
@permission_required('enable_disable_users')
def toggle_user(user_id):
    db = get_db()
    u = db.execute('SELECT username, is_enabled FROM users WHERE id = ?', (user_id,)).fetchone()
    if u:
        new_status = 0 if u['is_enabled'] else 1
        db.execute('UPDATE users SET is_enabled = ? WHERE id = ?', (new_status, user_id))
        db.commit()
        log_event(session['user'], f'admin_toggle_user:{u["username"]}')
        flash(f'User {u["username"]} {"enabled" if new_status else "disabled"}.', 'info')
    return redirect(url_for('manage_users'))




@app.route('/roles')
@admin_required 
def view_roles():
    db = get_db()
    roles = db.execute('SELECT * FROM roles ORDER BY id DESC').fetchall()

    # Optional: define role descriptions
    role_descriptions = {
        'admin': 'Superuser with full access',
        'moderator': 'Can edit posts but not manage users',
        'user': 'Basic user with default access'
    }

    return render_template('admin/roles.html', roles=roles, descriptions=role_descriptions)


@app.route('/some_edit_route')
@permission_required('edit_posts')
def edit_post():
    ...

@app.route('/')
def landing():
    return redirect(url_for('dashboard')) if 'user' in session else render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        captcha_token = request.form.get('g-recaptcha-response', '')

        if not username or not password or not email:
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if not verify_captcha(captcha_token):
            flash('reCAPTCHA failed.', 'danger')
            return redirect(url_for('register'))

        if password_score(password) < 4:
            flash('Password too weak.', 'warning')
            return redirect(url_for('register'))

        password_hash = bcrypt.generate_password_hash(password).decode()
        otp_secret = pyotp.random_base32()
        verification_token = secrets.token_urlsafe(32)
        verification_expiry = datetime.now() + timedelta(hours=24)

        try:
            with get_db() as db:
                db.execute(
                    'INSERT INTO users (username, email, password_hash, otp_secret, verification_token, verification_token_expiry) VALUES (?, ?, ?, ?, ?, ?)',
                    (username, email, password_hash, otp_secret, verification_token, verification_expiry)
                )
            send_verification_email(email, username, verification_token)
            log_event(username, 'register')
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))

        uri = pyotp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name='SecureApp')
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        flash('Registration successful! Please verify your email before login.', 'info')
        return render_template('register_2fa_setup.html', qr_code=qr_b64, secret=otp_secret)

    return render_template('register.html', site_key=SITE_KEY)

@app.route('/enable_2fa', methods=['POST'])
def disable_2fa():
    if 'user' not in session:
        return redirect(url_for('login'))

    with get_db() as db:
        db.execute('UPDATE users SET otp_secret = NULL WHERE username = ?', (session['user'],))
        db.commit()
        log_event(session['user'], '2fa_disabled')
    flash('2FA disabled.', 'info')
    return redirect(url_for('dashboard'))



@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    if 'user' not in session and 'tmp_user' not in session:
        flash("Session expired or invalid.", "danger")
        return redirect(url_for('login'))

    username = session.get('user') or session.get('tmp_user')
    code = request.form.get('code')

    db = get_db()
    user = db.execute('SELECT otp_secret FROM users WHERE username = ?', (username,)).fetchone()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    totp = pyotp.TOTP(user['otp_secret'])

    if totp.verify(code):
        flash("2FA setup successful!", "success")
        log_event(username, '2fa_verified')

        if 'tmp_user' in session:
            session.pop('tmp_user')
            session['user'] = username
            return redirect(url_for('dashboard'))

        return redirect(url_for('dashboard'))
    else:
        flash("Invalid 2FA code. Please try again.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/verify_email/<token>')
def verify_email(token):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE verification_token = ?', (token,)).fetchone()
    if not user or datetime.now() > datetime.strptime(user['verification_token_expiry'], '%Y-%m-%d %H:%M:%S.%f'):
        flash('Invalid or expired verification link.', 'danger')
        return redirect(url_for('login'))

    with get_db() as db:
        db.execute('UPDATE users SET email_verified = 1, verification_token = NULL, verification_token_expiry = NULL WHERE id = ?', (user['id'],))
    flash('Email verified successfully! You can now login.', 'success')
    log_event(user['username'], 'email_verified')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        recaptcha_token = request.form.get('g-recaptcha-response')

        if not verify_captcha(recaptcha_token):
            flash('reCAPTCHA failed. Please try again.', 'danger')
            return redirect(url_for('login'))

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        print(f"Login attempt: username={username}")
        print(f"User found: {user}")
        if user:
            print(f"DB Role: {user['role']}")

        if user:
            # Account lockout check
            if user['lockout_time']:
                lockout_time = datetime.strptime(user['lockout_time'], '%Y-%m-%d %H:%M:%S')
                if datetime.now() < lockout_time:
                    remaining = (lockout_time - datetime.now()).seconds // 60 + 1
                    flash(f'Account locked. Try again in {remaining} minute(s).', 'danger')
                    log_event(username, 'login_locked_out')
                    return redirect(url_for('login'))
                else:
                    db.execute('UPDATE users SET failed_login_attempts = 0, lockout_time = NULL WHERE username = ?', (username,))
                    db.commit()

            # Password check
            if bcrypt.check_password_hash(user['password_hash'], password):
                if not user['email_verified']:
                    flash('Please verify your email before logging in.', 'warning')
                    return redirect(url_for('login'))

                try:
                    last_change = datetime.strptime(user['last_password_change'], '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    last_change = datetime.strptime(user['last_password_change'], '%Y-%m-%d %H:%M:%S.%f')

                if datetime.now() - last_change > timedelta(days=90):
                    session['change_password'] = username
                    flash('Password expired. Please change it.', 'warning')
                    return redirect(url_for('change_password'))

                # Reset failed attempts and update last_login
                db.execute('UPDATE users SET failed_login_attempts = 0, lockout_time = NULL, last_login = ? WHERE username = ?',
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username)
                )
                db.commit()

                session['user'] = username
                session['role'] = user['role']
                login_user(User(user))  # ✅ Flask-Login session

                log_event(username, 'login_success')

                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard'))

            else:
                failed_attempts = user['failed_login_attempts'] + 1
                lockout_time = None
                if failed_attempts >= 5:
                    lockout_time = datetime.now() + timedelta(minutes=15)
                    flash('Account locked due to too many failed login attempts.', 'danger')
                    log_event(username, 'login_locked_out')
                else:
                    flash('Invalid credentials.', 'danger')
                    log_event(username, 'login_failed')

                db.execute(
                    'UPDATE users SET failed_login_attempts = ?, lockout_time = ? WHERE username = ?',
                    (failed_attempts, lockout_time.strftime('%Y-%m-%d %H:%M:%S') if lockout_time else None, username)
                )
                db.commit()
                return redirect(url_for('login'))

        else:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', site_key=SITE_KEY)


@app.route('/forgot_password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form['identifier'].strip() 
        db = get_db()
        user = None

        # Check if input looks like email
        if re.match(r"[^@]+@[^@]+\.[^@]+", identifier):
            user = db.execute('SELECT * FROM users WHERE email = ?', (identifier.lower(),)).fetchone()
        else:
            user = db.execute('SELECT * FROM users WHERE username = ?', (identifier,)).fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(minutes=30)
            db.execute('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
                       (token, expiry, user['id']))
            db.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            send_reset_email(user['email'], reset_link)
            log_event(user['username'], 'password_reset_requested')

        flash('If the username or email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE reset_token = ?', (token,)).fetchone()

    if not user or datetime.now() >  datetime.strptime(user['reset_token_expiry'], '%Y-%m-%d %H:%M:%S.%f'):
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(request.url)

        if password_score(new_password) < 4:
            flash('Password too weak.', 'warning')
            return redirect(request.url)

        # Check password reuse (prevent reuse of last 3 passwords)
        if check_password_reuse(db, user['id'], new_password):
            flash('You cannot reuse any of your last 3 passwords.', 'danger')
            return redirect(request.url)

        new_hash = bcrypt.generate_password_hash(new_password).decode()

        with get_db() as db2:
            old_hash = user['password_hash']
            prev_hash = user['previous_password_hash']
            prev2_hash = user['previous_password_hash2']

            db2.execute('''
                UPDATE users SET password_hash = ?, previous_password_hash = ?, previous_password_hash2 = ?, 
                previous_password_hash3 = ?, last_password_change = CURRENT_TIMESTAMP, reset_token = NULL, reset_token_expiry = NULL
                WHERE id = ?
            ''', (new_hash, old_hash, prev_hash, prev2_hash, user['id']))
            db2.commit()

        flash('Password reset successful. Please log in.', 'success')
        log_event(user['username'], 'password_reset_success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'change_password' not in session:
        return redirect(url_for('login'))

    username = session['change_password']

    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('change_password'))

        if password_score(new_password) < 4:
            flash('Password too weak.', 'danger')
            return redirect(url_for('change_password'))

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if not bcrypt.check_password_hash(user['password_hash'], old_password):
            flash('Incorrect current password.', 'danger')
            return redirect(url_for('change_password'))

        # Check password reuse (last 3)
        if check_password_reuse(db, user['id'], new_password):
            flash('You cannot reuse any of your last 3 passwords.', 'danger')
            return redirect(url_for('change_password'))

        new_hash = bcrypt.generate_password_hash(new_password).decode()

        with get_db() as db2:
            old_hash = user['password_hash']
            prev_hash = user['previous_password_hash']
            prev2_hash = user['previous_password_hash2']

            db2.execute('''
                UPDATE users SET password_hash = ?, previous_password_hash = ?, previous_password_hash2 = ?, 
                previous_password_hash3 = ?, last_password_change = CURRENT_TIMESTAMP
                WHERE username = ?
            ''', (new_hash, old_hash, prev_hash, prev2_hash, username))
            db2.commit()

        session.pop('change_password')
        flash('Password changed successfully. Please login again.', 'success')
        log_event(username, 'password_changed')
        return redirect(url_for('login'))

    return render_template('change_password.html')

@app.route('/twofa', methods=['GET', 'POST'])
def twofa():
    if 'tmp_user' not in session:
        return redirect(url_for('login'))

    username = session['tmp_user']
    user = get_db().execute('SELECT otp_secret, email FROM users WHERE username = ?', (username,)).fetchone()
    totp = pyotp.TOTP(user['otp_secret'])
    otp_code = totp.now()
    send_otp_email(user['email'], otp_code)

    next_page = request.args.get('next', 'user')  # default to user dashboard

    if request.method == 'POST':
        code = request.form['code'].strip()
        if totp.verify(code):
            session.pop('tmp_user')
            session['user'] = username
            log_event(username, 'login_2fa_success')
            flash('Login successful ✅', 'success')

            # Role-based final redirection
            if next_page == 'admin':
                return redirect(url_for('manage_users'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code.', 'danger')
            log_event(username, 'login_2fa_failed')

    return render_template('twofa.html')



def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Login required.', 'warning')
            return redirect(url_for('login'))
        db = get_db()
        u = db.execute('SELECT role FROM users WHERE username = ?', (session['user'],)).fetchone()
        if not u or u['role'] != 'admin':
            flash('Admin access only.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    user = session.get('user')

    logout_user()  # ✅ Flask-Login logout
    session.clear()  # Optional but good for clearing custom session data like 'role'

    if user:
        log_event(user, 'logout')

    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/login/google')
def login_google():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorized')
def google_callback():
    token = google.authorize_access_token()
    userinfo_endpoint = google.load_server_metadata().get("userinfo_endpoint")
    resp = google.get(userinfo_endpoint)
    user_info = resp.json()

    email = user_info['email']
    base_username = user_info.get('name', email.split('@')[0])
    username = base_username

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if not user:
        counter = 1
        while db.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
            username = f"{base_username}{counter}"
            counter += 1

        password_hash = bcrypt.generate_password_hash(secrets.token_urlsafe(16)).decode()
        otp_secret = pyotp.random_base32()
        verification_token = secrets.token_urlsafe(32)
        verification_expiry = datetime.now() + timedelta(hours=24)

        db.execute('INSERT INTO users (username, email, password_hash, otp_secret, verification_token, verification_token_expiry) VALUES (?, ?, ?, ?, ?, ?)',
                   (username, email, password_hash, otp_secret, verification_token, verification_expiry))
        db.commit()

        send_verification_email(email, username, verification_token)
        flash('Please verify your email sent to your Google account before logging in.', 'info')
        return redirect(url_for('login'))

    session['user'] = username
    session['role'] = user['role']  # <- ADD THIS LINE

    log_event(username, 'login_google_success')
    flash(f'Logged in as {username} via Google ', 'success')

    # Redirect based on role
    if user['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('dashboard'))

def print_custom_url():
    time.sleep(1)  # Wait for server to start
    print("\n * Running on https://myapp.local:5000/\n")

threading.Thread(target=print_custom_url).start()
if __name__ == "__main__":
    app.debug = True  
    app.run(
        host='127.0.0.1',
        port=5000,
        ssl_context=('certs/myapp.local+2.pem', 'certs/myapp.local+2-key.pem')
    )

