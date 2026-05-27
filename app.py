"""
Secure Student Portal
Features: Attack Chart, Real Email OTP, Log Search, Message Reply,
          Auto-refresh SOC, Email Forgot Password
"""
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g, send_from_directory, jsonify, Response)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3, bcrypt, bleach, re, os, time, random, string, csv, io
from functools import wraps
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-key-123')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

csrf    = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["300 per day","60 per hour"])

DATABASE   = 'portal.db'
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXT = {'pdf','docx','txt','png','jpg','jpeg'}
IMAGE_EXT   = {'png','jpg','jpeg'}
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── Email config (Gmail SMTP) ─────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

MAIL_SENDER   = os.getenv('MAIL_SENDER')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
MAIL_ENABLED  = os.getenv('MAIL_ENABLED', 'False').strip().lower() in ('true', '1', 'yes')

def send_email(to_addr, subject, html_body):
    """Send email via Gmail SMTP. Returns (True, '') or (False, error_msg)."""
    if not MAIL_ENABLED:
        return False, 'Email disabled'
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = MAIL_SENDER
        msg['To']      = to_addr
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(MAIL_SENDER, MAIL_PASSWORD.replace(' ',''))
            server.sendmail(MAIL_SENDER, to_addr, msg.as_string())
        return True, ''
    except Exception as e:
        return False, str(e)

# ── Security headers ──────────────────────────────────────────────────────────
@app.after_request
def sec_headers(r):
    r.headers['X-Frame-Options']        = 'DENY'
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['X-XSS-Protection']       = '1; mode=block'
    r.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
    r.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:;"
    )
    return r

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS organizations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            admin_code_hash TEXT NOT NULL,
            created_at      TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT DEFAULT 'student',
            full_name     TEXT DEFAULT '',
            department    TEXT DEFAULT 'CSE',
            year          TEXT DEFAULT 'S6',
            bio           TEXT DEFAULT '',
            org_id        INTEGER,
            is_locked     INTEGER DEFAULT 0,
            created_at    TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(org_id) REFERENCES organizations(id)
        );
        CREATE TABLE IF NOT EXISTS attack_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            ip_address  TEXT,
            payload     TEXT,
            username    TEXT,
            endpoint    TEXT,
            org_id      INTEGER,
            timestamp   TEXT DEFAULT (datetime('now')),
            status      TEXT DEFAULT 'blocked'
        );
        CREATE TABLE IF NOT EXISTS files (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            recipient_id  INTEGER,
            org_id        INTEGER,
            filename      TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_size     INTEGER,
            share_note    TEXT,
            uploaded_at   TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS announcements (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id   INTEGER NOT NULL,
            org_id     INTEGER NOT NULL,
            title      TEXT NOT NULL,
            content    TEXT NOT NULL,
            category   TEXT DEFAULT 'general',
            priority   TEXT DEFAULT 'normal',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT NOT NULL,
            content    TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id    INTEGER NOT NULL,
            recipient_id INTEGER,
            org_id       INTEGER,
            subject      TEXT NOT NULL,
            body         TEXT NOT NULL,
            is_read      INTEGER DEFAULT 0,
            reply_to     INTEGER DEFAULT NULL,
            created_at   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS login_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            status     TEXT DEFAULT 'success',
            timestamp  TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS last_seen (
            user_id   INTEGER PRIMARY KEY,
            ts        REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS email_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id      INTEGER,
            to_addr     TEXT,
            subject     TEXT,
            status      TEXT DEFAULT 'sent',
            attack_type TEXT,
            timestamp   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS otp_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            otp_code   TEXT NOT NULL,
            expires_at REAL NOT NULL,
            used       INTEGER DEFAULT 0,
            attempts   INTEGER DEFAULT 0
        );
    """)
    db.commit()
    db.close()

# ── Helpers ───────────────────────────────────────────────────────────────────
login_attempts = {}
MAX_ATTEMPTS   = 5
LOCKOUT_SECS   = 300

def is_locked_out(ip):
    now    = time.time()
    recent = [t for t in login_attempts.get(ip,[]) if now-t < LOCKOUT_SECS]
    login_attempts[ip] = recent
    return len(recent) >= MAX_ATTEMPTS

def record_attempt(ip):
    login_attempts.setdefault(ip,[]).append(time.time())

def sanitize(t):
    return bleach.clean(str(t), tags=[], strip=True)

def contains_sqli(t):
    return bool(re.search(
        r"('|--|;|\/\*|\*\/|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bEXEC\b)",
        str(t), re.IGNORECASE))

def contains_xss(t):
    return bool(re.search(
        r"<\s*(script|iframe|object|embed|svg|img)|javascript\s*:|on\w+\s*=",
        str(t), re.IGNORECASE))

def log_attack(attack_type, payload, username=None):
    try:
        db  = get_db()
        oid = session.get('org_id')
        db.execute(
            "INSERT INTO attack_logs (attack_type,ip_address,payload,username,endpoint,org_id) VALUES (?,?,?,?,?,?)",
            (attack_type, request.remote_addr, str(payload)[:500], username, request.endpoint or '', oid))
        db.commit()
        # FEATURE 2: Send email alert to admin when attack detected
        if oid:
            admin = db.execute(
                "SELECT u.email, u.full_name FROM users u WHERE u.org_id=? AND u.role='admin' LIMIT 1",(oid,)).fetchone()
            if admin:
                email_alert(admin['email'], admin['full_name'], attack_type, payload, username)
    except: pass

def email_alert(admin_email, admin_name, attack_type, payload, attacker):
    """Send attack alert email to admin and log it."""
    subject = f"🚨 Security Alert — {attack_type} detected"
    body = f"""
    <div style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:20px;border:1px solid #333;">
      <h2 style="color:#ef4444;">🚨 ATTACK DETECTED</h2>
      <p>Hello {admin_name},</p>
      <p>A security threat was detected in your organization portal.</p>
      <table style="border-collapse:collapse;width:100%;margin-top:12px;">
        <tr><td style="padding:6px;border:1px solid #333;color:#aaa;">Attack Type</td>
            <td style="padding:6px;border:1px solid #333;color:#ef4444;font-weight:bold;">{attack_type}</td></tr>
        <tr><td style="padding:6px;border:1px solid #333;color:#aaa;">Attacker</td>
            <td style="padding:6px;border:1px solid #333;">{attacker or 'Unknown'}</td></tr>
        <tr><td style="padding:6px;border:1px solid #333;color:#aaa;">Payload</td>
            <td style="padding:6px;border:1px solid #333;color:#f59e0b;">{str(payload)[:200]}</td></tr>
        <tr><td style="padding:6px;border:1px solid #333;color:#aaa;">Time</td>
            <td style="padding:6px;border:1px solid #333;">{time.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
      </table>
      <p style="margin-top:16px;color:#aaa;">Login to your admin panel to view the full attack log.</p>
      <p style="color:#555;font-size:12px;">Secure Student Portal — 23CSE313</p>
    </div>
    """
    ok, err = send_email(admin_email, subject, body)
    # Log the email attempt in DB
    try:
        oid = session.get('org_id')
        db  = get_db()
        db.execute(
            "INSERT INTO email_logs (org_id,to_addr,subject,status,attack_type) VALUES (?,?,?,?,?)",
            (oid, admin_email, subject, 'sent' if ok else f'failed:{err[:80]}', attack_type))
        db.commit()
    except: pass

def check_inputs(*fields, username=None):
    for v in fields:
        if contains_sqli(v): log_attack('SQL Injection', v, username); return False
        if contains_xss(v):  log_attack('XSS Attempt',  v, username); return False
    return True

def validate_password(pw):
    if len(pw) < 8:                                   return False,"Password must be at least 8 characters."
    if not re.search(r'[A-Z]', pw):                   return False,"Password must contain an uppercase letter."
    if not re.search(r'[a-z]', pw):                   return False,"Password must contain a lowercase letter."
    if not re.search(r'\d', pw):                      return False,"Password must contain a digit."
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', pw): return False,"Password must contain a special character."
    return True,"OK"

def username_for(db, uid):
    if not uid: return 'Admin'
    u = db.execute("SELECT full_name,username FROM users WHERE id=?",(uid,)).fetchone()
    return (u['full_name'] or u['username']) if u else 'Unknown'

def update_last_seen():
    if 'user_id' in session:
        try:
            db = get_db()
            db.execute("INSERT OR REPLACE INTO last_seen (user_id,ts) VALUES (?,?)",
                       (session['user_id'], time.time()))
            db.commit()
        except: pass

def get_unread_count():
    if 'user_id' not in session: return 0
    try:
        row = get_db().execute(
            "SELECT COUNT(*) as n FROM messages WHERE recipient_id=? AND is_read=0",
            (session['user_id'],)).fetchone()
        return row['n'] if row else 0
    except: return 0

# ── Decorators ────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def d(*a, **k):
        if 'user_id' not in session:
            flash('Please log in.','warning')
            return redirect(url_for('login'))
        update_last_seen()
        return f(*a, **k)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **k):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            log_attack('Unauthorized Admin Access',
                       f'User {session.get("username")} tried /admin', session.get('username'))
            flash('Access denied.','danger')
            return redirect(url_for('dashboard'))
        update_last_seen()
        return f(*a, **k)
    return d

# ─────────────────────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/')
def index(): return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
@limiter.limit("30 per minute")
def login():
    if request.method == 'POST':
        ip       = request.remote_addr
        username = request.form.get('username','').strip()
        password = request.form.get('password','')

        if is_locked_out(ip):
            log_attack('Brute Force Lockout', f'IP {ip}', username)
            flash(f'Too many failed attempts. Locked for {LOCKOUT_SECS//60} minutes.','danger')
            return render_template('login.html')

        if contains_sqli(username) or contains_sqli(password):
            log_attack('SQL Injection', f"{username} / {password}", username)
            record_attempt(ip)
            flash('Malicious input detected and blocked.','danger')
            return render_template('login.html')

        if contains_xss(username) or contains_xss(password):
            log_attack('XSS Attempt', f"{username} / {password}", username)
            record_attempt(ip)
            flash('Malicious input detected and blocked.','danger')
            return render_template('login.html')

        username = sanitize(username)
        user     = get_db().execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()

        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            if user['is_locked']:
                flash('Your account has been locked by your administrator.','danger')
                return render_template('login.html')
            login_attempts.pop(ip, None)
            db = get_db()
            db.execute("INSERT INTO login_log (user_id,ip_address,user_agent,status) VALUES (?,?,?,?)",
                       (user['id'], ip, request.headers.get('User-Agent','')[:200], 'success'))
            db.commit()
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            session['name']     = user['full_name'] or user['username']
            session['org_id']   = user['org_id']
            update_last_seen()
            return redirect(url_for('admin_dashboard') if user['role']=='admin' else url_for('dashboard'))
        else:
            record_attempt(ip)
            remaining = max(0, MAX_ATTEMPTS - len(login_attempts.get(ip,[])))
            log_attack('Failed Login', username, username)
            try:
                u = get_db().execute("SELECT id FROM users WHERE username=?",(username,)).fetchone()
                if u:
                    get_db().execute("INSERT INTO login_log (user_id,ip_address,user_agent,status) VALUES (?,?,?,?)",
                                     (u['id'], ip, request.headers.get('User-Agent','')[:200], 'failed'))
                    get_db().commit()
            except: pass
            flash(f'Invalid credentials. {remaining} attempts left before lockout.','danger')
    return render_template('login.html')

@app.route('/register/admin', methods=['GET','POST'])
def register_admin():
    if request.method == 'POST':
        full_name    = request.form.get('full_name','').strip()
        username     = request.form.get('username','').strip()
        email        = request.form.get('email','').strip()
        password     = request.form.get('password','')
        org_name     = request.form.get('org_name','').strip()
        admin_code   = request.form.get('admin_code','').strip()
        confirm_code = request.form.get('confirm_code','').strip()

        if not check_inputs(full_name, username, email, org_name, username=username):
            flash('Malicious input detected.','danger')
            return render_template('register_admin.html')

        full_name = sanitize(full_name); username = sanitize(username)
        email     = sanitize(email);     org_name = sanitize(org_name)

        if not all([full_name, username, email, password, org_name, admin_code]):
            flash('All fields are required.','warning')
            return render_template('register_admin.html')

        ok, msg = validate_password(password)
        if not ok: flash(msg,'warning'); return render_template('register_admin.html')

        if len(admin_code) < 8:
            flash('Admin Code must be at least 8 characters.','warning')
            return render_template('register_admin.html')

        if admin_code != confirm_code:
            flash('Admin Codes do not match.','warning')
            return render_template('register_admin.html')

        pw_hash   = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        code_hash = bcrypt.hashpw(admin_code.encode(), bcrypt.gensalt()).decode()
        db = get_db()
        try:
            db.execute("INSERT INTO organizations (name,admin_code_hash) VALUES (?,?)",(org_name, code_hash))
            db.commit()
            org_id = db.execute("SELECT id FROM organizations WHERE name=? ORDER BY id DESC LIMIT 1",(org_name,)).fetchone()['id']
            db.execute("INSERT INTO users (username,email,password_hash,role,full_name,org_id) VALUES (?,?,?,?,?,?)",
                       (username, email, pw_hash, 'admin', full_name, org_id))
            db.commit()
            flash(f'Organization "{org_name}" created! Share your Admin Code with students.','success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.','danger')
    return render_template('register_admin.html')

@app.route('/register/student', methods=['GET','POST'])
def register_student():
    if request.method == 'POST':
        full_name  = request.form.get('full_name','').strip()
        username   = request.form.get('username','').strip()
        email      = request.form.get('email','').strip()
        dept       = request.form.get('department','CSE')
        year       = request.form.get('year','S6')
        password   = request.form.get('password','')
        admin_code = request.form.get('admin_code','').strip()

        if not check_inputs(full_name, username, email, username=username):
            flash('Malicious input detected.','danger')
            return render_template('register_student.html')

        full_name = sanitize(full_name); username = sanitize(username); email = sanitize(email)

        if not all([full_name, username, email, password, admin_code]):
            flash('All fields including Admin Code are required.','warning')
            return render_template('register_student.html')

        ok, msg = validate_password(password)
        if not ok: flash(msg,'warning'); return render_template('register_student.html')

        db   = get_db()
        orgs = db.execute("SELECT * FROM organizations").fetchall()
        matched_org = None
        for org in orgs:
            if bcrypt.checkpw(admin_code.encode(), org['admin_code_hash'].encode()):
                matched_org = org; break

        if not matched_org:
            log_attack('Wrong Admin Code', admin_code[:20], username)
            flash('Invalid Admin Code.','danger')
            return render_template('register_student.html')

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            db.execute("INSERT INTO users (username,email,password_hash,role,full_name,department,year,org_id) VALUES (?,?,?,?,?,?,?,?)",
                       (username, email, pw_hash, 'student', full_name, dept, year, matched_org['id']))
            db.commit()
            flash(f'Account created! You joined "{matched_org["name"]}". Please log in.','success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.','danger')
    return render_template('register_student.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Session destroyed.','info')
    return redirect(url_for('login'))

# ── Forgot Password — Email OTP flow ─────────────────────────────────────────
@app.route('/forgot-password', methods=['GET','POST'])
@limiter.limit("5 per minute")
def forgot_password():
    step = request.args.get('step','1')
    if request.method == 'POST':
        step = request.form.get('step','1')

        # STEP 1: Find user by email + username → send OTP
        if step == '1':
            email    = sanitize(request.form.get('email','').strip())
            username = sanitize(request.form.get('username','').strip())
            if not check_inputs(email, username):
                flash('Malicious input detected.','danger')
                return render_template('forgot_password.html', step='1')

            user = get_db().execute(
                "SELECT * FROM users WHERE email=? AND username=?",(email, username)).fetchone()

            # Always say same message (prevent user enumeration)
            if user:
                otp  = ''.join(random.choices(string.digits, k=6))
                exp  = time.time() + 600  # 10 min
                db   = get_db()
                # Clear old OTPs for this user
                db.execute("DELETE FROM otp_resets WHERE user_id=?",(user['id'],))
                db.execute("INSERT INTO otp_resets (user_id,otp_code,expires_at) VALUES (?,?,?)",
                           (user['id'], otp, exp))
                db.commit()
                session['reset_uid']   = user['id']
                session['reset_email'] = email

                # Send real email
                subject = "🔐 SecurePortal — Password Reset OTP"
                body = f"""
                <div style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:24px;border:1px solid #333;max-width:480px;">
                  <h2 style="color:#22c55e;margin-bottom:8px;">Password Reset Request</h2>
                  <p>Hello {user['full_name'] or user['username']},</p>
                  <p>Your one-time password reset code is:</p>
                  <div style="font-size:2.5rem;font-weight:bold;letter-spacing:0.4em;color:#22c55e;
                              text-align:center;padding:16px;border:1px dashed #333;margin:16px 0;">
                    {otp}
                  </div>
                  <p style="color:#aaa;">⏱ This code expires in <strong style="color:#fff;">10 minutes</strong>.</p>
                  <p style="color:#aaa;">If you did not request this, ignore this email. Your password remains unchanged.</p>
                  <hr style="border-color:#333;margin:16px 0;">
                  <p style="color:#555;font-size:11px;">Secure Student Portal</p>
                </div>
                """
                ok, err = send_email(email, subject, body)
                if ok:
                    flash(f'OTP sent to {email[:3]}***{email[email.find("@"):]}. Check your inbox.','success')
                else:
                    # Show OTP in flash if email fails (demo fallback)
                    flash(f'Email failed ({err}). Demo OTP: {otp}','warning')

            else:
                # Same message whether user exists or not
                flash('If that account exists, an OTP has been sent to the email.','info')
                log_attack('Failed Password Reset', f'{email}/{username}')

            return render_template('forgot_password.html', step='2',
                                   masked=email[:3]+'***'+email[email.find('@'):] if user else '')

        # STEP 2: Verify OTP
        elif step == '2':
            uid = session.get('reset_uid')
            if not uid:
                flash('Session expired. Start again.','danger')
                return redirect(url_for('forgot_password'))

            entered = request.form.get('otp','').strip()
            db      = get_db()
            row     = db.execute(
                "SELECT * FROM otp_resets WHERE user_id=? AND used=0 ORDER BY id DESC LIMIT 1",(uid,)).fetchone()

            if not row:
                flash('No active OTP. Please request a new one.','danger')
                return redirect(url_for('forgot_password'))

            # Max 3 attempts
            if row['attempts'] >= 3:
                db.execute("DELETE FROM otp_resets WHERE id=?",(row['id'],)); db.commit()
                log_attack('OTP Brute Force', f'uid={uid}')
                flash('Too many wrong attempts. Request a new OTP.','danger')
                return redirect(url_for('forgot_password'))

            if time.time() > row['expires_at']:
                db.execute("DELETE FROM otp_resets WHERE id=?",(row['id'],)); db.commit()
                flash('OTP expired. Please request a new one.','danger')
                return redirect(url_for('forgot_password'))

            if entered != row['otp_code']:
                db.execute("UPDATE otp_resets SET attempts=attempts+1 WHERE id=?",(row['id'],)); db.commit()
                left = 3 - row['attempts'] - 1
                flash(f'Wrong OTP. {left} attempt(s) remaining.','danger')
                return render_template('forgot_password.html', step='2',
                                       masked=session.get('reset_email',''))

            # OTP correct → mark used
            db.execute("UPDATE otp_resets SET used=1 WHERE id=?",(row['id'],)); db.commit()
            session['reset_verified'] = True
            flash('OTP verified! Set your new password.','success')
            return render_template('forgot_password.html', step='3')

        # STEP 3: Set new password
        elif step == '3':
            uid      = session.get('reset_uid')
            verified = session.get('reset_verified')
            if not uid or not verified:
                flash('Session expired.','danger')
                return redirect(url_for('forgot_password'))

            new_pw  = request.form.get('new_password','')
            confirm = request.form.get('confirm_password','')
            if new_pw != confirm:
                flash('Passwords do not match.','danger')
                return render_template('forgot_password.html', step='3')
            ok, msg = validate_password(new_pw)
            if not ok: flash(msg,'warning'); return render_template('forgot_password.html', step='3')

            h = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            get_db().execute("UPDATE users SET password_hash=? WHERE id=?",(h, uid))
            get_db().commit()
            session.pop('reset_uid', None); session.pop('reset_verified', None)
            session.pop('reset_email', None)
            flash('Password reset successfully! Please log in.','success')
            return redirect(url_for('login'))

    return render_template('forgot_password.html', step=step, masked='')

@app.route('/reset-password', methods=['GET','POST'])
def reset_password():
    if not session.get('reset_verified'):
        flash('Verify your identity first.','warning')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_pw  = request.form.get('new_password','')
        confirm = request.form.get('confirm_password','')
        if new_pw != confirm:
            flash('Passwords do not match.','warning')
            return render_template('reset_password.html')
        ok, msg = validate_password(new_pw)
        if not ok: flash(msg,'warning'); return render_template('reset_password.html')
        h = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
        get_db().execute("UPDATE users SET password_hash=? WHERE id=?",(h, session.get('reset_user_id')))
        get_db().commit()
        session.pop('reset_user_id', None); session.pop('reset_verified', None)
        flash('Password reset! Please log in.','success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# ─────────────────────────────────────────────────────────────────────────────
# STUDENT ROUTES
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    db     = get_db()
    tab    = request.args.get('tab','messages')
    org_id = session['org_id']
    uid    = session['user_id']
    user   = db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    notes  = db.execute("SELECT * FROM notes WHERE user_id=? ORDER BY created_at DESC",(uid,)).fetchall()
    announcements = db.execute(
        "SELECT * FROM announcements WHERE org_id=? ORDER BY priority DESC, created_at DESC",(org_id,)).fetchall()
    my_files = db.execute(
        "SELECT f.*, u.full_name as owner_name, r.full_name as recipient_name, r.username as recipient_username "
        "FROM files f JOIN users u ON f.user_id=u.id LEFT JOIN users r ON f.recipient_id=r.id "
        "WHERE f.user_id=? ORDER BY f.uploaded_at DESC",(uid,)).fetchall()
    shared_with_me = db.execute(
        "SELECT f.*, u.full_name as owner_name, u.username as owner_username "
        "FROM files f JOIN users u ON f.user_id=u.id "
        "WHERE f.recipient_id=? ORDER BY f.uploaded_at DESC",(uid,)).fetchall()
    org_users = db.execute(
        "SELECT id,username,full_name,department,year,role FROM users WHERE org_id=?",(org_id,)).fetchall()

    raw_msgs = db.execute(
        "SELECT * FROM messages WHERE org_id=? AND (sender_id=? OR recipient_id=?) ORDER BY created_at DESC LIMIT 50",
        (org_id, uid, uid)).fetchall()
    messages = []
    for m in raw_msgs:
        messages.append({
            'id':             m['id'],
            'subject':        m['subject'],
            'body':           m['body'],
            'is_read':        m['is_read'],
            'created_at':     m['created_at'],
            'sender_id':      m['sender_id'],
            'reply_to':       m['reply_to'],
            'sender_name':    username_for(db, m['sender_id']),
            'recipient_name': username_for(db, m['recipient_id']),
        })

    unread_count = sum(1 for m in messages if m['sender_id'] != uid and not m['is_read'])
    atk_rows     = db.execute(
        "SELECT attack_type, COUNT(*) as cnt FROM attack_logs GROUP BY attack_type ORDER BY cnt DESC LIMIT 5").fetchall()
    atk_stats    = [(r['attack_type'], r['cnt']) for r in atk_rows]
    org          = db.execute("SELECT * FROM organizations WHERE id=?",(org_id,)).fetchone()
    stats = {
        'messages': len(messages), 'files': len(my_files)+len(shared_with_me),
        'notes':    len(notes),    'unread': unread_count,
        'members':  len(org_users),'announce': len(announcements),
    }
    login_history = db.execute(
        "SELECT * FROM login_log WHERE user_id=? ORDER BY timestamp DESC LIMIT 5",(uid,)).fetchall()
    now      = time.time()
    seen_map = {}
    for u in org_users:
        row = db.execute("SELECT ts FROM last_seen WHERE user_id=?",(u['id'],)).fetchone()
        if row:
            diff = now - row['ts']
            seen_map[u['id']] = 'online' if diff < 60 else ('away' if diff < 300 else 'offline')
        else:
            seen_map[u['id']] = 'offline'

    return render_template('dashboard.html',
        tab=tab, user=user, notes=notes, announcements=announcements,
        files=my_files, shared_with_me=shared_with_me, org_users=org_users,
        messages=messages, atk_stats=atk_stats, org=org,
        stats=stats, login_history=login_history, seen_map=seen_map,
        unread_count=unread_count)

@app.route('/mark_read/<int:msg_id>', methods=['POST'])
@login_required
def mark_read(msg_id):
    get_db().execute("UPDATE messages SET is_read=1 WHERE id=? AND recipient_id=?",
                     (msg_id, session['user_id']))
    get_db().commit()
    return jsonify({'ok': True})

@app.route('/api/unread_count')
@login_required
def api_unread_count():
    return jsonify({'count': get_unread_count()})

# FEATURE 5: Auto-refresh — returns new attack count + timestamp
@app.route('/api/attack_alert')
@login_required
def api_attack_alert():
    if session.get('role') != 'admin': return jsonify({'count':0,'ts':''})
    row = get_db().execute(
        "SELECT COUNT(*) as n FROM attack_logs WHERE (org_id=? OR org_id IS NULL) AND timestamp > datetime('now','-30 seconds')",
        (session['org_id'],)).fetchone()
    total = get_db().execute(
        "SELECT COUNT(*) as n FROM attack_logs WHERE org_id=? OR org_id IS NULL",(session['org_id'],)).fetchone()
    return jsonify({
        'count': row['n'] if row else 0,
        'total': total['n'] if total else 0,
        'ts':    time.strftime('%H:%M:%S')
    })

@app.route('/api/last_seen', methods=['POST'])
@login_required
def api_last_seen():
    update_last_seen()
    return jsonify({'ok': True})

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    subject      = request.form.get('subject','').strip()
    body         = request.form.get('body','').strip()
    recipient_id = request.form.get('recipient_id','').strip() or None
    reply_to     = request.form.get('reply_to','').strip() or None
    broadcast    = request.form.get('broadcast','')

    if not check_inputs(subject, body, username=session['username']):
        flash('Malicious content detected.','danger')
        return redirect(url_for('dashboard', tab='messages'))

    subject = sanitize(subject); body = sanitize(body)
    if not subject or not body:
        flash('Subject and body are required.','warning')
        return redirect(url_for('dashboard', tab='messages'))

    db = get_db()
    if broadcast and session.get('role') == 'admin':
        students = db.execute(
            "SELECT id FROM users WHERE org_id=? AND role='student'",(session['org_id'],)).fetchall()
        for s in students:
            db.execute("INSERT INTO messages (sender_id,recipient_id,org_id,subject,body,reply_to) VALUES (?,?,?,?,?,?)",
                       (session['user_id'], s['id'], session['org_id'], subject, body, reply_to))
    else:
        db.execute("INSERT INTO messages (sender_id,recipient_id,org_id,subject,body,reply_to) VALUES (?,?,?,?,?,?)",
                   (session['user_id'], recipient_id, session['org_id'], subject, body, reply_to))
    db.commit()
    flash('Message sent securely.','success')
    return redirect(url_for('dashboard', tab='messages'))

@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    title   = request.form.get('title','').strip()
    content = request.form.get('content','').strip()
    if not check_inputs(title, content, username=session['username']):
        flash('Malicious content detected.','danger')
        return redirect(url_for('dashboard', tab='notes'))
    title = sanitize(title); content = sanitize(content)
    if not title or not content:
        flash('Title and content required.','warning')
        return redirect(url_for('dashboard', tab='notes'))
    get_db().execute("INSERT INTO notes (user_id,title,content) VALUES (?,?,?)",(session['user_id'],title,content))
    get_db().commit()
    flash('Note saved securely.','success')
    return redirect(url_for('dashboard', tab='notes'))

@app.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    db = get_db()
    n  = db.execute("SELECT * FROM notes WHERE id=? AND user_id=?",(note_id, session['user_id'])).fetchone()
    if n: db.execute("DELETE FROM notes WHERE id=?",(note_id,)); db.commit(); flash('Note deleted.','success')
    else: flash('Access denied.','danger')
    return redirect(url_for('dashboard', tab='notes'))

@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def upload_file():
    if 'file' not in request.files: flash('No file selected.','warning'); return redirect(url_for('dashboard', tab='files'))
    f = request.files['file']
    if not f.filename: flash('No file selected.','warning'); return redirect(url_for('dashboard', tab='files'))
    original = f.filename
    if '..' in original or '/' in original or '\\' in original:
        log_attack('Path Traversal', original, session['username'])
        flash('Invalid filename.','danger'); return redirect(url_for('dashboard', tab='files'))
    ext = original.rsplit('.',1)[-1].lower() if '.' in original else ''
    if ext not in ALLOWED_EXT:
        log_attack('Malicious File Upload', original, session['username'])
        flash(f'.{ext} not allowed. Use: {", ".join(ALLOWED_EXT)}','danger')
        return redirect(url_for('dashboard', tab='files'))
    stored       = f"{session['user_id']}_{int(time.time())}_{secure_filename(original)}"
    recipient_id = request.form.get('recipient_id','').strip() or None
    share_note   = sanitize(request.form.get('share_note','').strip())
    if recipient_id:
        recp = get_db().execute("SELECT org_id FROM users WHERE id=?",(recipient_id,)).fetchone()
        if not recp or recp['org_id'] != session['org_id']:
            flash('Cannot share outside your organization.','danger')
            return redirect(url_for('dashboard', tab='files'))
    f.save(os.path.join(UPLOAD_DIR, stored))
    size = os.path.getsize(os.path.join(UPLOAD_DIR, stored))
    get_db().execute(
        "INSERT INTO files (user_id,recipient_id,org_id,filename,original_name,file_size,share_note) VALUES (?,?,?,?,?,?,?)",
        (session['user_id'], recipient_id, session['org_id'], stored, original, size, share_note))
    get_db().commit()
    flash(f'"{original}" shared securely.','success')
    return redirect(url_for('dashboard', tab='files'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    db   = get_db()
    file = db.execute(
        "SELECT * FROM files WHERE id=? AND org_id=? AND (user_id=? OR recipient_id=?)",
        (file_id, session['org_id'], session['user_id'], session['user_id'])).fetchone()
    if not file:
        log_attack('IDOR Attempt', f'file {file_id}', session['username'])
        flash('Access denied.','danger'); return redirect(url_for('dashboard', tab='files'))
    return send_from_directory(UPLOAD_DIR, file['filename'], as_attachment=True, download_name=file['original_name'])

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    db   = get_db()
    file = db.execute("SELECT * FROM files WHERE id=? AND user_id=?",(file_id, session['user_id'])).fetchone()
    if file:
        try: os.remove(os.path.join(UPLOAD_DIR, file['filename']))
        except: pass
        db.execute("DELETE FROM files WHERE id=?",(file_id,)); db.commit()
        flash('File deleted.','success')
    else: flash('Access denied.','danger')
    return redirect(url_for('dashboard', tab='files'))

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    if request.method == 'POST':
        full_name = request.form.get('full_name','').strip()
        dept = request.form.get('department',''); year = request.form.get('year','')
        bio  = request.form.get('bio','').strip()
        if not check_inputs(full_name, bio, username=session['username']):
            flash('Malicious input detected.','danger')
            return render_template('profile.html', user=user)
        db.execute("UPDATE users SET full_name=?,department=?,year=?,bio=? WHERE id=?",
                   (sanitize(full_name), sanitize(dept), sanitize(year), sanitize(bio), session['user_id']))
        db.commit(); session['name'] = full_name
        flash('Profile updated.','success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current = request.form.get('current_password','')
    new_pw  = request.form.get('new_password','')
    db      = get_db()
    user    = db.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    if not bcrypt.checkpw(current.encode(), user['password_hash'].encode()):
        flash('Current password is incorrect.','danger')
        return redirect(url_for('profile'))
    ok, msg = validate_password(new_pw)
    if not ok: flash(msg,'warning'); return redirect(url_for('profile'))
    h = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    db.execute("UPDATE users SET password_hash=? WHERE id=?",(h, session['user_id'])); db.commit()
    flash('Password changed successfully.','success')
    return redirect(url_for('profile'))

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN ROUTES
# ─────────────────────────────────────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin_dashboard():
    db     = get_db()
    tab    = request.args.get('tab','logs')
    org_id = session['org_id']
    search = request.args.get('q','').strip()
    org    = db.execute("SELECT * FROM organizations WHERE id=?",(org_id,)).fetchone()

    # FEATURE 3: Search/filter attack logs
    if search:
        logs = db.execute(
            "SELECT * FROM attack_logs WHERE (org_id=? OR org_id IS NULL) AND "
            "(attack_type LIKE ? OR username LIKE ? OR payload LIKE ? OR ip_address LIKE ?) "
            "ORDER BY timestamp DESC LIMIT 100",
            (org_id, f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%')).fetchall()
    else:
        logs = db.execute("SELECT * FROM attack_logs WHERE org_id=? OR org_id IS NULL ORDER BY timestamp DESC LIMIT 100",(org_id,)).fetchall()

    users         = db.execute("SELECT id,username,email,full_name,department,year,role,is_locked,created_at FROM users WHERE org_id=?",(org_id,)).fetchall()
    announcements = db.execute("SELECT * FROM announcements WHERE org_id=? ORDER BY created_at DESC",(org_id,)).fetchall()
    org_users     = db.execute("SELECT id,username,full_name FROM users WHERE org_id=? AND role='student'",(org_id,)).fetchall()

    activity = []
    for u in users:
        if u['role'] == 'student':
            msg_cnt  = db.execute("SELECT COUNT(*) as n FROM messages WHERE sender_id=?",(u['id'],)).fetchone()['n']
            file_cnt = db.execute("SELECT COUNT(*) as n FROM files WHERE user_id=?",(u['id'],)).fetchone()['n']
            last_log = db.execute("SELECT timestamp FROM login_log WHERE user_id=? ORDER BY timestamp DESC LIMIT 1",(u['id'],)).fetchone()
            activity.append({
                'username':   u['username'],
                'full_name':  u['full_name'],
                'messages':   msg_cnt,
                'files':      file_cnt,
                'last_login': last_log['timestamp'][:16] if last_log else 'Never',
            })

    stats = {
        'total':    db.execute("SELECT COUNT(*) FROM attack_logs WHERE org_id=? OR org_id IS NULL",(org_id,)).fetchone()[0],
        'sqli':     db.execute("SELECT COUNT(*) FROM attack_logs WHERE (org_id=? OR org_id IS NULL) AND attack_type LIKE '%SQL%'",(org_id,)).fetchone()[0],
        'xss':      db.execute("SELECT COUNT(*) FROM attack_logs WHERE (org_id=? OR org_id IS NULL) AND attack_type LIKE '%XSS%'",(org_id,)).fetchone()[0],
        'brute':    db.execute("SELECT COUNT(*) FROM attack_logs WHERE (org_id=? OR org_id IS NULL) AND (attack_type LIKE '%Brute%' OR attack_type LIKE '%Login%')",(org_id,)).fetchone()[0],
        'upload':   db.execute("SELECT COUNT(*) FROM attack_logs WHERE (org_id=? OR org_id IS NULL) AND (attack_type LIKE '%Upload%' OR attack_type LIKE '%Path%')",(org_id,)).fetchone()[0],
        'students': db.execute("SELECT COUNT(*) FROM users WHERE org_id=? AND role='student'",(org_id,)).fetchone()[0],
        'files':    db.execute("SELECT COUNT(*) FROM files WHERE org_id=?",(org_id,)).fetchone()[0],
    }

    # FEATURE 1: Chart data for bar graph
    chart_labels = ['SQLi','XSS','Brute Force','File Attack','Other']
    other = max(0, stats['total'] - stats['sqli'] - stats['xss'] - stats['brute'] - stats['upload'])
    chart_values = [stats['sqli'], stats['xss'], stats['brute'], stats['upload'], other]

    # Email logs for feature 2
    email_logs = db.execute(
        "SELECT * FROM email_logs WHERE org_id=? ORDER BY timestamp DESC LIMIT 20",(org_id,)).fetchall()

    sent_messages = []
    for m in db.execute(
        "SELECT * FROM messages WHERE org_id=? AND sender_id=? ORDER BY created_at DESC LIMIT 30",
        (org_id, session['user_id'])).fetchall():
        sent_messages.append({
            'id': m['id'], 'subject': m['subject'], 'body': m['body'],
            'created_at': m['created_at'],
            'recipient_name': username_for(db, m['recipient_id']),
        })

    return render_template('admin.html',
        logs=logs, users=users, stats=stats, announcements=announcements,
        tab=tab, org=org, activity=activity,
        chart_labels=chart_labels, chart_values=chart_values,
        org_users=org_users, search=search,
        mail_enabled=MAIL_ENABLED, mail_sender=MAIL_SENDER,
        email_logs=email_logs, sent_messages=sent_messages)

@app.route('/admin/export_logs')
@admin_required
def export_logs():
    db   = get_db()
    logs = db.execute("SELECT * FROM attack_logs WHERE org_id=? OR org_id IS NULL ORDER BY timestamp DESC",(session['org_id'],)).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID','Attack Type','IP','Username','Endpoint','Payload','Time','Status'])
    for log in logs:
        writer.writerow([log['id'], log['attack_type'], log['ip_address'],
                         log['username'], log['endpoint'], log['payload'],
                         log['timestamp'], log['status']])
    output.seek(0)
    return Response(output, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment;filename=attack_logs.csv'})

@app.route('/admin/announce', methods=['POST'])
@admin_required
def post_announcement():
    title    = request.form.get('title','').strip()
    content  = request.form.get('content','').strip()
    cat      = request.form.get('category','general')
    priority = request.form.get('priority','normal')
    if not check_inputs(title, content, username='admin'):
        flash('Malicious content detected.','danger')
        return redirect(url_for('admin_dashboard', tab='post'))
    get_db().execute(
        "INSERT INTO announcements (admin_id,org_id,title,content,category,priority) VALUES (?,?,?,?,?,?)",
        (session['user_id'], session['org_id'], sanitize(title), sanitize(content), cat, priority))
    get_db().commit()
    flash('Announcement published.','success')
    return redirect(url_for('admin_dashboard', tab='post'))

@app.route('/admin/delete_announce/<int:ann_id>', methods=['POST'])
@admin_required
def delete_announcement(ann_id):
    get_db().execute("DELETE FROM announcements WHERE id=? AND org_id=?",(ann_id, session['org_id']))
    get_db().commit()
    flash('Announcement deleted.','success')
    return redirect(url_for('admin_dashboard', tab='post'))

@app.route('/admin/toggle_lock/<int:user_id>', methods=['POST'])
@admin_required
def toggle_lock(user_id):
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=? AND org_id=?",(user_id, session['org_id'])).fetchone()
    if user and user['role'] != 'admin':
        new = 0 if user['is_locked'] else 1
        db.execute("UPDATE users SET is_locked=? WHERE id=?",(new, user_id)); db.commit()
        flash(f'User {user["username"]} {"locked" if new else "unlocked"}.','success')
    return redirect(url_for('admin_dashboard', tab='users'))

@app.route('/admin/clear_logs', methods=['POST'])
@admin_required
def clear_logs():
    get_db().execute("DELETE FROM attack_logs WHERE org_id=? OR org_id IS NULL",(session['org_id'],))
    get_db().commit()
    flash('Logs cleared.','info')
    return redirect(url_for('admin_dashboard', tab='logs'))

@app.route('/admin/rotate_code', methods=['POST'])
@admin_required
def rotate_code():
    new_code     = request.form.get('new_code','').strip()
    confirm_code = request.form.get('confirm_code','').strip()
    admin_pw     = request.form.get('admin_password','')
    db           = get_db()
    user         = db.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    if not bcrypt.checkpw(admin_pw.encode(), user['password_hash'].encode()):
        flash('Your password is incorrect.','danger')
        return redirect(url_for('admin_dashboard', tab='settings'))
    if len(new_code) < 8:
        flash('Admin Code must be at least 8 characters.','warning')
        return redirect(url_for('admin_dashboard', tab='settings'))
    if new_code != confirm_code:
        flash('Codes do not match.','warning')
        return redirect(url_for('admin_dashboard', tab='settings'))
    code_hash = bcrypt.hashpw(new_code.encode(), bcrypt.gensalt()).decode()
    db.execute("UPDATE organizations SET admin_code_hash=? WHERE id=?",(code_hash, session['org_id'])); db.commit()
    flash('Admin Code rotated successfully.','success')
    return redirect(url_for('admin_dashboard', tab='settings'))

# ── Error handlers ────────────────────────────────────────────────────────────

@app.route('/admin/test_email', methods=['POST'])
@admin_required
def test_email_alert():
    """Send a test alert email to admin — for demo."""
    db    = get_db()
    admin = db.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    org   = db.execute("SELECT * FROM organizations WHERE id=?",(session['org_id'],)).fetchone()
    subject = "🧪 Test Alert — SecurePortal Email Working"
    body = f"""
    <div style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:24px;border:1px solid #333;max-width:520px;">
      <h2 style="color:#22c55e;">✅ Email Alerts Are Working!</h2>
      <p>Hello {admin['full_name'] or admin['username']},</p>
      <p>This is a test email from your SecurePortal admin panel.</p>
      <table style="border-collapse:collapse;width:100%;margin-top:12px;">
        <tr><td style="padding:6px;border:1px solid #333;color:#aaa;">Organization</td>
            <td style="padding:6px;border:1px solid #333;color:#22c55e;">{org['name']}</td></tr>
        <tr><td style="padding:6px;border:1px solid #333;color:#aaa;">Admin</td>
            <td style="padding:6px;border:1px solid #333;">{admin['username']}</td></tr>
        <tr><td style="padding:6px;border:1px solid #333;color:#aaa;">Time</td>
            <td style="padding:6px;border:1px solid #333;">{time.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
      </table>
      <p style="margin-top:16px;color:#aaa;">Real alerts send automatically when attacks are detected.</p>
      <p style="color:#555;font-size:11px;">Secure Student Portal — 23CSE313</p>
    </div>
    """
    ok, err = send_email(admin['email'], subject, body)
    db.execute(
        "INSERT INTO email_logs (org_id,to_addr,subject,status,attack_type) VALUES (?,?,?,?,?)",
        (session['org_id'], admin['email'], subject,
         'sent' if ok else f'failed:{err[:80]}', 'Test Email'))
    db.commit()
    if ok:
        flash(f'✅ Test email sent to {admin["email"]} — check your inbox!','success')
    else:
        flash(f'❌ Email failed: {err[:100]} — check MAIL_SENDER in .env','danger')
    return redirect(url_for('admin_dashboard', tab='logs'))


@app.route('/reply/<int:msg_id>', methods=['POST'])
@login_required
def reply_message(msg_id):
    db     = get_db()
    org_id = session['org_id']
    orig   = db.execute(
        "SELECT * FROM messages WHERE id=? AND org_id=? AND (sender_id=? OR recipient_id=?)",
        (msg_id, org_id, session['user_id'], session['user_id'])).fetchone()
    if not orig:
        flash('Message not found.', 'danger')
        return redirect(url_for('dashboard', tab='messages'))
    body = request.form.get('body','').strip()
    if not body: flash('Reply cannot be empty.','warning'); return redirect(url_for('dashboard', tab='messages'))
    if not check_inputs(body, username=session['username']):
        flash('Malicious content detected.','danger'); return redirect(url_for('dashboard', tab='messages'))
    body         = sanitize(body)
    recipient_id = orig['sender_id'] if orig['sender_id'] != session['user_id'] else orig['recipient_id']
    subject      = ('Re: '+orig['subject']) if not orig['subject'].startswith('Re: ') else orig['subject']
    db.execute("INSERT INTO messages (sender_id,recipient_id,org_id,subject,body,reply_to) VALUES (?,?,?,?,?,?)",
               (session['user_id'], recipient_id, org_id, subject, body, msg_id))
    db.commit()
    flash('Reply sent.','success')
    return redirect(url_for('dashboard', tab='messages'))


@app.route('/admin/reply/<int:msg_id>', methods=['POST'])
@admin_required
def admin_reply_message(msg_id):
    db     = get_db()
    org_id = session['org_id']
    orig   = db.execute("SELECT * FROM messages WHERE id=? AND org_id=?",(msg_id,org_id)).fetchone()
    if not orig:
        flash('Message not found.','danger'); return redirect(url_for('admin_dashboard', tab='messages'))
    body = request.form.get('body','').strip()
    if not body: flash('Reply cannot be empty.','warning'); return redirect(url_for('admin_dashboard', tab='messages'))
    if not check_inputs(body, username=session['username']):
        flash('Malicious content detected.','danger'); return redirect(url_for('admin_dashboard', tab='messages'))
    body         = sanitize(body)
    recipient_id = orig['sender_id'] if orig['sender_id'] != session['user_id'] else orig['recipient_id']
    subject      = ('Re: '+orig['subject']) if not orig['subject'].startswith('Re: ') else orig['subject']
    db.execute("INSERT INTO messages (sender_id,recipient_id,org_id,subject,body,reply_to) VALUES (?,?,?,?,?,?)",
               (session['user_id'], recipient_id, org_id, subject, body, msg_id))
    db.commit()
    flash('Reply sent.','success')
    return redirect(url_for('admin_dashboard', tab='messages'))

@app.errorhandler(404)
def not_found(e): return render_template('error.html', code=404, msg="Page not found."), 404
@app.errorhandler(413)
def too_large(e): flash('File too large. Max 5 MB.','danger'); return redirect(url_for('dashboard', tab='files'))
@app.errorhandler(429)
def rate_limited(e): return render_template('error.html', code=429, msg="Too many requests."), 429

@app.route('/setup-db-now')
def setup_db():
    try:
        init_db()
        return "DB tables created!"
    except Exception as e:
        return f"ERROR: {e}"

SEED_SECRET = os.environ.get('SEED_SECRET', '')

@app.route(f'/seed-{SEED_SECRET}')
def seed_route():
    if not SEED_SECRET:
        return "disabled", 404
    try:
        from seed_data import seed
        seed()
        return "SEED DONE ✅"
    except Exception as e:
        return f"ERROR: {e}"

with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=False)