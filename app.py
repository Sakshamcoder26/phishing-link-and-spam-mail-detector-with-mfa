from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
import pyotp
import qrcode
import io
import base64
import re
from urllib.parse import urlparse
from email_validator import validate_email, EmailNotValidError
from datetime import datetime, timedelta
import hashlib 
import requests
import secrets
import string
import csv  # NEW: For generating Audit Reports

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_this'

# --- CONFIGURATION ---
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)

# --- GLOBAL VARIABLES ---
SYSTEM_MESSAGE = None

# --- DATABASE (Mock) ---
users = {
    'admin': {
        'password': '123',
        'email': 'admin@secure.com',
        'role': 'admin',
        'mfa_enabled': False,
        'mfa_secret': None,
        'logs': [],
        'banned': False,
        'failed_attempts': 0,
        'lockout_time': None
    }
}

# --- HELPER FUNCTIONS ---
def generate_strong_password():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for i in range(16))

def is_password_pwned(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code != 200: return 0
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix: return int(count)
        return 0
    except: return 0

def check_phishing(url):
    score = 0
    logs = []
    if re.match(r"^(http|https)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        score += 30; logs.append("⚠️ Suspicious: Uses IP address.")
    if len(url) > 75:
        score += 20; logs.append("⚠️ Suspicious: URL is very long.")
    if "@" in url:
        score += 25; logs.append("🚫 High Risk: Contains '@' symbol.")
    if any(k in url.lower() for k in ['login', 'verify', 'update', 'banking']) and "google.com" not in url:
        score += 15; logs.append("⚠️ Notice: Sensitive keywords found.")
    
    if score >= 40: return "PHISHING DETECTED", "high", logs
    elif score >= 20: return "SUSPICIOUS", "medium", logs
    else: return "SAFE", "low", ["✅ URL looks clean."]

def check_email_risk(email):
    try:
        v = validate_email(email, check_deliverability=False)
        email = v.email
    except EmailNotValidError as e: return "INVALID SYNTAX", "high", [str(e)]
    
    domain = email.split('@')[1]
    if domain in ['tempmail.com', '10minutemail.com', 'yopmail.com']:
        return "DISPOSABLE EMAIL", "high", ["🚫 Known temporary email provider."]
    return "VALID", "low", ["✅ Email domain looks standard."]

def complete_login(username):
    session['username'] = username
    session['last_active'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'ip': request.remote_addr}
    users[username]['logs'].insert(0, log_entry)
    users[username]['logs'] = users[username]['logs'][:5]

# --- SESSION TIMEOUT ---
@app.before_request
def check_session_timeout():
    session.permanent = True
    if request.endpoint in ['static', 'login', 'logout', 'register']: return
    if 'username' in session:
        now = datetime.now()
        last_active = session.get('last_active')
        if last_active:
            last_time = datetime.strptime(last_active, "%Y-%m-%d %H:%M:%S")
            if now - last_time > timedelta(minutes=1):
                session.clear()
                flash("Session expired due to inactivity. Please login again.", "error")
                return redirect(url_for('login'))
        session['last_active'] = now.strftime("%Y-%m-%d %H:%M:%S")

# --- ROUTES ---
@app.route('/')
def home():
    return redirect(url_for('dashboard')) if 'username' in session else redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if username in users:
            flash("Username exists!", "error")
        else:
            users[username] = {
                'password': password, 'email': email, 'role': 'user', 
                'mfa_enabled': False, 'mfa_secret': None, 'logs': [], 
                'banned': False, 'failed_attempts': 0, 'lockout_time': None
            }
            flash("Account created! Please login.", "success")
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user:
            if user.get('lockout_time') and datetime.now() < user['lockout_time']:
                remaining = (user['lockout_time'] - datetime.now()).seconds
                flash(f"Account locked. Try again in {remaining} s.", "error")
                return render_template('login.html')
            if user['password'] == password:
                if user.get('banned'):
                    flash("Account SUSPENDED.", "error")
                    return redirect(url_for('login'))
                user['failed_attempts'] = 0; user['lockout_time'] = None
                session['pre_2fa_username'] = username
                if user['mfa_enabled']: return redirect(url_for('verify_2fa'))
                complete_login(username)
                return redirect(url_for('dashboard'))
            else:
                user['failed_attempts'] += 1
                if user['failed_attempts'] >= 5:
                    user['lockout_time'] = datetime.now() + timedelta(minutes=2)
                    flash("⚠️ Account locked for 2 minutes.", "error")
                else:
                    flash(f"Invalid credentials. {5-user['failed_attempts']} attempts left.", "error")
        else:
            flash("Invalid credentials", "error")
    return render_template('login.html')

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_username' not in session: return redirect(url_for('login'))
    if request.method == 'POST':
        otp = request.form['otp']
        username = session['pre_2fa_username']
        if pyotp.TOTP(users[username]['mfa_secret']).verify(otp):
            session.pop('pre_2fa_username', None)
            complete_login(username)
            return redirect(url_for('dashboard'))
        flash("Invalid OTP", "error")
    return render_template('verify_2fa.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session: return redirect(url_for('login'))
    user = users[session['username']]
    if user['role'] == 'admin': return redirect(url_for('admin_panel'))

    qr_code = None; url_result = None; email_result = None; pwd_result = None

    if not user['mfa_enabled']:
        if not user.get('temp_secret'): user['temp_secret'] = pyotp.random_base32()
        uri = pyotp.TOTP(user['temp_secret']).provisioning_uri(name=user['email'], issuer_name="SecureFlask")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf)
        qr_code = base64.b64encode(buf.getvalue()).decode('utf-8')

    if request.method == 'POST':
        if 'check_url' in request.form:
            url_result = check_phishing(request.form['url_input'])
            url_result = {'input': request.form['url_input'], 'status': url_result[0], 'risk': url_result[1], 'logs': url_result[2]}
        elif 'check_email' in request.form:
            email_result = check_email_risk(request.form['email_input'])
            email_result = {'input': request.form['email_input'], 'status': email_result[0], 'risk': email_result[1], 'logs': email_result[2]}
        elif 'check_password' in request.form:
            pwd = request.form['pwd_input']
            leaks = is_password_pwned(pwd)
            if leaks > 0:
                suggestion = generate_strong_password()
                pwd_result = {'status': f"⚠️ LEAKED {leaks} TIMES", 'risk': 'high', 'logs': ["This password appears in known data breaches."], 'suggestion': suggestion}
            else:
                pwd_result = {'status': "✅ SAFE (No Leaks)", 'risk': 'low', 'logs': ["This password has not been found in public breaches."]}

    return render_template('dashboard.html', user=user, qr_code=qr_code, url_result=url_result, email_result=email_result, pwd_result=pwd_result, sys_msg=SYSTEM_MESSAGE)

@app.route('/admin')
def admin_panel():
    if 'username' not in session: return redirect(url_for('login'))
    if users[session['username']]['role'] != 'admin': return redirect(url_for('dashboard'))
    return render_template('admin_panel.html', all_users=users, current_user=users[session['username']], sys_msg=SYSTEM_MESSAGE)

# --- NEW: EXPORT AUDIT REPORT (CSV) ---
@app.route('/admin/export_audit')
def export_audit():
    if session.get('username') != 'admin': return redirect(url_for('login'))
    
    # Generate CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Add Header
    writer.writerow(['Username', 'Email', 'Role', 'Status', 'MFA Enabled', 'Last Login Time', 'Last Login IP'])
    
    # Add Data Rows
    for name, info in users.items():
        last_log = info['logs'][0] if info['logs'] else {'time': 'Never', 'ip': 'N/A'}
        status = "BANNED" if info.get('banned') else "Active"
        writer.writerow([name, info['email'], info['role'], status, info['mfa_enabled'], last_log['time'], last_log['ip']])
    
    # Create Response
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=security_audit_report.csv"}
    )

@app.route('/enable_mfa', methods=['POST'])
def enable_mfa():
    otp = request.form['otp']; user = users[session['username']]
    if pyotp.TOTP(user['temp_secret']).verify(otp):
        user['mfa_secret'] = user['temp_secret']; user['mfa_enabled'] = True
        flash("MFA Enabled!", "success")
    else: flash("Invalid Code", "error")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/admin/ban/<username>')
def ban_user(username):
    if session.get('username') == 'admin' and username in users and username != 'admin':
        users[username]['banned'] = not users[username].get('banned', False)
        flash(f"Status changed for {username}", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete/<username>')
def delete_user(username):
    if session.get('username') == 'admin' and username in users and username != 'admin':
        del users[username]; flash(f"Deleted {username}", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/broadcast', methods=['POST'])
def send_broadcast():
    if session.get('username') != 'admin': return redirect(url_for('login'))
    global SYSTEM_MESSAGE
    msg = request.form.get('message')
    SYSTEM_MESSAGE = msg if msg else None
    flash("Broadcast Updated", "success")
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(debug=True)