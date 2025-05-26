from flask import Flask, render_template, redirect, url_for, request, session, flash
import sqlite3
from datetime import datetime
import re
from flask_login import LoginManager, UserMixin
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from dotenv import load_dotenv
import os
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import logging
from logging.handlers import TimedRotatingFileHandler
import time
import imghdr
from publicsuffix2 import get_sld
import pyotp
import qrcode
import io
import base64

LOGGING_ATTEMPT_LIMIT = 3
LOCKOUT_DURATION_SECONDS = 300 # 5 minutes lockout after 3 failed attempts
PHISHING_SCORE_GENERIC_CLICK = 20
PHISHING_SCORE_URGENCY = 20
PHISHING_SCORE_CREDENTIALS = 30
PHISHING_SCORE_VERIFY_ACCOUNT = 30
PHISHING_SCORE_BANK_LOGIN = 20
PHISHING_SCORE_SUSPICIOUS_ACTIVITY = 20
PHISHING_SCORE_URL_SHORTENER = 20
PHISHING_SCORE_HTTP_URL = 10
PHISHING_SCORE_VIRUSTOTAL_FLAGGED_DOMAIN = 50
PHISHING_SCORE_PREVIOUSLY_FLAGGED_AUTHOR = 20
MAX_PHISHING_SCORE = 100
MIN_PHISHING_SCORE_FOR_AUTHOR_FLAG = 70
PHISHING_SCORE_SUSPICIOUS_TLD = 10
PHISHING_SCORE_FREE_HOSTING = 10
HISTORY_ITEMS_PER_PAGE = 15

SUSPICIOUS_TLDS = {"site", "shop", "xyz", "run"}
FREE_HOSTING_DOMAINS = {"vercel.app", "netlify.app", "github.io"}
WHITELIST_DOMAINS = {"gmail.com", "outlook.com", "yahoo.com", "amazon.com", "walla.co.il", "microsoft.com"}

def setup_logger():
    if not os.path.exists('logs'):
        os.makedirs('logs')

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    rotating_handler = TimedRotatingFileHandler('logs/app.log', when='midnight', interval=1, backupCount=7, encoding='utf-8')
    rotating_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    rotating_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(rotating_handler)
        logger.addHandler(console_handler)

    return logger

logger = setup_logger()

load_dotenv()
app = Flask(__name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'bmp', 'tiff'}

def allowed_file(filename, file_stream):
    extension = filename.rsplit('.', 1)[1].lower()
    type_check = imghdr.what(file_stream)
    return extension in ALLOWED_EXTENSIONS and type_check in ALLOWED_EXTENSIONS

USE_LOCAL_AI = os.getenv('USE_LOCAL_AI', 'false').lower() == 'true'
logger.info(f"USE_LOCAL_AI setting: {USE_LOCAL_AI}")

secret_key = os.getenv('secret_key')
if not secret_key:
    raise ValueError("SECRET_KEY is not set in environment variables")
app.secret_key = secret_key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id_, email, password_hash, mfa_secret=None, mfa_enabled=False):
        self.id = id_
        self.email = email
        self.password_hash = password_hash
        self.mfa_secret = mfa_secret
        self.mfa_enabled = mfa_enabled == 1  
@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT id, email, password_hash, mfa_secret, mfa_enabled FROM users WHERE id = ?", (user_id,))
        user_data = c.fetchone()
        if user_data:
            return User(*user_data)
        return None
    finally:
        conn.close()

def get_db_connection():
    conn = sqlite3.connect('history.db')
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email_author TEXT,
            email_text TEXT,
            phishing_score INTEGER,
            timestamp TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT,
        mfa_secret TEXT,
        mfa_enabled BOOLEAN DEFAULT 0
    )''')
    
    conn.commit()
    conn.close()

init_db()

def is_valid_email(email):
    return re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email) is not None

def validate_password(password):
    """Validates a password and returns a tuple of (is_valid, error_message)"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    
    if not has_letter:
        return False, "Password must contain at least one letter"
    if not has_digit:
        return False, "Password must contain at least one number"
    if not (has_upper and has_lower):
        return False, "Password must contain both uppercase and lowercase letters"
        
    return True, None

def is_valid_password(password):
    is_valid, _ = validate_password(password)
    return is_valid

def generate_mfa_qr(email, secret):
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(email, issuer_name="Phishing Detector")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer)
    return base64.b64encode(buffer.getvalue()).decode()

def verify_mfa_code(secret, code):
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def generate_mfa_secret():
    return pyotp.random_base32()

def check_virustotal_domain(domain):
    if domain.lower() in WHITELIST_DOMAINS:
        return False

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            logging.info(f"VirusTotal: Domain '{domain}' not found in database.")
            return False
        elif response.status_code != 200:
            logging.error("VirusTotal error:", response.status_code, response.text)
            return False

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        logger.info(f"Checking VirusTotal for domain: {domain} ➤ Malicious: {malicious}, Suspicious: {suspicious}")

        return malicious > 0 or suspicious > 0
    except Exception as e:
        logging.error("VirusTotal error:", e)
        return False

def extract_urls(email_text):
    soup = BeautifulSoup(email_text, 'html.parser')
    return [a['href'] for a in soup.find_all('a', href=True)]

def extract_root_domain(url):
    try:
        parsed = urlparse(url)
        return get_sld(parsed.netloc.lower())
    except Exception as e:
        logger.warning(f"Failed to extract root domain from {url}: {e}")
        return ""

def detect_phishing(email_text):
    phishing_score = 0
    explanations = []

    if "click here" in email_text.lower():
        phishing_score += PHISHING_SCORE_GENERIC_CLICK
        explanations.append("Contains generic 'click here' call-to-action")
        logging.debug("Phrase match: click here")
    if "urgent" in email_text.lower() or "immediately" in email_text.lower():
        phishing_score += PHISHING_SCORE_URGENCY
        explanations.append("Uses urgency or pressure tactics")
        logging.debug("Phrase match: urgent")
    if "password" in email_text.lower() or "account number" in email_text.lower():
        phishing_score += PHISHING_SCORE_CREDENTIALS
        explanations.append("Requests sensitive credentials or account information")
        logging.debug("Phrase match: password")
    if "verify your account" in email_text.lower():
        phishing_score += PHISHING_SCORE_VERIFY_ACCOUNT
        explanations.append("Asks for account verification")
        logging.debug("Phrase match: verify your account")
    if "bank" in email_text.lower() and "login" in email_text.lower():
        phishing_score += PHISHING_SCORE_BANK_LOGIN
        explanations.append("Contains banking/login related content")
        logging.debug("Phrase match: bank login")
    if "suspicious activity" in email_text.lower():
        phishing_score += PHISHING_SCORE_SUSPICIOUS_ACTIVITY
        explanations.append("Claims suspicious account activity")
        logging.debug("Phrase match: suspicious activity")

    urls = extract_urls(email_text)
    for url in urls:
        domain = extract_root_domain(url)
        parsed = urlparse(url)

        tld = domain.split('.')[-1]
        if tld in SUSPICIOUS_TLDS:
            phishing_score += PHISHING_SCORE_SUSPICIOUS_TLD
            explanations.append(f"Uses suspicious TLD: .{tld}")
            logger.debug(f"Suspicious TLD detected: {domain}")
        
        if domain in FREE_HOSTING_DOMAINS:
            phishing_score += PHISHING_SCORE_FREE_HOSTING
            explanations.append(f"Uses free hosting domain: {domain}")
            logger.debug(f"Free hosting domain detected: {domain}")

        if any(shortener in domain for shortener in ["bit.ly", "tinyurl", "shorturl", "t.co", "goo.gl", "ow.ly", "bitly.com"]):
            phishing_score += PHISHING_SCORE_URL_SHORTENER
            explanations.append("Contains URL shortener links")
            logger.debug(f"Shortener domain detected: {domain}")

        if parsed.scheme != "https":
            phishing_score += PHISHING_SCORE_HTTP_URL
            explanations.append("Contains non-HTTPS URLs")
            logger.debug(f"No SSL URL detected: {url}")

        if phishing_score:
            logger.info(f"Phishing score after processing URL {url}: (Domain: {domain}): {phishing_score})")

    return min(phishing_score, MAX_PHISHING_SCORE), explanations

def sanitize_input_for_llm(text):
    return text.replace('"""', '\"\"').replace('{', '').replace('}', '').replace('#', '').replace('---', '')

def query_llm(email_text, email_author):
    if not USE_LOCAL_AI:
        return "(AI explanation disabled - local model not configured)"
    safe_email_text = sanitize_input_for_llm(email_text)

    prompt = f"""You are a cybersecurity threat analyst.

Your task is to determine whether the following email is a phishing attempt. Focus on red flags such as:
- Urgency or scare tactics
- Requests to click links or log in
- Reward offers or financial promises
- Vague or missing sender info
- Unusual domain names or spoofed branding
- Suspicious links or attachments
- Poor grammar or spelling
- Unsolicited attachments
- Suspicious sender email addresses
- Requests for sensitive information
- Threats or warnings about account security

Respond ONLY in the following format:

Phishing: Yes or No  
Explanation:
- **Suspicious sender email address**: The sender's email address is not associated with a well-known and trusted bank.
- **Request for sensitive information**: The email asks the recipient to reset their password through a provided link.
- **Suspicious link**: The link provided in the email contains suspicious characters or domains.
- **Urgency or scare tactics**: The message implies immediate action is needed.

Sender: {email_author}

Email:
\"\"\" 
{safe_email_text}
\"\"\"
"""
    try:
        logger.info("Making request to Ollama API...")
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "mistral", "prompt": prompt},
            stream=True,
            timeout=30
        )
        logger.info(f"Ollama API response status: {response.status_code}")

        collected = ""
        for line in response.iter_lines():
            if line:
                try:
                    data = json.loads(line.decode('utf-8'))
                    collected += data.get("response", "")
                except json.JSONDecodeError as e:
                    logging.error(f"JSON parsing error: {e}, Line: {line}")

        result = collected.strip() if collected else "(No AI response)"
        logger.info(f"Final LLM Response: {result}")
        return result
    except Exception as e:
        logger.error(f"LLM Error: {str(e)}", exc_info=True)
        return "(AI explanation not available - local model not running.)"

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/')
def root():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return redirect(url_for('welcome'))

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        email_text = request.form.get('email_text', '')
        email_author = request.form.get('email_author', '')

        if not email_text or not email_author:
            flash('Please provide both email text and author', 'error')
            return redirect(url_for('index'))

        phishing_score, explanations = detect_phishing(email_text)
        
        conn = get_db_connection()
        c = conn.cursor()
        # checking if sender domain already in DB
        c.execute("""
            SELECT COUNT(*) FROM emails 
            WHERE email_author = ? AND phishing_score >= ?
        """, (email_author, MIN_PHISHING_SCORE_FOR_AUTHOR_FLAG))
        previously_flagged = c.fetchone()[0] > 0
        

        if previously_flagged:
            phishing_score = min(phishing_score + PHISHING_SCORE_PREVIOUSLY_FLAGGED_AUTHOR, MAX_PHISHING_SCORE)
            explanations.append("Sender was previously flagged for suspicious emails")
            logger.warning(f"Author {email_author} was previously flagged for phishing")

        
        urls = extract_urls(email_text)
        for url in urls:
            domain = extract_root_domain(url)
            if check_virustotal_domain(domain):
                phishing_score = min(phishing_score + PHISHING_SCORE_VIRUSTOTAL_FLAGGED_DOMAIN, MAX_PHISHING_SCORE)
                explanations.append(f"Domain {domain} was flagged by VirusTotal")
                logger.warning(f"Domain {domain} was flagged by VirusTotal")

        
        if USE_LOCAL_AI:
            logger.info("USE_LOCAL_AI is True, calling query_llm...")
            ai_explanation = query_llm(email_text, email_author)
            logger.info(f"Got AI explanation: {ai_explanation}")
        else:
            logger.info("USE_LOCAL_AI is False, skipping AI analysis")
            ai_explanation = "AI analysis is currently disabled. Enable local AI to use this feature."
            
        # set score to 100 if AI detects phishing
        if ai_explanation and "Phishing: Yes" in ai_explanation:
            phishing_score = MAX_PHISHING_SCORE
            explanations.append("AI model detected phishing patterns")
            logger.warning("AI model detected phishing patterns in the email")

        c.execute("""
            INSERT INTO emails (user_id, email_author, email_text, phishing_score, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (current_user.id, email_author, email_text, phishing_score, datetime.now().isoformat()))
        conn.commit()

        # check if email is already in DB
        c.execute("""
            SELECT COUNT(*) FROM emails 
            WHERE user_id = ? AND email_text = ?
        """, (current_user.id, email_text))
        duplicate_email = c.fetchone()[0] > 1  # > 1 because we just inserted one
        conn.close()

        session['last_analysis'] = {
            'email_text': email_text,
            'email_author': email_author,
            'phishing_score': phishing_score,
            'explanations': explanations,
            'ai_explanation': ai_explanation,
            'previously_flagged': previously_flagged,
            'duplicate_email': duplicate_email
        }
        return redirect(url_for('result'))

    return render_template('index.html')

@app.route('/result')
@login_required
def result():
    analysis = session.get('last_analysis')
    if not analysis:
        return redirect(url_for('index'))
    
    email_domain = analysis['email_author'].split('@')[-1] if '@' in analysis['email_author'] else ''
    domain_trusted = email_domain.lower() in WHITELIST_DOMAINS
    
    return render_template('result.html', 
                         score=analysis['phishing_score'],
                         email=analysis['email_text'],
                         author=analysis['email_author'],
                         ai_explanation=analysis['ai_explanation'],
                         explanations=analysis['explanations'],
                         domain_trusted=domain_trusted,
                         domain_report=f"https://www.virustotal.com/gui/domain/{email_domain}",
                         previously_flagged=analysis['previously_flagged'],
                         duplicate_email=analysis['duplicate_email'])

@app.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    offset = (page - 1) * HISTORY_ITEMS_PER_PAGE

    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM emails WHERE user_id = ?", (current_user.id,))
    total_items = c.fetchone()[0]
    total_pages = (total_items + HISTORY_ITEMS_PER_PAGE - 1) // HISTORY_ITEMS_PER_PAGE

    c.execute("""
        SELECT email_author, email_text, phishing_score, timestamp 
        FROM emails 
        WHERE user_id = ? 
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """, (current_user.id, HISTORY_ITEMS_PER_PAGE, offset))
    
    history_items = c.fetchall()
    conn.close()

    return render_template('history.html', 
                         history=history_items, 
                         page=page, 
                         total_pages=total_pages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not email or not password or not confirm_password:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('register'))

        if not is_valid_email(email):
            flash('Please enter a valid email address', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))

        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message, 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        if c.fetchone() is not None:
            conn.close()
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        mfa_secret = generate_mfa_secret()
        
        c.execute("""
            INSERT INTO users (email, password_hash, mfa_secret)
            VALUES (?, ?, ?)
        """, (email, generate_password_hash(password), mfa_secret))
        
        user_id = c.lastrowid
        conn.commit()
        conn.close()

        
        user = User(user_id, email, generate_password_hash(password), mfa_secret)
        login_user(user)
        
        session['mfa_setup'] = {
            'secret': mfa_secret,
            'email': email
        }
        
        return redirect(url_for('complete_mfa_setup'))

    return render_template('register.html')

@app.route('/complete-mfa-setup')
def complete_mfa_setup():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
        
    mfa_setup = session.get('mfa_setup')
    if not mfa_setup:
        return redirect(url_for('index'))
        
    qr_code = generate_mfa_qr(mfa_setup['email'], mfa_setup['secret'])
    return render_template('complete_mfa.html', qr_code=qr_code)

@app.route('/verify-initial-mfa', methods=['POST'])
def verify_initial_mfa():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
        
    mfa_setup = session.get('mfa_setup')
    if not mfa_setup:
        return redirect(url_for('index'))
        
    code = request.form.get('code')
    if not code:
        flash('Please enter the verification code', 'error')
        return redirect(url_for('complete_mfa_setup'))
        
    if verify_mfa_code(mfa_setup['secret'], code):
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (current_user.id,))
        conn.commit()
        conn.close()
        
        session.pop('mfa_setup', None)  
        flash('MFA setup complete!', 'success')
        return redirect(url_for('index'))
    else:
        flash('Invalid verification code', 'error')
        return redirect(url_for('complete_mfa_setup'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'partial_login' in session:
            mfa_code = request.form.get('mfa_code')
            if not mfa_code:
                flash('Please enter the verification code', 'error')
                return render_template('login.html', show_mfa=True)

            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT id, email, password_hash, mfa_secret, mfa_enabled FROM users WHERE id = ?", 
                     (session['partial_login']['user_id'],))
            user_data = c.fetchone()
            conn.close()

            if not user_data:
                session.pop('partial_login', None)
                flash('Login session expired. Please try again.', 'error')
                return redirect(url_for('login'))

            user = User(*user_data)
            if verify_mfa_code(user.mfa_secret, mfa_code):
                login_user(user)
                session.pop('partial_login', None)
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                flash('Invalid verification code', 'error')
                return render_template('login.html', show_mfa=True)

        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please provide both email and password', 'error')
            return redirect(url_for('login'))

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, email, password_hash, mfa_secret, mfa_enabled FROM users WHERE email = ?", (email,))
        user_data = c.fetchone()
        conn.close()

        if user_data and check_password_hash(user_data[2], password):
            user = User(*user_data)
            
            session['partial_login'] = {
                'user_id': user.id,
                'email': user.email
            }
            return render_template('login.html', show_mfa=True)
        else:
            flash('Invalid email or password', 'error')

    show_mfa = 'partial_login' in session
    return render_template('login.html', show_mfa=show_mfa)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    app.run(debug=True)

