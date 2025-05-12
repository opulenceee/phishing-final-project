from flask import Flask, render_template, redirect, url_for, request, session
import sqlite3
from datetime import datetime
import re
from flask_login import LoginManager, UserMixin
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests
from dotenv import load_dotenv
import os
import json
from PIL import Image
import pytesseract
from urllib.parse import urlparse

load_dotenv()
app = Flask(__name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'bmp', 'tiff'}


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


app.secret_key = os.getenv('secret_key')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id_, email, password_hash):
        self.id = id_
        self.email = email
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute("SELECT id, email, password_hash FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(*user)
    return None
        

def init_db():
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email_author TEXT,
            email_text TEXT,
            phishing_score INTEGER,
            timestamp TEXT
        )
    ''')

    c.execute ('''CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               email TEXT UNIQUE, 
               password_hash TEXT
               ) 
           ''')
    conn.commit()
    conn.close()

init_db()

def check_virustotal_domain(domain):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            print(f"VirusTotal: Domain '{domain}' not found in database.")
            return False
        elif response.status_code != 200:
            print("VirusTotal error:", response.status_code, response.text)
            return False

        data = response.json()
        # This part checks if any malicious or suspicious engines flagged it
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        print(f"VirusTotal scan results for {domain} ➤ Malicious: {malicious}, Suspicious: {suspicious}")
        return malicious > 0 or suspicious > 0
    except Exception as e:
        print("VirusTotal error:", e)
        return False



def query_llm(email_text):
    prompt = f"""You are a cybersecurity analyst with vast experience in analyzing phishing emails. Analyze the following email and determine whether it is a phishing attempt. If it is, explain why (e.g., suspicious links, urgency, sender impersonation). If it's not phishing, explain why it appears safe.

Email content:
\"\"\"
{email_text}
\"\"\"
"""
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "mistral", "prompt": prompt},
            stream=True,
            timeout=30
        )

        collected = ""
        for line in response.iter_lines():
            if line:
                try:
                    data = json.loads(line.decode('utf-8'))
                    collected += data.get("response", "")
                except json.JSONDecodeError as e:
                    print("JSON parsing error:", e)

        return collected.strip() if collected else "(No AI response)"
    except Exception as e:
        print("LLM Error:", e)
        return "(AI explanation not available - local model not running.)"




def detect_phishing(email_text):
    phishing_score = 0

    # some generic detection rules prior to ai integration
    if "click here" in email_text.lower():
        phishing_score += 20
    if "urgent" in email_text.lower() or "immediately" in email_text.lower():
        phishing_score += 20
    if "password" in email_text.lower() or "account number" in email_text.lower():
        phishing_score += 30
    if "verify your account" in email_text.lower():
        phishing_score += 30
    if "bank" in email_text.lower() and "login" in email_text.lower():
        phishing_score += 20
    if "suspicious activity" in email_text.lower():
        phishing_score += 20

    urls = re.findall(r'(https?://[^\s]+)', email_text)
    for url in urls:
        if "bit.ly" in url or "tinyurl" in url or "shorturl" in url:
            phishing_score  += 20
        if not url.startswith("https://"):
            phishing_score  += 10
    # score should be 100 max.
    phishing_score = min(phishing_score, 100)

    return phishing_score

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        email_author = request.form['email_author']
        email_text = request.form.get('email_text', '').strip()

        if not email_text:
            return render_template('index.html', error="No email content provided. Please enter text or upload an image.")

        sender_domain = email_author.split('@')[-1]
        virustotal_link = f"https://www.virustotal.com/gui/domain/{sender_domain}"
        domain_flagged = check_virustotal_domain(sender_domain)            


        # detect phishing score from content
        phishing_score = detect_phishing(email_text)

        if domain_flagged:
            phishing_score += 50  #  if domain is flagged in virustotal's db, add 50 points to it.
            phishing_score = min(phishing_score, 100)

        # Check sender's past history
        conn = sqlite3.connect('history.db') 
        c = conn.cursor()
        c.execute('''
            SELECT COUNT(*) FROM emails 
            WHERE email_author = ? AND phishing_score >= 70
        ''', (email_author,))
        author_flag_count = c.fetchone()[0]

        if author_flag_count >= 1:
            phishing_score += 20
            phishing_score = min(phishing_score, 100)

        # Generate AI explanation
        ai_explanation = query_llm(email_text)

        # Save to DB
        c.execute('''
            INSERT INTO emails (user_id, email_author, email_text, phishing_score, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            current_user.id,
            email_author,
            email_text,
            phishing_score,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        conn.close()

        # Store for result page
        session['result_data'] = {
            'author': email_author,
            'email': email_text,
            'score': phishing_score,
            'flags': author_flag_count,
            'ai_explanation': ai_explanation,
            'virustotal_flagged': domain_flagged,
            'sender_domain_report': virustotal_link
        }

        return redirect(url_for('result'))

    return render_template('index.html')

@app.route('/result')
@login_required
def result():
    result_data = session.pop('result_data', None)
    if not result_data:
        return redirect(url_for('index'))

    return render_template(
        'result.html',
        author=result_data['author'],
        email=result_data['email'],
        score=result_data['score'],
        author_flag_count=result_data['flags'],
        ai_explanation=result_data['ai_explanation'],
        virustotal_flagged=result_data['virustotal_flagged'],
        domain_report=result_data['sender_domain_report']
    )

@app.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 15
    offset = (page - 1) * per_page
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute('''
        SELECT id, email_author, email_text, phishing_score, timestamp
        FROM emails
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?      
    ''', (current_user.id, per_page, offset))
    emails = c.fetchall()

    c.execute('SELECT COUNT(*) FROM emails where user_id = ?', (current_user.id,))
    total = c.fetchone()[0]
    conn.close()

    total_pages = (total + per_page - 1) // per_page
    return render_template('history.html', history=emails, page=page, total_pages=total_pages)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        conn = sqlite3.connect('history.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hashed_pw))
            conn.commit()
        except sqlite3.IntegrityError:
            return "User already exists"
        conn.close()
        return redirect('/login')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('history.db')
        c = conn.cursor()
        c.execute ("SELECT id, email, password_hash FROM users WHERE email =?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            login_user(User(*user))
            return redirect('/')
        else:
            return "Invalid Credentials"
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')
if __name__ == '__main__':
    app.run(debug=True)

