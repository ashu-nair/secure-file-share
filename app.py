from flask import Flask, render_template, request, send_file, redirect, url_for
import os
import io

import time 
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet 
import boto3
import sqlite3 # New: Import SQLite
from contextlib import contextmanager # New: Helper for database connection
import threading
import secrets
from datetime import datetime, timedelta
from flask import flash
import requests

ENCRYPTION_KEY_FILE = "encryption.key"

def load_or_create_encryption_key():
    global ENCRYPTION_KEY, CIPHER
    # try env first
    env_key = os.getenv("ENCRYPTION_KEY")
    if env_key:
        ENCRYPTION_KEY = env_key.encode()
    elif os.path.exists(ENCRYPTION_KEY_FILE):
        ENCRYPTION_KEY = open(ENCRYPTION_KEY_FILE, "rb").read().strip()
    else:
        ENCRYPTION_KEY = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, "wb") as f:
            f.write(ENCRYPTION_KEY)
    CIPHER = Fernet(ENCRYPTION_KEY)
    print("🔑 Using encryption key from", "ENV" if env_key else ENCRYPTION_KEY_FILE)


# --- 1. AWS S3 Configuration (Existing) ---
AWS_ACCESS_KEY_ID = None
AWS_SECRET_ACCESS_KEY = None
S3_BUCKET_NAME = None
AWS_REGION = None
s3_client = None
DATABASE_FILE = '/app/data/file_metadata.db'
ENCRYPTION_KEY = None
CIPHER = None

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")


def initialize_app_secrets():
    """Initialize application secrets from environment variables."""
    global AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET_NAME, AWS_REGION, s3_client

    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
    AWS_REGION = os.getenv('AWS_REGION')

    # Validation
    if not all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET_NAME, AWS_REGION]):
        print("⚠️  Missing required AWS configuration. Please set these environment variables:")
        print("   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET_NAME, AWS_REGION")
        exit(1)

    try:
        # Initialize S3 client
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )
        s3_client.head_bucket(Bucket=S3_BUCKET_NAME)
        print(f"☁️  AWS S3 Client Initialized and connected to '{S3_BUCKET_NAME}'.")
    except Exception as e:
        s3_client = None
        print(f"⚠️  Warning: Could not initialize S3 client. Uploads/Downloads may fail. Error: {e}")

    # Initialize encryption key
    load_or_create_encryption_key()


# --- 3. SQLite Persistence Setup (New) ---

@contextmanager
def get_db_connection():
    """Context manager for safely handling SQLite connections."""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db_connection() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS shared_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at REAL NOT NULL,
            FOREIGN KEY(file_id) REFERENCES files(id)
         );
""")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                original_filename TEXT NOT NULL,
                disk_name TEXT UNIQUE NOT NULL,
                uploaded_at REAL NOT NULL,
                owner_id TEXT DEFAULT 'anonymous'
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        """)
        conn.commit()
    print(f"💾 SQLite Database '{DATABASE_FILE}' initialized and ready.")


# Initialize the database when the application starts
with app.app_context():
    init_db()
# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@app.template_filter('datetime')
def format_datetime(value):
    """Convert a timestamp (float or int) to readable date string."""
    try:
        dt = datetime.fromtimestamp(float(value))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "N/A"

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row:
            return User(row["id"], row["username"], row["password_hash"])
    return None

# --- 4. Flask Routes Updated for Persistence ---

@app.route('/')
@login_required
def index():
    # Fetch file metadata from the database instead of in-memory dictionary
    with get_db_connection() as conn:
        files_cursor = conn.execute(
            "SELECT * FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC",
            (current_user.username,)
        ).fetchall()
    files_metadata = [dict(row) for row in files_cursor]
    return render_template('index.html', files=files_metadata)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return "Missing username/password", 400
        password_hash = generate_password_hash(password)
        try:
            with get_db_connection() as conn:
                conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                             (username, password_hash))
                conn.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return "Username already exists", 400
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        with get_db_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            user = User(row["id"], row["username"], row["password_hash"])
            login_user(user)
            return redirect(url_for("index"))
        return "Invalid username or password", 401
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

def scan_with_virustotal(file_data, filename):
    """Optimized VirusTotal scanning with better polling + timeout handling."""
    api_key = os.getenv("VT_API_KEY") or os.environ.get("VT_API_KEY")

    if not api_key:
        print("⚠️ No VirusTotal API key found — skipping scan.")
        return True, "Scan skipped (no API key configured)."

    vt_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}

    try:
        # Step 1: Upload file for scanning
        files = {"file": (filename, file_data)}
        response = requests.post(vt_url, headers=headers, files=files)

        if response.status_code not in (200, 202):
            return True, f"⚠️ VirusTotal error ({response.status_code}): {response.text}"

        analysis_url = response.json()["data"]["links"]["self"]

        # Step 2: Poll for results
        max_wait_seconds = 45   # free tier needs more time
        poll_interval = 2       # check every 2 sec
        waited = 0

        while waited < max_wait_seconds:
            analysis = requests.get(analysis_url, headers=headers).json()
            status = analysis["data"]["attributes"]["status"]

            if status == "completed":
                stats = analysis["data"]["attributes"]["stats"]
                malicious = stats.get("malicious", 0)

                if malicious > 0:
                    return False, f"🚨 VirusTotal detected: {malicious} engines flagged this file!"
                return True, "✅ Virus scan complete — file is clean."

            time.sleep(poll_interval)
            waited += poll_interval

        # If not completed within allowed time
        return True, "⚠️ VirusTotal scan took too long; upload allowed but results unavailable."

    except Exception as e:
        print(f"[VirusTotal Error] {e}")
        return True, f"⚠️ Scan failed — {e}"

def background_virus_scan(file_id, file_data, filename, owner):
    """Runs VirusTotal scan in background after upload."""
    ok, msg = scan_with_virustotal(file_data, filename)

    if ok:
        print(f"[VT-CLEAN] {filename} → {msg}")
        return

    # If malicious → delete file from S3 + DB
    print(f"[VT-DETECTED] {filename} — removing file!")

    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not row:
        return

    s3_key = row["disk_name"]

    # delete from S3
    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
    except:
        pass

    # delete from DB
    with get_db_connection() as conn:
        conn.execute("DELETE FROM shared_links WHERE file_id = ?", (file_id,))
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()

    print(f"[VT-DELETED] {filename} removed due to virus detection.")

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if s3_client is None:
        return "S3 Client initialization failed. Cannot upload.", 503

    # multiple files
    files = request.files.getlist("files")

    if not files or files[0].filename == "":
        flash("No files selected.", "error")
        return redirect(url_for("index"))

    for file in files:
        original_filename = secure_filename(file.filename)
        unique_file_id = str(time.time()).replace('.', '') + secrets.token_hex(4)
        s3_key = unique_file_id + ".enc"

        file_data = file.read()

        # Start background VT scan (non-blocking)
        threading.Thread(
            target=background_virus_scan,
            args=(unique_file_id, file_data, original_filename, current_user.username)
        ).start()

        # Encrypt file
        encrypted_data = CIPHER.encrypt(file_data)
        encrypted_buffer = io.BytesIO(encrypted_data)

        # Upload to S3
        try:
            s3_client.upload_fileobj(
                encrypted_buffer,
                S3_BUCKET_NAME,
                s3_key
            )
        except Exception as e:
            flash(f"S3 upload failed for {original_filename}: {e}", "error")
            continue

        # Save metadata
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO files (id, original_filename, disk_name, uploaded_at, owner_id)
                VALUES (?, ?, ?, ?, ?)
            """, (unique_file_id, original_filename, s3_key, time.time(), current_user.username))
            conn.commit()

    flash("✅ All files uploaded! Virus scan running in background.", "success")
    return redirect(url_for('index'))

    
@app.route('/download/<file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    if s3_client is None:
        return "S3 Client initialization failed. Cannot download.", 503
        
    # NEW: Retrieve file metadata from SQLite
    with get_db_connection() as conn:
        file_metadata = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        
    if not file_metadata:
        return "File metadata not found in database.", 404
    
    # Convert Row object to dictionary for consistent access
    file_metadata = dict(file_metadata)

    if file_metadata.get("owner_id") != current_user.username:
        return "Unauthorized access to this file.", 403
    
    s3_key = file_metadata['disk_name']
    original_filename = file_metadata['original_filename']
    
    try:
        s3_object = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        encrypted_data = s3_object['Body'].read()

        decrypted_data = CIPHER.decrypt(encrypted_data)
        
        file_buffer = io.BytesIO(decrypted_data)
        
        response = send_file(
            file_buffer, 
            as_attachment=True, 
            download_name=original_filename, 
            mimetype='application/octet-stream' 
        )
        
        return response

    except Exception as e:
        # Catch decryption errors, S3 errors, etc.
        print(f"Error during file download/decryption: {e}")
        return f"An unexpected error occurred during S3 or file handling: {e}", 500
    
@app.route("/share/<file_id>", methods=["POST"])
@login_required
def share_file(file_id):
    # Get duration from form (in minutes)
    duration = int(request.form.get("duration", 10))  # default 10 minutes

    with get_db_connection() as conn:
        file_metadata = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if not file_metadata:
            return "❌ File not found.", 404

        if file_metadata["owner_id"] != current_user.username:
            return "🚫 Unauthorized access.", 403

        # Generate unique token + expiry time
        token = secrets.token_urlsafe(16)
        expires_at = time.time() + (duration * 60)

        # Save to shared_links table
        conn.execute(
            "INSERT INTO shared_links (file_id, token, expires_at) VALUES (?, ?, ?)",
            (file_id, token, expires_at)
        )
        conn.commit()

    # Generate full link (e.g., http://127.0.0.1:5000/shared/abc123)
    share_link = url_for("shared_download", token=token, _external=True)
    flash(f"✅ Shareable link (valid for {duration} minutes): {share_link}", "success")
    return redirect(url_for('index'))

@app.route("/shared/<token>")
def shared_download(token):
    with get_db_connection() as conn:
        shared_row = conn.execute("SELECT * FROM shared_links WHERE token = ?", (token,)).fetchone()
        if not shared_row:
            return "❌ Invalid or expired link.", 404
        if time.time() > shared_row["expires_at"]:
            conn.execute("DELETE FROM shared_links WHERE token = ?", (token,))
            conn.commit()
            return "⏰ This link has expired.", 403
        file_row = conn.execute("SELECT * FROM files WHERE id = ?", (shared_row["file_id"],)).fetchone()

    # Download encrypted file from S3
    s3_obj = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=file_row["disk_name"])
    encrypted_data = s3_obj["Body"].read()

    # Decrypt
    decrypted_data = CIPHER.decrypt(encrypted_data)

    # Send decrypted file
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file_row["original_filename"]
    )

if __name__ == '__main__':
    initialize_app_secrets()
    app.config['S3_BUCKET_NAME'] = S3_BUCKET_NAME 
    with app.app_context():
         init_db()
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)

@app.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    if s3_client is None:
        return "S3 Client initialization failed. Cannot delete.", 503

    # Fetch metadata
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()

    if not row:
        flash("❌ File not found.", "error")
        return redirect(url_for("index"))

    if row["owner_id"] != current_user.username:
        flash("🚫 Unauthorized action.", "error")
        return redirect(url_for("index"))

    s3_key = row["disk_name"]

    # 1️⃣ Delete from S3 safely
    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
    except Exception as e:
        print(f"Error deleting S3 object: {e}")
        flash("⚠️ Could not delete file from storage.", "error")
        return redirect(url_for("index"))

    # 2️⃣ Delete metadata + shared links
    try:
        with get_db_connection() as conn:
            conn.execute("DELETE FROM shared_links WHERE file_id = ?", (file_id,))
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
        flash("🗑️ File deleted successfully.", "success")
    except Exception as e:
        print(f"Error deleting database metadata: {e}")
        flash("⚠️ File removed from S3 but metadata deletion failed.", "error")

    return redirect(url_for("index"))
