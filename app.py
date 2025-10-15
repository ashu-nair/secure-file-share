from flask import Flask, render_template, request, send_file, redirect, url_for
import os
import io
import json
import time 
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet 
import boto3
import sqlite3 # New: Import SQLite
from contextlib import contextmanager # New: Helper for database connection
import getpass

# --- 1. AWS S3 Configuration (Existing) ---
AWS_ACCESS_KEY_ID = None
AWS_SECRET_ACCESS_KEY = None
S3_BUCKET_NAME = None
AWS_REGION = None
s3_client = None
DATABASE_FILE = 'file_metadata.db'
ENCRYPTION_KEY = None
CIPHER = None

app = Flask(__name__)

def initialize_app_secrets():
    """Initialize application secrets from environment or user input."""
    global AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3_BUCKET_NAME, AWS_REGION
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    if not AWS_ACCESS_KEY_ID:
        print("--- AWS Configuration Required ---\n\n")
        AWS_ACCESS_KEY_ID = input("Enter AWS Access Key ID: ")

    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    if not AWS_SECRET_ACCESS_KEY:
        # Use getpass.getpass() to securely read the secret key without displaying it
        AWS_SECRET_ACCESS_KEY = getpass.getpass("Enter AWS Secret Access Key: ")

    S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
    if not S3_BUCKET_NAME:
        S3_BUCKET_NAME = input("Enter S3 Bucket Name: ")

    AWS_REGION = os.getenv('AWS_REGION')
    if not AWS_REGION:
        AWS_REGION = input("Enter AWS Region (e.g., us-east-1): ")

    try:
        s3_client = boto3.client(...)
        s3_client.head_bucket(Bucket=S3_BUCKET_NAME) # <--- THIS VALIDATES THE CONNECTION
        print(f"☁️ AWS S3 Client Initialized and connected to '{S3_BUCKET_NAME}'.")

    except Exception as e:
        s3_client = None
        print(f"⚠️ Warning: Could not initialize S3 client. Uploads/Downloads will fail. Error: {e}")

    # --- 2. Encryption Setup (Existing) ---
    ENCRYPTION_KEY = Fernet.generate_key()
    CIPHER = Fernet(ENCRYPTION_KEY)
    print(f"🔑 Encryption Key: {ENCRYPTION_KEY.decode()}")

    # FILE_DATABASE = {} # Removed: Replaced with SQLite

    app.config['S3_BUCKET_NAME'] = S3_BUCKET_NAME

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
    """Initializes the database and creates the files table if it doesn't exist."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                original_filename TEXT NOT NULL,
                disk_name TEXT UNIQUE NOT NULL,
                uploaded_at REAL NOT NULL,
                owner_id TEXT DEFAULT 'anonymous'
            );
        """)
        conn.commit()
    print(f"💾 SQLite Database '{DATABASE_FILE}' initialized and ready.")

# Initialize the database when the application starts
with app.app_context():
    init_db()

# --- 4. Flask Routes Updated for Persistence ---

@app.route('/')
def index():
    # Fetch file metadata from the database instead of in-memory dictionary
    with get_db_connection() as conn:
        # Order by uploaded_at descending
        files_cursor = conn.execute("SELECT * FROM files ORDER BY uploaded_at DESC").fetchall()
        # Convert sqlite.Row objects to dictionary list
        files_metadata = [dict(row) for row in files_cursor] 

    print("\n--- CURRENT FILE DATABASE CONTENTS (METADATA) ---")
    print(json.dumps(files_metadata, indent=4))
    print("--------------------------------------------------\n")

    # The HTML template will now receive data from the persistent database
    return render_template('index.html', files=files_metadata)

@app.route('/upload', methods=['POST'])
def upload_file():
    if s3_client is None:
        return "S3 Client initialization failed. Cannot upload.", 503
        
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    
    if file.filename == '':
        return 'No selected file', 400

    if file:
        original_filename = secure_filename(file.filename)
        unique_file_id = str(time.time()).replace('.', '') 
        s3_key = unique_file_id + ".enc"
        
        file_data = file.read()

        try:
            encrypted_data = CIPHER.encrypt(file_data)
        except Exception as e:
            return f"Encryption failed: {e}", 500

        encrypted_buffer = io.BytesIO(encrypted_data)
        
        try:
            s3_client.upload_fileobj(
                encrypted_buffer,
                S3_BUCKET_NAME,
                s3_key
            )
        except Exception as e:
            return f"S3 Upload failed: {e}", 500

        # NEW: Save metadata to SQLite instead of in-memory dictionary
        try:
            with get_db_connection() as conn:
                conn.execute("""
                    INSERT INTO files (id, original_filename, disk_name, uploaded_at)
                    VALUES (?, ?, ?, ?)
                """, (unique_file_id, original_filename, s3_key, time.time()))
                conn.commit()
        except Exception as e:
             # Important: Log and potentially delete the S3 file if metadata save fails
            print(f"CRITICAL: Failed to save metadata to SQLite: {e}")
            return f"Metadata saving failed. File uploaded but lost track of: {original_filename}", 500
                
        # Redirect back to the index page instead of just showing a message
        return redirect(url_for('index'))
    
@app.route('/download/<file_id>', methods=['GET'])
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

if __name__ == '__main__':
    initialize_app_secrets()
    app.config['S3_BUCKET_NAME'] = S3_BUCKET_NAME 
    with app.app_context():
         init_db()
    app.run(debug=True, use_reloader=False)
