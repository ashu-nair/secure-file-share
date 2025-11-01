# ☁️ Secure File Sharing System (Cloud + Encryption)

A **secure, cloud-based file sharing platform** built using **Flask**, **AWS S3**, and **Docker**, designed to ensure **end-to-end encryption**, **user authentication**, and **time-limited file sharing links**.  
This project demonstrates **real-world cloud security practices** and is hosted on **AWS EC2** for global access.

---

## 🔒 Overview

The Secure File Sharing System allows users to upload, encrypt, and share files safely.  
Each uploaded file is encrypted locally using AES (via the Fernet cipher) and then uploaded to a private **AWS S3 bucket**.  
Users can share a unique, **time-limited download link**, ensuring only authorized users can access the content.

---

## 🚀 Features

- 🔐 **End-to-End Encryption** — Files are encrypted before upload using Fernet AES.
- ☁️ **AWS S3 Integration** — Secure, scalable cloud storage.
- 👤 **User Authentication** — Register/login system with password hashing.
- ⏳ **Time-Limited Links** — Shared download links automatically expire.
- 🧰 **Dockerized Application** — Easily deployable on any platform.
- 🧑‍💻 **SQLite Database** — Simple and lightweight metadata storage.
- 🌍 **Global Accessibility** — Hosted on AWS EC2 with public access.

---

## 🧠 Tech Stack

| Layer | Technology |
|-------|-------------|
| **Frontend** | HTML, CSS (Flask Templates) |
| **Backend** | Python (Flask) |
| **Database** | SQLite |
| **Cloud** | AWS S3 + EC2 |
| **Containerization** | Docker |
| **Security** | Fernet AES Encryption, JWT Auth, Environment Variables |

---

## ⚙️ Architecture Flow

1. User logs in or registers securely.
2. Files are encrypted locally with Fernet AES.
3. Encrypted files are uploaded to a secure AWS S3 bucket.
4. A **signed, time-limited share link** is generated for access.
5. The recipient can download and decrypt the file before expiration.

---

## 🧩 Setup Instructions

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/secure-file-sharing.git
cd secure-file-sharing
```
2️⃣ Create a .env File
Create a .env file in your project root and add:

```bash
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
S3_BUCKET_NAME=secure-file-sharingproject
AWS_REGION=eu-north-1
ENCRYPTION_KEY=your_generated_fernet_key
FLASK_SECRET_KEY=your_flask_secret
```
🧠 Tip:
Generate your Fernet key in Python:

```bash
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```
Generate Flask secret key:
```bash
import secrets
print(secrets.token_hex(32))
```
3️⃣ Run Locally
```bash
pip install -r requirements.txt
python app.py
```
Access it on:
http://127.0.0.1:5000/
🐳 Docker Deployment
Build the Docker Image
```bash
docker build -t secure-file-sharing .
```
Run the Container
```bash
docker run -d -p 5000:5000 --env-file .env secure-file-sharing
```
Now open:

http://localhost:5000/

☁️ Deploy on AWS EC2
1. Launch EC2 Instance
OS: Ubuntu 22.04 or Amazon Linux 2

Instance Type: t2.micro (Free Tier)

Open inbound ports 22 (SSH), 80 (HTTP), 5000 (test)

2. Connect to EC2
```bash
ssh -i your-key.pem ubuntu@<ec2-public-ip>
```
3. Install Docker
```bash
sudo apt update -y
sudo apt install docker.io -y
sudo systemctl start docker
sudo systemctl enable docker
```
4. Clone Repo & Run App
```bash
git clone https://github.com/<your-username>/secure-file-sharing.git
cd secure-file-sharing
nano .env   # add your secrets
docker build -t secure-file-sharing .
docker run -d -p 80:5000 --env-file .env secure-file-sharing
```
Access your live app at:

http://<ec2-public-ip>/

🧠 Future Enhancements
🔑 Integrate AWS KMS for key management
🦠 Add virus scanning (ClamAV) for uploaded files
📊 Build a Flask dashboard to track downloads and users
🕵️ Role-based access control (RBAC)
