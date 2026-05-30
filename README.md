# 🔐 Secure Student Portal

A multi-organization web application built with **Python Flask** demonstrating real-world cybersecurity countermeasures.
Built for **23CSE313 — Foundations of Cyber Security**.

🔗 **Live Demo:** [Secure-Student-Portal](https://secure-student-portal.onrender.com/)

## 🛡️ Security Features

| Attack | Protection |
|--------|-----------|
| SQL Injection | Parameterized queries + regex detector |
| XSS | `bleach` sanitization + regex |
| CSRF | Flask-WTF tokens on every form |
| Brute Force | IP lockout after 5 failed attempts |
| Malicious File Upload | Extension whitelist + `secure_filename` |
| Clickjacking | `X-Frame-Options: DENY` |
| MIME Sniffing | `X-Content-Type-Options: nosniff` |

---

## ⚙️ Tech Stack

- **Backend** — Python 3, Flask
- **Database** — SQLite3
- **Auth** — bcrypt, Flask-WTF
- **Input Validation** — bleach, regex
- **Rate Limiting** — Flask-Limiter
- **Email** — Gmail SMTP
- **Frontend** — HTML5, Bootstrap 5, Chart.js

---

## 🚀 Run Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Add .env file
MAIL_SENDER=your_gmail@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_ENABLED=True
SECRET_KEY=any_random_string

# Seed database
python seed_data.py

# Run
python app.py
```

Open `http://127.0.0.1:5000`

---

## ☁️ Deploy on Render (Free)

1. Push repo to GitHub
2. Go to [render.com](https://render.com) → New Web Service → connect repo
3. Start Command: `gunicorn app:app`
4. Add environment variables (`MAIL_SENDER`, `MAIL_PASSWORD`, `MAIL_ENABLED`, `SECRET_KEY`)
5. Deploy → run `python seed_data.py` from Shell

---

## 📁 Allowed File Uploads

`.pdf` `.docx` `.txt` `.png` `.jpg` `.jpeg` — Max **5MB**

---

## 📋 Rubric

| Criterion | Done |
|-----------|------|
| Authentication & Authorization | ✅ |
| Input Validation & Attack Prevention | ✅ |
| Data Protection (HTTPS, bcrypt, headers) | ✅ |
