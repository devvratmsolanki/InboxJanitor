# 🧹 INBOX JANITOR

**INBOX JANITOR** is a self-hosted Gmail cleaner that helps you take back control of your inbox. Sign in with Google, scan your Gmail for promotional emails and newsletter spam, then bulk-delete and optionally unsubscribe from them — all from a clean web UI.

---

## ✨ Features

- **Google OAuth 2.0 Sign-In** — Secure, scoped access to your Gmail account only
- **Smart Inbox Scan** — Detects promotions and newsletters using Gmail's category filters
- **Bulk Email Deletion** — Trash thousands of emails from a sender in one click using batch Gmail API calls
- **One-Click Unsubscribe** — Follows `List-Unsubscribe` headers via HTTP GET or `mailto:` to automatically unsubscribe
- **Email Preview** — Preview recent emails from any sender before taking action
- **Sender Whitelist** — Protect trusted senders from being accidentally deleted
- **Retention Period Filter** — Only delete emails older than N days; keep recent ones safe
- **Async Background Tasks** — Long-running deletion jobs run in background threads with live progress polling
- **Per-User Rate Limiting** — Token-bucket rate limiter prevents Gmail API quota abuse
- **CSRF Protection** — All state-mutating endpoints are protected with CSRF tokens
- **SSRF Guard** — Unsubscribe URLs are validated to block private/loopback address abuse
- **SQLite / PostgreSQL** — Stores subscription metadata locally (or on Postgres in production)
- **Render-Ready** — Includes `Procfile` and `gunicorn` for zero-config cloud deployment

---

## 🖥️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python · Flask · Flask-SQLAlchemy |
| Auth | Google OAuth 2.0 (`google-auth-oauthlib`) |
| Gmail API | `google-api-python-client` |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Server | Gunicorn (production) |
| Frontend | Single-page HTML (Jinja2 template) |

---

## 🚀 Getting Started (Local Development)

### Prerequisites

- Python 3.9+
- A [Google Cloud Project](https://console.cloud.google.com/) with the **Gmail API** enabled
- OAuth 2.0 credentials (`credentials.json`) downloaded from Google Cloud Console

### 1. Clone & Install

```bash
git clone https://github.com/your-username/InboxJanitor.git
cd InboxJanitor
pip install -r requirements.txt
```

### 2. Set Up Google Cloud Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to **APIs & Services → Credentials**
3. Create an **OAuth 2.0 Client ID** (Application type: **Web application**)
4. Add `http://127.0.0.1:5005/callback` as an **Authorized Redirect URI**
5. Download the credentials and save as `credentials.json` in the project root
6. Enable the **Gmail API** under **APIs & Services → Library**

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and fill in your values:

```env
SECRET_KEY=replace-this-with-a-random-64-char-hex-string
FLASK_ENV=development
```

To generate a secure secret key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Run the App

```bash
python app.py
```

Open your browser at **http://127.0.0.1:5005**

---

## 🌐 Deployment (Render)

> See [`DEPLOYMENT_GUIDE.md`](./DEPLOYMENT_GUIDE.md) for a full step-by-step walkthrough.

**Quick summary:**

1. Push your code to a GitHub repository (**do not commit `credentials.json`**)
2. Create a new **Web Service** on [Render.com](https://render.com)
3. Set the **Build Command**: `pip install -r requirements.txt`
4. Set the **Start Command**: `gunicorn app:app`
5. Add **Secret Files** → upload your `credentials.json`
6. Set the **Environment Variable**: `SECRET_KEY=<your-strong-random-key>`
7. Add your Render app URL to Google Cloud's **Authorized Redirect URIs**: `https://your-app.onrender.com/callback`

---

## ⚙️ Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | ✅ Yes | (ephemeral) | Flask session secret key. Set a strong value in production. |
| `FLASK_ENV` | No | `production` | Set to `development` for local dev (enables debug mode & HTTP OAuth). |
| `CLIENT_SECRETS_FILE` | No | `credentials.json` | Path to your Google OAuth credentials file. |
| `DATABASE_URL` | No | `sqlite:///subscriptions.db` | Database URI. Use a Postgres URL in production. |
| `PORT` | No | `5005` | Port the Flask app listens on. |

---

## 📁 Project Structure

```
InboxJanitor/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── Procfile                # Gunicorn start command for Render/Heroku
├── credentials.json        # Google OAuth secrets (⚠️ never commit this)
├── .env.example            # Environment variable template
├── .gitignore              # Excludes secrets and build artifacts
├── DEPLOYMENT_GUIDE.md     # Step-by-step guide to share with others
└── templates/
    └── index.html          # Single-page frontend UI
```

---

## 🔐 Security Notes

- **`credentials.json` must never be committed** to version control. It's listed in `.gitignore`.
- The `SECRET_KEY` should be a random 64-char hex string. If unset, an ephemeral key is used (sessions reset on every restart).
- All POST/DELETE routes are protected by a **CSRF token** (sent as `X-CSRF-Token` header or form field).
- Unsubscribe URLs are validated against a private IP blocklist to prevent **SSRF attacks**.
- Gmail API access uses the `https://mail.google.com/` scope. Your app is in **Testing Mode** by default and limited to 100 test users unless you complete Google's verification process.

---

## 🛠️ API Endpoints

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Main dashboard (redirects to login if unauthenticated) |
| `GET` | `/login` | Initiates Google OAuth flow |
| `GET` | `/callback` | OAuth callback handler |
| `GET` | `/logout` | Clears session |
| `GET` | `/scan` | Scans inbox for promotional senders (paginated) |
| `POST` | `/execute` | Starts a background unsubscribe + delete task |
| `GET` | `/task-status/<task_id>` | Polls the status of a running background task |
| `GET/POST/DELETE` | `/whitelist` | Manages whitelisted senders |
| `GET` | `/api/emails` | Fetches recent emails from a specific sender |
| `POST` | `/api/total-counts` | Returns total email count per sender |
| `GET` | `/api/profile` | Returns Gmail account profile info |
| `GET` | `/api/csrf-token` | Returns a fresh CSRF token for the frontend |

---

## 📦 Dependencies

```
flask
flask-sqlalchemy
google-api-python-client
google-auth-oauthlib
google-auth-httplib2
requests
python-dotenv
gunicorn
```

---

## ⚠️ Google App Verification Notice

Because INBOX JANITOR requests sensitive Gmail scopes (read, send, and trash emails), Google will display an **"App not verified"** warning when users sign in during Testing Mode.

To bypass this for trusted users:
1. Add their Gmail address as a **Test User** in Google Cloud Console → **APIs & Services → OAuth consent screen**
2. Tell them to click **Advanced → Go to INBOX JANITOR (unsafe)** on the warning screen

Getting the app fully verified requires a Google security review ($15,000–$75,000+).

---

## 📄 License

This project is for personal/private use. No license is currently defined.
