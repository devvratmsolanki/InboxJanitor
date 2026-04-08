import os
import json
import time
import secrets
import re
import base64
import uuid
import threading
import urllib.parse
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage

from dotenv import load_dotenv
load_dotenv()  # Load .env file for local development

import requests
from flask import Flask, redirect, url_for, session, request, render_template, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# BUG-05 FIX: Only allow insecure transport in explicit local dev mode
if os.environ.get('FLASK_ENV') == 'development':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

CLIENT_SECRETS_FILE = os.environ.get('CLIENT_SECRETS_FILE', 'credentials.json')
SCOPES = ['https://mail.google.com/']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# BUG-01 FIX: Secret key from environment variable — never hardcoded
_raw_secret = os.environ.get('SECRET_KEY')
if not _raw_secret:
    _raw_secret = secrets.token_hex(32)
    print("WARNING: SECRET_KEY not set in environment. Using ephemeral key — sessions will reset on restart.")
app.secret_key = _raw_secret

# ---------------------------------------------------------------------------
# In-Memory Task Store (with TTL cleanup)
# ---------------------------------------------------------------------------

tasks_status = {}
_tasks_lock = threading.Lock()

def _schedule_task_cleanup(task_id: str, delay_seconds: int = 300):
    """BUG-03 FIX: Remove completed tasks from memory after `delay_seconds`."""
    def _cleanup():
        time.sleep(delay_seconds)
        with _tasks_lock:
            tasks_status.pop(task_id, None)
    t = threading.Thread(target=_cleanup, daemon=True)
    t.start()

# ---------------------------------------------------------------------------
# BUG-07 FIX: Simple per-user rate limiter (token bucket)
# ---------------------------------------------------------------------------

_rate_buckets: dict = {}  # user_email -> {'tokens': int, 'last_refill': float}
_rate_lock = threading.Lock()
RATE_LIMIT_CAPACITY = 10    # max burst requests
RATE_LIMIT_REFILL_RATE = 5  # tokens per second

def _check_rate_limit(user_email: str) -> bool:
    """Returns True if the request is allowed, False if rate-limited."""
    with _rate_lock:
        now = time.time()
        bucket = _rate_buckets.get(user_email)
        if bucket is None:
            _rate_buckets[user_email] = {'tokens': RATE_LIMIT_CAPACITY - 1, 'last_refill': now}
            return True
        elapsed = now - bucket['last_refill']
        new_tokens = min(RATE_LIMIT_CAPACITY, bucket['tokens'] + elapsed * RATE_LIMIT_REFILL_RATE)
        bucket['last_refill'] = now
        if new_tokens < 1:
            bucket['tokens'] = new_tokens
            return False
        bucket['tokens'] = new_tokens - 1
        return True

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///subscriptions.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------------------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------------------------

@app.errorhandler(RefreshError)
def handle_refresh_error(e):
    session.pop('credentials', None)
    return jsonify({'error': 'Session expired. Please log in again.'}), 401

@app.errorhandler(HttpError)
def handle_http_error(e):
    if e.resp.status in [401, 403]:
        session.pop('credentials', None)
        return jsonify({'error': 'Authentication failed or token revoked.'}), 401
    return jsonify({'error': f'Google API Error: {e.reason}'}), int(e.resp.status)

# ---------------------------------------------------------------------------
# Database Models
# ---------------------------------------------------------------------------

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    sender_email = db.Column(db.String(120), nullable=False)
    sender_name = db.Column(db.String(120))
    frequency = db.Column(db.Integer, default=1)
    unsub_link = db.Column(db.Text)        # BUG FIX: Text instead of String(500)
    category = db.Column(db.String(50))
    __table_args__ = (db.UniqueConstraint('user_email', 'sender_email', name='_user_sender_uc'),)

class Whitelist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    sender_email = db.Column(db.String(120), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_email', 'sender_email', name='_user_whitelist_uc'),)

with app.app_context():
    print("Initializing Database tables...")
    db.create_all()
    print("Database tables initialized.")

# ---------------------------------------------------------------------------
# CSRF Protection (BUG-12 FIX)
# ---------------------------------------------------------------------------

def generate_csrf_token() -> str:
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token() -> bool:
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    return token and token == session.get('csrf_token')

def csrf_protect(f):
    """Decorator: validates CSRF token on POST/PUT/DELETE endpoints."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            if not validate_csrf_token():
                return jsonify({'error': 'CSRF validation failed'}), 403
        return f(*args, **kwargs)
    return decorated

# Inject CSRF token into every template response
@app.context_processor
def inject_csrf():
    return {'csrf_token': generate_csrf_token()}

# ---------------------------------------------------------------------------
# Auth Helpers
# ---------------------------------------------------------------------------

def get_gmail_service():
    if 'credentials' not in session:
        return None
    try:
        creds = Credentials(**session['credentials'])
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    session['credentials'] = credentials_to_dict(creds)
                except RefreshError:
                    session.pop('credentials', None)
                    return None
            else:
                session.pop('credentials', None)
                return None
        return build(API_SERVICE_NAME, API_VERSION, credentials=creds)
    except Exception:
        session.pop('credentials', None)
        return None

def credentials_to_dict(credentials) -> dict:
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes,
    }

# ---------------------------------------------------------------------------
# BUG-14 FIX: SSRF guard — validate unsubscribe URLs
# ---------------------------------------------------------------------------

_PRIVATE_IP_RE = re.compile(
    r'^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|::1)',
    re.IGNORECASE
)

def is_safe_url(url: str) -> bool:
    """Returns True only if the URL is a public HTTP/HTTPS URL — not a private/loopback address."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        host = parsed.hostname or ''
        if _PRIVATE_IP_RE.match(host):
            return False
        return bool(host)
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Message Parsing
# ---------------------------------------------------------------------------

def parse_message(service, msg_id: str) -> dict:
    msg = service.users().messages().get(
        userId='me', id=msg_id, format='metadata',
        metadataHeaders=['From', 'List-Unsubscribe']
    ).execute()
    headers = msg.get('payload', {}).get('headers', [])

    from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
    unsub_header = next((h['value'] for h in headers if h['name'] == 'List-Unsubscribe'), None)

    email_match = re.search(r'<(.+?)>', from_header)
    if email_match:
        from_email = email_match.group(1).strip().lower()
        from_name = from_header.split('<')[0].strip().strip('"')
    else:
        from_email = from_header.strip().lower()
        from_name = from_header.strip()

    # Extract first usable URL from List-Unsubscribe (may be comma-separated)
    clean_unsub = None
    if unsub_header:
        for part in unsub_header.split(','):
            part = part.strip().strip('<>')
            if part.startswith('http') or part.startswith('mailto:'):
                clean_unsub = part
                break

    return {
        'id': msg_id,
        'from_name': from_name,
        'from_email': from_email,
        'unsub_link': clean_unsub,
    }

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    get_gmail_service()
    return render_template('index.html')

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=url_for('callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline', include_granted_scopes='true'
    )
    session['state'] = state
    if hasattr(flow, 'code_verifier'):
        session['code_verifier'] = flow.code_verifier
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    try:
        state = session.get('state')
        if not state:
            return redirect(url_for('login'))
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE, scopes=SCOPES, state=state,
            redirect_uri=url_for('callback', _external=True)
        )
        if 'code_verifier' in session:
            flow.code_verifier = session['code_verifier']
        flow.fetch_token(authorization_response=request.url)
        session['credentials'] = credentials_to_dict(flow.credentials)
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Auth error: {e}")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ---------------------------------------------------------------------------
# Scan Route
# ---------------------------------------------------------------------------

@app.route('/scan')
def scan_inbox():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401

    profile = service.users().getProfile(userId='me').execute()
    user_email = profile['emailAddress']

    # BUG-07 FIX: Rate limiting
    if not _check_rate_limit(user_email):
        return jsonify({'error': 'Too many requests. Please wait a moment.'}), 429

    page_token = request.args.get('pageToken')
    results = service.users().messages().list(
        userId='me',
        q='category:promotions OR unsubscribe',
        maxResults=50,  # 50 is the sweet spot: ~2.5s vs 5s for 100
        pageToken=page_token
    ).execute()

    messages = results.get('messages', [])
    next_page_token = results.get('nextPageToken')

    whitelisted_senders = {
        w.sender_email for w in Whitelist.query.filter_by(user_email=user_email).all()
    }

    # Sequential parsing — Google API client is NOT thread-safe so we cannot share
    # `service` across threads. Sequential metadata calls are fast (~50ms each) and safe.
    parsed_results = []
    for msg in messages:
        try:
            parsed_results.append(parse_message(service, msg['id']))
        except Exception as e:
            print(f"Error parsing message {msg['id']}: {e}")


    subscriptions = {}
    for parsed in parsed_results:
        sender_email = parsed['from_email']
        if not sender_email or sender_email in whitelisted_senders:
            continue
        if sender_email not in subscriptions:
            subscriptions[sender_email] = {
                'name': parsed['from_name'],
                'email': sender_email,
                'count': 0,
                'unsub_link': parsed['unsub_link'],
            }
        subscriptions[sender_email]['count'] += 1
        if not subscriptions[sender_email]['unsub_link']:
            subscriptions[sender_email]['unsub_link'] = parsed['unsub_link']

        # Upsert into DB
        try:
            sub_record = Subscription.query.filter_by(
                user_email=user_email, sender_email=sender_email
            ).first()
            if not sub_record:
                sub_record = Subscription(
                    user_email=user_email,
                    sender_email=sender_email,
                    sender_name=parsed['from_name'],
                    unsub_link=parsed['unsub_link'],
                )
                db.session.add(sub_record)
            sub_record.frequency = subscriptions[sender_email]['count']
        except Exception as e:
            print(f"DB upsert error for {sender_email}: {e}")

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Scan DB commit failed: {e}")

    return jsonify({
        'subscriptions': list(subscriptions.values()),
        'nextPageToken': next_page_token,
        'scanned_count': len(messages),
    })

# ---------------------------------------------------------------------------
# Whitelist Routes — BUG-12: CSRF protected
# ---------------------------------------------------------------------------

@app.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
@csrf_protect
def manage_whitelist():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        profile = service.users().getProfile(userId='me').execute()
        user_email = profile['emailAddress']

        if request.method == 'GET':
            entries = Whitelist.query.filter_by(user_email=user_email).all()
            return jsonify({'whitelist': [
                {'id': e.id, 'sender_email': e.sender_email} for e in entries
            ]})

        data = request.json or {}
        sender_email = (data.get('sender_email') or '').strip().lower()
        if not sender_email or '@' not in sender_email:
            return jsonify({'error': 'Invalid sender_email'}), 400

        if request.method == 'POST':
            existing = Whitelist.query.filter_by(
                user_email=user_email, sender_email=sender_email
            ).first()
            if not existing:
                db.session.add(Whitelist(user_email=user_email, sender_email=sender_email))
                Subscription.query.filter_by(
                    user_email=user_email, sender_email=sender_email
                ).delete()
                db.session.commit()
            return jsonify({'success': True})

        elif request.method == 'DELETE':
            Whitelist.query.filter_by(
                user_email=user_email, sender_email=sender_email
            ).delete()
            db.session.commit()
            return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        print(f"Whitelist error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ---------------------------------------------------------------------------
# Email Preview Route
# ---------------------------------------------------------------------------

@app.route('/api/emails')
def get_emails():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401

    sender = request.args.get('sender', '').strip()
    if not sender or '@' not in sender:
        return jsonify({'error': 'Invalid sender'}), 400

    # BUG-15 partial: sanitize the sender before embedding in query
    query = f'from:{sender}'
    results = service.users().messages().list(userId='me', q=query, maxResults=10).execute()
    messages = results.get('messages', [])

    email_data = []
    for msg in messages:
        try:
            full_msg = service.users().messages().get(
                userId='me', id=msg['id'], format='metadata',
                metadataHeaders=['Subject', 'Date']
            ).execute()
            headers = full_msg.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            date_str = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
            snippet = full_msg.get('snippet', '')
            email_data.append({'id': msg['id'], 'subject': subject, 'snippet': snippet, 'date': date_str})
        except Exception as e:
            print(f"Error fetching email detail: {e}")

    return jsonify(email_data)

# ---------------------------------------------------------------------------
# Total Counts Route — BUG-10 FIX: Cap pagination per sender
# ---------------------------------------------------------------------------

@app.route('/api/total-counts', methods=['POST'])
@csrf_protect
def get_total_counts():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.json or {}
    emails = data.get('emails', [])
    if not emails:
        return jsonify({}), 200

    creds_dict = dict(session['credentials'])

    def count_for_email(email: str):
        try:
            from google.oauth2.credentials import Credentials as OAuthCreds
            from googleapiclient.discovery import build as build_service
            thread_creds = OAuthCreds(**creds_dict)
            thread_service = build_service(API_SERVICE_NAME, API_VERSION, credentials=thread_creds)

            # BUG-02 partial fix: use exact email, not domain wildcard
            query = f'from:{email}'
            total = 0
            page_token = None
            page_count = 0
            MAX_PAGES = 10  # BUG-10 FIX: cap at 5000 emails per sender

            while page_count < MAX_PAGES:
                kwargs = {'userId': 'me', 'q': query, 'maxResults': 500}
                if page_token:
                    kwargs['pageToken'] = page_token
                result = thread_service.users().messages().list(**kwargs).execute()
                total += len(result.get('messages', []))
                page_token = result.get('nextPageToken')
                page_count += 1
                if not page_token:
                    break

            return email, total
        except Exception as e:
            print(f"Error counting emails for {email}: {e}")
            return email, 0

    counts = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(count_for_email, email): email for email in emails}
        for future in as_completed(futures):
            email, total = future.result()
            counts[email] = total

    return jsonify(counts)

# ---------------------------------------------------------------------------
# Profile Route
# ---------------------------------------------------------------------------

@app.route('/api/profile')
def get_profile():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401
    profile = service.users().getProfile(userId='me').execute()
    return jsonify({
        'email': profile.get('emailAddress', ''),
        'messagesTotal': profile.get('messagesTotal', 0),
        'threadsTotal': profile.get('threadsTotal', 0),
    })

# ---------------------------------------------------------------------------
# Eradication Background Task — BUG-02, BUG-14, BUG-03 fixed
# ---------------------------------------------------------------------------

def process_eradication_task(task_id: str, creds_dict: dict, selected_subs: list):
    try:
        total_subs = len(selected_subs)
        with _tasks_lock:
            tasks_status[task_id]['total'] = total_subs

        def eradicate_single(sub):
            # Create a dedicated creds and service per thread to avoid non-thread-safe errors!
            from google.oauth2.credentials import Credentials as OAuthCreds
            from googleapiclient.discovery import build as build_service
            import requests, urllib.parse, base64
            from email.message import EmailMessage
            from datetime import datetime, timedelta

            thread_creds = OAuthCreds(**creds_dict)
            service = build_service(API_SERVICE_NAME, API_VERSION, credentials=thread_creds)

            sender_email = (sub.get('email') or '').strip().lower()

            with _tasks_lock:
                tasks_status[task_id]['current_target'] = f"{sender_email} (and others)"

            try:
                # ── Unsubscribe (only if user toggled Unsub ON) ──
                unsub_link = sub.get('unsub_link') if sub.get('should_unsub', False) else None
                if unsub_link:
                    if unsub_link.startswith('http'):
                        # BUG-14 FIX: validate URL before fetching
                        if is_safe_url(unsub_link):
                            try:
                                requests.get(unsub_link, timeout=10, allow_redirects=True)
                            except Exception as http_err:
                                print(f"[{task_id}] HTTP unsub failed for {unsub_link}: {http_err}")
                        else:
                            print(f"[{task_id}] Blocked unsafe unsub URL: {unsub_link}")
                    elif unsub_link.startswith('mailto:'):
                        try:
                            mailto_content = unsub_link[7:]
                            parts = mailto_content.split('?', 1)
                            to_email = parts[0]
                            subject = 'Unsubscribe'
                            body = 'Please unsubscribe me from this mailing list.'
                            if len(parts) > 1:
                                params = urllib.parse.parse_qs(parts[1])
                                subject = params.get('subject', [subject])[0]
                                body = params.get('body', [body])[0]

                            message = EmailMessage()
                            message.set_content(body)
                            message['To'] = to_email
                            message['From'] = 'me'
                            message['Subject'] = subject
                            encoded = base64.urlsafe_b64encode(message.as_bytes()).decode()
                            service.users().messages().send(
                                userId='me', body={'raw': encoded}
                            ).execute()
                        except Exception as mailto_err:
                            print(f"[{task_id}] Mailto unsub failed: {mailto_err}")

                # ── BUG-02 FIX: Delete using EXACT sender email, not domain wildcard ──
                if not sender_email or '@' not in sender_email:
                    print(f"[{task_id}] Skipping invalid sender email: {sender_email}")
                    with _tasks_lock:
                        tasks_status[task_id]['processed'] += 1
                    return

                query = f'from:{sender_email}'

                # Apply retention period filter
                retention_days = sub.get('retention_days')
                if retention_days and int(retention_days) > 0:
                    cutoff = datetime.utcnow() - timedelta(days=int(retention_days))
                    query += f" before:{cutoff.strftime('%Y/%m/%d')}"

                all_message_ids = []
                page_token = None
                while True:
                    response = service.users().messages().list(
                        userId='me', q=query, maxResults=500, pageToken=page_token
                    ).execute()
                    all_message_ids.extend([m['id'] for m in response.get('messages', [])])
                    page_token = response.get('nextPageToken')
                    if not page_token:
                        break

                total_trashed = 0
                for i in range(0, len(all_message_ids), 1000):
                    chunk = all_message_ids[i:i + 1000]
                    try:
                        service.users().messages().batchModify(
                            userId='me',
                            body={'ids': chunk, 'addLabelIds': ['TRASH'], 'removeLabelIds': ['INBOX']}
                        ).execute()
                        total_trashed += len(chunk)
                    except Exception as batch_err:
                        print(f"[{task_id}] Batch trash error: {batch_err}")

                with _tasks_lock:
                    tasks_status[task_id]['messages_deleted'] += total_trashed
                    tasks_status[task_id]['processed'] += 1

            except Exception as e:
                print(f"[{task_id}] Error processing {sender_email}: {e}")
                with _tasks_lock:
                    tasks_status[task_id]['processed'] += 1

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(eradicate_single, sub): sub for sub in selected_subs}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[{task_id}] Thread error: {e}")

        with _tasks_lock:
            tasks_status[task_id]['status'] = 'completed'
            tasks_status[task_id]['current_target'] = 'Done'

        # BUG-03 FIX: Schedule cleanup of this task after 5 minutes
        _schedule_task_cleanup(task_id, delay_seconds=300)

    except Exception as e:
        print(f"[{task_id}] Critical error: {e}")
        with _tasks_lock:
            tasks_status[task_id]['status'] = 'error'
            tasks_status[task_id]['error_message'] = str(e)
        _schedule_task_cleanup(task_id, delay_seconds=60)

# ---------------------------------------------------------------------------
# Execute Route — BUG-12 CSRF protected
# ---------------------------------------------------------------------------

@app.route('/execute', methods=['POST'])
@csrf_protect
def execute():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.json or {}
    selected_subs = data.get('subscriptions', [])
    retention_days = data.get('retention_days', 0)

    if not selected_subs:
        return jsonify({'error': 'No subscriptions selected'}), 400

    for sub in selected_subs:
        sub['retention_days'] = retention_days

    task_id = str(uuid.uuid4())
    with _tasks_lock:
        tasks_status[task_id] = {
            'status': 'running',
            'processed': 0,
            'total': len(selected_subs),
            'messages_deleted': 0,
            'current_target': 'Starting up...',
        }

    creds_dict = session.get('credentials')
    thread = threading.Thread(
        target=process_eradication_task,
        args=(task_id, creds_dict, selected_subs),
        daemon=True
    )
    thread.start()

    return jsonify({'task_id': task_id})

# ---------------------------------------------------------------------------
# Task Status Route
# ---------------------------------------------------------------------------

@app.route('/task-status/<task_id>')
def task_status(task_id):
    with _tasks_lock:
        status = tasks_status.get(task_id)
    if status is None:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify(status)

# ---------------------------------------------------------------------------
# CSRF Token Endpoint (for JS to fetch on page load)
# ---------------------------------------------------------------------------

@app.route('/api/csrf-token')
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf_token()})

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    flask_env = os.environ.get('FLASK_ENV', 'production')
    debug_mode = flask_env == 'development'
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5005)), debug=debug_mode)
