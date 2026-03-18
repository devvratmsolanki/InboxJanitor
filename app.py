import os
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from email.message import EmailMessage
import base64
import re
import urllib.parse
from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

# Configuration
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For local development only
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = ['https://mail.google.com/']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError
import threading
import uuid

app = Flask(__name__)
# Tell Flask it is behind a proxy (like Render's load balancer) so url_for(_external=True) generates HTTPS URLs instead of HTTP
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = 'your_super_secret_key'

tasks_status = {}

# Configure Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///subscriptions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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

# --- Database Models ---
class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False) # Which inbox this belongs to
    sender_email = db.Column(db.String(120), nullable=False)
    sender_name = db.Column(db.String(120))
    frequency = db.Column(db.Integer, default=1)
    unsub_link = db.Column(db.String(500))
    category = db.Column(db.String(50)) # 'Newsletter', 'Promo', etc
    
    # Ensure a user only has one active sub entry per sender
    __table_args__ = (db.UniqueConstraint('user_email', 'sender_email', name='_user_sender_uc'),)

class Whitelist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120), nullable=False)
    sender_email = db.Column(db.String(120), nullable=False)
    
    __table_args__ = (db.UniqueConstraint('user_email', 'sender_email', name='_user_whitelist_uc'),)

# Create tables if they don't exist
with app.app_context():
    print("Initializing Database tables...")
    db.create_all()
    print("Database tables initialized.")

def get_gmail_service():
    if 'credentials' not in session:
        return None
    
    try:
        creds = Credentials(**session['credentials'])
        from google.auth.transport.requests import Request
        from google.auth.exceptions import RefreshError
        
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
    except Exception as e:
        session.pop('credentials', None)
        return None

def parse_message(service, msg_id):
    # Fetch only needed headers to massively optimize scan time
    msg = service.users().messages().get(userId='me', id=msg_id, format='metadata', metadataHeaders=['From', 'List-Unsubscribe']).execute()
    headers = msg.get('payload', {}).get('headers', [])
    
    from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
    unsub_header = next((h['value'] for h in headers if h['name'] == 'List-Unsubscribe'), None)
    
    # Extract email and name from "Name <email@example.com>"
    import re
    email_match = re.search(r'<(.*)>', from_header)
    if email_match:
        from_email = email_match.group(1)
        from_name = from_header.split('<')[0].strip().replace('"', '')
    else:
        from_email = from_header
        from_name = from_header

    return {
        'id': msg_id,
        'from_name': from_name,
        'from_email': from_email,
        'unsub_link': unsub_header
    }

@app.route('/scan')
def scan_inbox():
    print("=== SCAN REQUEST START ===")
    service = get_gmail_service()
    if not service:
        print("Scan: No gmail service")
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get the user's email profile context for the DB
    print("Scan: Getting Profile...")
    profile = service.users().getProfile(userId='me').execute()
    user_email = profile['emailAddress']
    print(f"Scan: Profile email is {user_email}")

    # Get optional pagination token from frontend
    page_token = request.args.get('pageToken')

    # Search for promotion or unsubscribe emails, fetch up to 100 to cast a wider net
    print("Scan: Querying Gmail API...")
    results = service.users().messages().list(
        userId='me', 
        q='category:promotions OR unsubscribe', 
        maxResults=100,
        pageToken=page_token
    ).execute()
    
    messages = results.get('messages', [])
    next_page_token = results.get('nextPageToken')
    
    # Load user's whitelist into memory for fast lookup
    whitelisted_senders = {w.sender_email for w in Whitelist.query.filter_by(user_email=user_email).all()}

    subscriptions = {}
    for msg in messages:
        try:
            parsed = parse_message(service, msg['id'])
            sender_email = parsed['from_email']
            
            # Skip instantly if it's on the user's whitelist
            if sender_email in whitelisted_senders:
                continue
            
            if sender_email not in subscriptions:
                # Add a rudimentary categorization for the frontend
                category = "Newsletters" if sender_email and ("news" in sender_email or "letter" in sender_email) else "Promotions"
                
                subscriptions[sender_email] = {
                    'name': parsed['from_name'],
                    'email': sender_email,
                    'count': 0,
                    'message_ids': [],
                    'unsub_link': parsed['unsub_link'],
                    'category': category
                }
            
            # Use explicit int cast incase of type errors
            subscriptions[sender_email]['count'] = int(subscriptions[sender_email]['count']) + 1
            subscriptions[sender_email]['message_ids'].append(msg['id'])
            
            # Prefer the first unsub link found
            if not subscriptions[sender_email]['unsub_link']:
                subscriptions[sender_email]['unsub_link'] = parsed['unsub_link']
                
            # Store/Update in SQLite DB
            sub_record = Subscription.query.filter_by(user_email=user_email, sender_email=sender_email).first()
            if not sub_record:
                sub_record = Subscription(
                    user_email=user_email,
                    sender_email=sender_email,
                    sender_name=parsed['from_name'],
                    unsub_link=parsed['unsub_link'],
                    category=subscriptions[sender_email]['category']
                )
                db.session.add(sub_record)
            
            sub_record.frequency = subscriptions[sender_email]['count']
                
        except Exception as e:
            print(f"Error parsing message {msg['id']}: {e}")
            
    print("Scan: Committing DB session...")
    try:
        db.session.commit()
        print("Scan: DB committed successfully.")
    except Exception as e:
        print(f"Scan: DB Commit Failed: {e}")
        db.session.rollback()
        raise e
            
    print(f"=== SCAN REQUEST END: Return {len(subscriptions)} elements ===")
    return jsonify({
        'subscriptions': list(subscriptions.values()),
        'nextPageToken': next_page_token,
        'scanned_count': len(messages)
    })

@app.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        profile = service.users().getProfile(userId='me').execute()
        user_email = profile['emailAddress']
        
        if request.method == 'GET':
            entries = Whitelist.query.filter_by(user_email=user_email).all()
            return jsonify({'whitelist': [{'id': e.id, 'sender_email': e.sender_email} for e in entries]})
            
        data = request.json
        sender_email = data.get('sender_email')
        if not sender_email:
            return jsonify({'error': 'Missing sender_email'}), 400

        if request.method == 'POST':
            existing = Whitelist.query.filter_by(user_email=user_email, sender_email=sender_email).first()
            if not existing:
                whitelist_entry = Whitelist(user_email=user_email, sender_email=sender_email)
                db.session.add(whitelist_entry)
                Subscription.query.filter_by(user_email=user_email, sender_email=sender_email).delete()
                db.session.commit()
            return jsonify({'success': True, 'message': f'{sender_email} added to whitelist.'})
            
        elif request.method == 'DELETE':
            Whitelist.query.filter_by(user_email=user_email, sender_email=sender_email).delete()
            db.session.commit()
            return jsonify({'success': True, 'message': f'{sender_email} removed from whitelist.'})
            
    except Exception as e:
        import traceback
        with open('debug_whitelist.log', 'w') as f:
            f.write(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/emails')
def get_emails():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401
        
    sender = request.args.get('sender')
    if not sender:
        return jsonify({'error': 'No sender provided'}), 400
        
    query = f"from:\"{sender}\""
    results = service.users().messages().list(userId='me', q=query, maxResults=10).execute()
    messages = results.get('messages', [])
    
    email_data = []
    for msg in messages:
        try:
            full_msg = service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['Subject', 'Date']).execute()
            headers = full_msg.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            date_str = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')
            snippet = full_msg.get('snippet', '')
            
            email_data.append({
                'id': msg['id'],
                'subject': subject,
                'snippet': snippet,
                'date': date_str
            })
        except Exception as e:
            print(f"Error fetching email detail: {e}")
            
    return jsonify(email_data)

def process_eradication_task(task_id, creds_dict, selected_subs):
    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
        
        creds = Credentials(**creds_dict)
        service = build(API_SERVICE_NAME, API_VERSION, credentials=creds)
        
        total_subs = len(selected_subs)
        tasks_status[task_id]['total'] = total_subs
        
        for idx, sub in enumerate(selected_subs):
            sender_email = sub.get('email')
            tasks_status[task_id]['current_target'] = sender_email
            
            try:
                # 1. Unsubscribe
                unsub_link = sub.get('unsub_link')
                if unsub_link:
                    if unsub_link.startswith('http'):
                        print(f"[{task_id}] Trying HTTP link: {unsub_link}")
                        try:
                            # Use requests in background thread with timeout
                            import requests
                            requests.get(unsub_link, timeout=10)
                        except Exception as http_err:
                            print(f"[{task_id}] HTTP unsubscribe failed for {unsub_link}: {http_err}")
                    elif unsub_link.startswith('mailto:'):
                        print(f"[{task_id}] Mailto unsub link found: {unsub_link}")
                        try:
                            mailto_content = unsub_link[7:]
                            parts = mailto_content.split('?', 1)
                            to_email = parts[0]
                            
                            subject = "Unsubscribe"
                            body = "Please unsubscribe me from this mailing list."
                            import urllib.parse
                            
                            if len(parts) > 1:
                                params = urllib.parse.parse_qs(parts[1])
                                if 'subject' in params:
                                    subject = params['subject'][0]
                                if 'body' in params:
                                    body = params['body'][0]
                                    
                            message = EmailMessage()
                            message.set_content(body)
                            message['To'] = to_email
                            message['From'] = 'me'
                            message['Subject'] = subject

                            encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
                            create_message = {'raw': encoded_message}
                            
                            service.users().messages().send(userId="me", body=create_message).execute()
                        except Exception as mailto_err:
                            print(f"[{task_id}] Failed to send mailto for {unsub_link}: {mailto_err}")
                
                # 2. Batch Trash (Safe Delete)
                domain = sender_email.split('@')[-1] if '@' in sender_email else sender_email
                query = f"from:*{domain}"
                all_message_ids = []
                page_token = None
                
                while True:
                    response = service.users().messages().list(
                        userId='me', 
                        q=query, 
                        maxResults=500,
                        pageToken=page_token
                    ).execute()
                    
                    messages = response.get('messages', [])
                    all_message_ids.extend([m['id'] for m in messages])
                    
                    page_token = response.get('nextPageToken')
                    if not page_token:
                        break
                
                total_trashed = 0
                if all_message_ids:
                    chunk_size = 1000
                    for i in range(0, len(all_message_ids), chunk_size):
                        chunk = all_message_ids[i:i + chunk_size]
                        try:
                            # Safely move to TRASH instead of permanently deleting
                            service.users().messages().batchModify(
                                userId='me',
                                body={
                                    'ids': chunk,
                                    'addLabelIds': ['TRASH'],
                                    'removeLabelIds': ['INBOX']
                                }
                            ).execute()
                            total_trashed += len(chunk)
                        except Exception as delete_err:
                            print(f"[{task_id}] Error trashing batch chunk: {delete_err}")
                            
                tasks_status[task_id]['messages_deleted'] += total_trashed
                tasks_status[task_id]['processed'] += 1
                
            except Exception as e:
                print(f"[{task_id}] Error processing subscription {sender_email}: {e}")
                tasks_status[task_id]['processed'] += 1
                
        tasks_status[task_id]['status'] = 'completed'
    except Exception as e:
        print(f"[{task_id}] Critical Error in Background Task: {e}")
        tasks_status[task_id]['status'] = 'error'
        tasks_status[task_id]['error_message'] = str(e)

@app.route('/execute', methods=['POST'])
def execute():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    selected_subs = data.get('subscriptions', [])
    
    if not selected_subs:
        return jsonify({'error': 'No subscriptions selected'}), 400
        
    task_id = str(uuid.uuid4())
    tasks_status[task_id] = {
        'status': 'running',
        'processed': 0,
        'total': len(selected_subs),
        'messages_deleted': 0,
        'current_target': 'Starting up...'
    }
    
    # We pass the credentials dict to the thread so it can build its own service object
    # The current Session object is thread-local and won't safely pass into a new thread
    creds_dict = session.get('credentials')
    
    thread = threading.Thread(target=process_eradication_task, args=(task_id, creds_dict, selected_subs))
    thread.daemon = True
    thread.start()
    
    return jsonify({'task_id': task_id})

@app.route('/task-status/<task_id>')
def task_status(task_id):
    if task_id not in tasks_status:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify(tasks_status[task_id])

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

@app.route('/')
def index():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    
    service = get_gmail_service()
    # Placeholder for fetching emails
    return render_template('index.html')

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, 
        scopes=SCOPES,
        redirect_uri=url_for('callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')
    session['state'] = state
    # Store the code_verifier for PKCE stability
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
            CLIENT_SECRETS_FILE, 
            scopes=SCOPES, 
            state=state,
            redirect_uri=url_for('callback', _external=True)
        )
        if 'code_verifier' in session:
            flow.code_verifier = session['code_verifier']
            
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)
        
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Auth error: {e}")
        return redirect(url_for('login'))

@app.route('/api/total-counts', methods=['POST'])
def get_total_counts():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.json
    emails = data.get('emails', [])
    if not emails:
        return jsonify({}), 200

    def count_for_email(email):
        try:
            domain = email.split('@')[-1] if '@' in email else email
            query = f'from:*{domain}'
            total = 0
            page_token = None
            while True:
                kwargs = {'userId': 'me', 'q': query, 'maxResults': 500}
                if page_token:
                    kwargs['pageToken'] = page_token
                result = service.users().messages().list(**kwargs).execute()
                total += len(result.get('messages', []))
                page_token = result.get('nextPageToken')
                if not page_token:
                    break
            return email, total
        except Exception as e:
            print(f"Error counting emails for {email}: {e}")
            return email, 0

    counts = {}
    # Fetch all sender counts in parallel — reduces N*T to ~T
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(count_for_email, email): email for email in emails}
        for future in as_completed(futures):
            email, total = future.result()
            counts[email] = total

    return jsonify(counts)

@app.route('/api/profile')
def get_profile():
    service = get_gmail_service()
    if not service:
        return jsonify({'error': 'Not authenticated'}), 401
    profile = service.users().getProfile(userId='me').execute()
    return jsonify({
        'email': profile.get('emailAddress', ''),
        'messagesTotal': profile.get('messagesTotal', 0),
        'threadsTotal': profile.get('threadsTotal', 0)
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=True)
