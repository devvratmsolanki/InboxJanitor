# Deployment Implementation Plan

Hosting the Email Cleaner application online requires shifting from a local development environment to a production-ready setup. Since the application handles sensitive user data (emails and OAuth tokens), security and proper configuration are paramount. 

## 1. Hosting Platform
I recommend **Render** or **Heroku** for hosting the application. Both are Platform-as-a-Service (PaaS) providers that make deploying Python/Flask applications straightforward, handling SSL/HTTPS and domain mapping automatically.
- **Render** has a very generous free tier and connects directly to your GitHub repository for automatic deployments.
- We will need to set up a `Procfile` or use `gunicorn` as the WSGI server, as Flask's built-in development server is not secure or performant for production.

## 2. Google Cloud OAuth Configuration Changes
This is the most critical step. The current Google Cloud OAuth configuration only allows redirects to `http://localhost:5005/callback`. 
1. **OAuth Consent Screen**: You will need to move the app from "Testing" to "Production" in the Google Cloud Console if you want anyone to be able to log in without you manually adding their email address. Note: *Google may require a security verification process since the app requests restricted scopes (`https://mail.google.com/`).*
2. **Authorized Redirect URIs**: You must add the production URL of your hosted application to the OAuth Client ID settings (e.g., `https://your-app-name.onrender.com/callback`).

## 3. Environment Variables & Security
Currently, sensitive configurations like the secret key and potentially the OAuth client secrets are in the code or in local files (`credentials.json`).
1. **Environment Variables**: We will move `app.secret_key` and the contents of `credentials.json` into Environment Variables in the hosting dashboard. This prevents exposing secrets if the code is uploaded to GitHub.
2. **OAUTHLIB_INSECURE_TRANSPORT**: We must remove the line `os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'`. Production environments mandate HTTPS, and this bypasses that requirement.

## 4. Database Storage
Currently, the app uses an SQLite database (`subscriptions.db`) stored on the local file system. 
1. **Ephemeral File Systems**: Platforms like Render and Heroku use ephemeral file systems. This means they wipe local files (like a SQLite DB) every time the server restarts or redeploys.
2. **PostgreSQL**: We should migrate from SQLite to a managed PostgreSQL database. Render offers a free PostgreSQL database tier that we can attach to our web service. We'll need to update the `SQLALCHEMY_DATABASE_URI` to point to the new database URL.

## 5. Background Tasks
The application currently uses `threading.Thread` for the background eradication tasks.
1. **Thread Limitations**: Web workers in production (like Gunicorn) often kill long-running background threads or restart.
2. **Task Queue Solution**: For a robust production environment, long-running tasks should ideally be moved to a task queue like **Celery** backed by Redis. However, for a simple MVP deployment, we can attempt to configure Gunicorn with sufficient timeout settings or synchronous workers, though a proper queuing system is the standard DevOps approach.

---

## Next Steps for the User
If you approve this plan, we will start by:
1. Modifying `app.py` to use environment variables for the database URI and Google credentials.
2. Adding `gunicorn` and `psycopg2-binary` (for PostgreSQL) to `requirements.txt`.
3. Guiding you on creating a GitHub repository and linking it to Render.com.
