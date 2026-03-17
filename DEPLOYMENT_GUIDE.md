# How to Share Your Inbox Janitor

Because your application reads, sends, and trashes emails, Google considers it a **highly sensitive** app. You cannot just share a link and let anyone log in. Google strictly limits who can use it unless you undergo a rigorous security audit ($15,000 to $75,000+).

However, there is a **Testing Mode** workaround! This guide explains how to invite your friends to try your app.

---

## Step 1: Add Your Friend's Email to the Google Cloud Console

Before your friend can log in, you *must* add their email address to your Google Cloud project as a "Test User."

1.  Go to the [Google Cloud Console](https://console.cloud.google.com/).
2.  Make sure your project is selected in the top-left dropdown (it should be `prefab-galaxy-488510-r7` based on your credentials).
3.  In the left sidebar menu, go to **APIs & Services** > **OAuth consent screen**.
4.  Scroll down to the **Test users** section.
5.  Click the **+ ADD USERS** button.
6.  Enter your friend's Gmail address exactly as they type it (e.g., `friend@gmail.com`).
7.  Click **Save**.

Your friend is now authorized to log in!

---

## Step 2: Choose How to Share the App

You have two main options for sharing the app with your friend:

### Option A: Share the Code (They run it locally)
This is the easiest option, but it requires your friend to have Python installed on their computer.

1.  Zip up the entire `InboxJanitor` folder.
    *   **CRITICAL:** Make sure you **do not** include your `credentials.json` file if you don't trust them implicitly. That file contains the "keys" to your Google Cloud project. However, they *will* need a `credentials.json` file to run the app. If they run their own, they have to set up their own Google Cloud project. If you are sharing this with a trusted friend just to try it out, you *can* leave your `credentials.json` in the folder, but tell them to keep it secret.
2.  Send them the zip file.
3.  Instruct them to:
    *   Unzip the folder.
    *   Open a terminal in that folder.
    *   Run `pip install -r requirements.txt` (or `pip3`).
    *   Run `python app.py` (or `python3`).
    *   Open `http://127.0.0.1:5005` in their browser.

### Option B: Deploy to the Web (You host it)
This option is harder to set up, but it means your friend just has to visit a website link (like `https://my-inbox-janitor.onrender.com`).

**We recommend using Render (render.com)** because it is free and easy for Python/Flask apps.

1.  **Push your code to GitHub:**
    *   Create a free account on GitHub.
    *   Initialize a git repository in your `InboxJanitor` folder, commit the code, and push it to a private (or public) repository.
    *   **WARNING:** Do *not* commit your `credentials.json` file to GitHub! We will upload that file directly to Render later as a "Secret File".

2.  **Create a Web Service on Render:**
    *   Go to [Render.com](https://render.com/) and link your GitHub account.
    *   Click "New" > "Web Service".
    *   Select the GitHub repository you just created.
    *   Configure the service:
        *   **Environment:** Python
        *   **Build Command:** `pip install -r requirements.txt`
        *   **Start Command:** `gunicorn app:app --logger-class=\"simple\"` (Note: we will need to add `gunicorn` to your requirements.txt for this to work).

3.  **Add `credentials.json` to Render:**
    *   In your Render dashboard for this Web Service, go to **Environment** > **Secret Files**.
    *   Click "Add Secret File".
    *   Filename: `credentials.json`
    *   Contents: Copy and paste the entire contents of your local `credentials.json` file here.
    *   Save it.

4.  **Update Google Cloud Redirect URIs:**
    *   Once your app is deployed, Render will give you a URL (e.g., `https://your-app-name.onrender.com`).
    *   Go back to the [Google Cloud Console](https://console.cloud.google.com/).
    *   Go to **APIs & Services** > **Credentials**.
    *   Click on your OAuth 2.0 Client ID.
    *   Under "Authorized redirect URIs", click **+ ADD URI**.
    *   Enter your new Render URL *exactly* with `/callback` at the end: `https://your-app-name.onrender.com/callback`.
    *   Click **Save**.
5.  **Re-download credentials (Optional but recommended):**
    *   Since you updated the URIs in Google Cloud, download the new `credentials.json` file and update it in Render's Secret Files if you encounter any "redirect_uri_mismatch" errors.

---

## Step 3: Your Friend Logs In

Whether they run it locally or visit your hosted link:

1.  They click the "Login" button.
2.  Google will show them a terrifying warning screen: **"Google hasn't verified this app"**.
    *   *This happens because your app is in Testing Mode and hasn't passed the $15k security audit.*
3.  Tell your friend to click the tiny **"Advanced"** link at the bottom left.
4.  Then, tell them to click the link that says **"Go to Inbox Janitor (unsafe)"**.
5.  They check the boxes to grant the required permissions to view and modify their emails.
6.  They will now be logged in to your app!
