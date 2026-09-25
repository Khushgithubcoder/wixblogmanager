import csv
import io
import os
import threading
import time
import requests
from functools import wraps
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, request, session, jsonify, send_from_directory, redirect
from werkzeug.security import generate_password_hash, check_password_hash

import db
import wix_api
from crypto_utils import encrypt_key, decrypt_key

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-change-me")

# Initialize PostgreSQL tables
db.init_db()

# --- Auth Helpers ------------------------------------------------------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Please log in first."}), 401
        return fn(*args, **kwargs)
    return wrapper

def get_active_wix_auth(user_id):
    """Retrieve and decrypt credentials for active user."""
    cred = db.get_wix_credential(user_id)
    if not cred:
        return None, None, None
    
    auth_type = cred.get("auth_type", "api_key")
    site_id = cred.get("site_id", "")
    
    if auth_type == "oauth":
        app_id = os.environ.get("WIX_APP_ID")
        app_secret = os.environ.get("WIX_APP_SECRET")
        raw_refresh = decrypt_key(cred.get("encrypted_refresh_token") or "")
        raw_access = decrypt_key(cred.get("encrypted_access_token") or "")

        # Wix OAuth access tokens are only valid for ~5 minutes, so always mint a fresh
        # one from the refresh token before making API calls.
        if raw_refresh and app_id and app_secret:
            try:
                refreshed = wix_api.refresh_oauth_token(app_id, app_secret, raw_refresh)
                raw_access = refreshed["access_token"]
                db.save_wix_credential(
                    user_id=user_id,
                    site_id=site_id,
                    auth_type="oauth",
                    encrypted_refresh_token=encrypt_key(refreshed.get("refresh_token") or raw_refresh),
                    encrypted_access_token=encrypt_key(raw_access),
                )
            except Exception as e:
                print(f"[OAuth] Refresh failed: {e}")
        # Never fall back to the refresh token as an access token: it is not accepted by Wix APIs.
        return raw_access, site_id, "oauth"
    else:
        raw_key = decrypt_key(cred.get("encrypted_api_key") or "")
        return raw_key, site_id, "api_key"

# --- Static Frontend Routes --------------------------------------------------

@app.get("/")
def root():
    return send_from_directory(FRONTEND_DIR, "login.html")

# --- User Authentication Routes ----------------------------------------------

@app.post("/api/auth/signup")
def signup():
    data = request.get_json(force=True)
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400
    try:
        user_id = db.create_user(email, generate_password_hash(password))
    except ValueError:
        return jsonify({"error": "An account with that email already exists."}), 409
    except Exception as e:
        return jsonify({"error": f"Database error: {e}"}), 500
    
    session["user_id"] = user_id
    return jsonify({"success": True, "userId": user_id, "email": email})

@app.post("/api/auth/login")
def login():
    data = request.get_json(force=True)
    email, password = data.get("email"), data.get("password")
    try:
        user = db.find_user_by_email(email)
    except Exception as e:
        return jsonify({"error": f"Database connection error: {e}"}), 500
        
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password."}), 401
    session["user_id"] = user["id"]
    return jsonify({"success": True, "userId": user["id"], "email": user["email"]})

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"success": True})

@app.get("/api/auth/me")
def me():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in."}), 401
    user = db.find_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": "Not logged in."}), 401
    return jsonify({"userId": user["id"], "email": user["email"]})

# --- Wix Connection Routes (Zero Password Sharing) --------------------------

@app.post("/api/wix/connect")
@login_required
def wix_connect():
    """Connect Wix site using Client Scoped API Key."""
    data = request.get_json(force=True)
    api_key = data.get("apiKey", "").strip()
    site_id = data.get("siteId", "").strip()

    if not api_key or not site_id:
        return jsonify({"error": "Both API Key and Site ID are required."}), 400

    try:
        # 1. Verify credentials and inspect site
        site_info = wix_api.verify_and_inspect_site(api_key, site_id, auth_type="api_key")
        # 2. Audit authorized permissions
        permissions = wix_api.check_permissions(api_key, site_id, auth_type="api_key")
        
        # 3. Store encrypted credentials in PostgreSQL
        db.save_wix_credential(
            user_id=session["user_id"],
            site_id=site_id,
            encrypted_api_key=encrypt_key(api_key),
            site_display_name=site_info.get("siteDisplayName"),
            site_url=site_info.get("url"),
            auth_type="api_key",
            permissions=permissions,
        )
        
        db.record_audit_log(session["user_id"], "CONNECTED_WIX_SITE", {
            "siteId": site_id,
            "siteName": site_info.get("siteDisplayName"),
            "url": site_info.get("url"),
        })
        
        return jsonify({
            "success": True,
            "siteId": site_id,
            "siteInfo": site_info,
            "permissions": permissions,
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to verify Wix credentials: {e}"}), 400

@app.get("/api/wix/status")
@login_required
def wix_status():
    """Get active connection status and details of connected Wix site."""
    cred = db.get_wix_credential(session["user_id"])
    if not cred:
        return jsonify({"connected": False})
    
    return jsonify({
        "connected": True,
        "siteId": cred.get("site_id"),
        "siteName": cred.get("site_display_name") or "Connected Wix Site",
        "siteUrl": cred.get("site_url") or "",
        "authType": cred.get("auth_type", "api_key"),
        "permissions": cred.get("permissions") or {},
        "connectedAt": str(cred.get("connected_at") or ""),
    })

@app.post("/api/wix/test-connection")
@login_required
def test_connection():
    """Live verification and permission health check for connected site."""
    auth_token, site_id, auth_type = get_active_wix_auth(session["user_id"])
    if not auth_token or not site_id:
        return jsonify({"error": "No connected Wix site found."}), 400
    
    try:
        site_info = wix_api.verify_and_inspect_site(auth_token, site_id, auth_type=auth_type)
        permissions = wix_api.check_permissions(auth_token, site_id, auth_type=auth_type)
        return jsonify({
            "success": True,
            "siteInfo": site_info,
            "permissions": permissions,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.post("/api/wix/disconnect")
@login_required
def disconnect_wix():
    """Disconnect Wix website and purge encrypted credentials."""
    db.delete_wix_credential(session["user_id"])
    db.record_audit_log(session["user_id"], "DISCONNECTED_WIX_SITE")
    return jsonify({"success": True})

# --- Wix OAuth 2.0 App Routes -----------------------------------------------

@app.get("/api/wix/oauth/start")
@login_required
def oauth_start():
    """Generate Wix App Installer URL for zero-credential one-click authorization."""
    app_id = os.environ.get("WIX_APP_ID")
    redirect_uri = os.environ.get("WIX_REDIRECT_URI", "http://localhost:5000/api/wix/oauth/callback")
    if not app_id:
        return jsonify({"error": "WIX_APP_ID not configured in backend environment."}), 400

    state_token = session["user_id"]
    installer_url = f"https://www.wix.com/installer/install?appId={app_id}&redirectUrl={redirect_uri}&token={state_token}"
    return jsonify({"installerUrl": installer_url})

@app.get("/api/wix/oauth/callback")
def oauth_callback():
    """Handle Wix OAuth redirect with authorization code."""
    code = request.args.get("code")
    instance_id = request.args.get("instanceId")
    state_token = request.args.get("token") or session.get("user_id")

    if not code or not instance_id:
        return "Authorization failed: Missing code or instanceId", 400

    app_id = os.environ.get("WIX_APP_ID")
    app_secret = os.environ.get("WIX_APP_SECRET")
    if not app_id or not app_secret:
        return "Server error: Wix App credentials missing in .env", 500

    try:
        tokens = wix_api.exchange_oauth_code(app_id, app_secret, code)
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        # Inspect site using token
        site_info = wix_api.verify_and_inspect_site(access_token, instance_id, auth_type="oauth")
        permissions = wix_api.check_permissions(access_token, instance_id, auth_type="oauth")

        if state_token:
            db.save_wix_credential(
                user_id=state_token,
                site_id=instance_id,
                auth_type="oauth",
                encrypted_refresh_token=encrypt_key(refresh_token),
                encrypted_access_token=encrypt_key(access_token),
                site_display_name=site_info.get("siteDisplayName"),
                site_url=site_info.get("url"),
                permissions=permissions,
            )
        return redirect("/dashboard.html?connected=oauth")
    except Exception as e:
        return f"OAuth Exchange Error: {e}", 400

# --- Live Wix Blog Management (CRUD) ----------------------------------------

@app.get("/api/wix/posts")
@login_required
def get_wix_posts():
    """Fetch live published blog posts and drafts directly from client's Wix site."""
    auth_token, site_id, auth_type = get_active_wix_auth(session["user_id"])
    if not auth_token or not site_id:
        return jsonify({"error": "Wix site not connected."}), 400

    try:
        published_posts = wix_api.list_posts(auth_token, site_id, auth_type=auth_type)
        draft_posts = wix_api.list_draft_posts(auth_token, site_id, auth_type=auth_type)
        return jsonify({
            "published": published_posts,
            "drafts": draft_posts,
            "totalPublished": len(published_posts),
            "totalDrafts": len(draft_posts),
        })
    except Exception as e:
        return jsonify({"error": f"Failed to fetch posts from Wix: {e}"}), 500

@app.post("/api/wix/posts")
@login_required
def create_wix_post():
    """Create a new post directly on client's Wix site (as draft or published)."""
    auth_token, site_id, auth_type = get_active_wix_auth(session["user_id"])
    if not auth_token or not site_id:
        return jsonify({"error": "Wix site not connected."}), 400

    data = request.get_json(force=True)
    title = data.get("title", "").strip()
    content = data.get("content", "").strip()
    image_url = data.get("imageUrl")
    publish_now = data.get("publishNow", False)

    if not title or not content:
        return jsonify({"error": "Title and content are required."}), 400

    try:
        draft_id = wix_api.create_draft_post(
            auth_token, site_id, title, content, image_url=image_url, auth_type=auth_type
        )
        post_id = None
        if publish_now:
            post_id = wix_api.publish_draft_post(auth_token, site_id, draft_id, auth_type=auth_type)
            db.record_audit_log(session["user_id"], "PUBLISHED_POST_TO_WIX", {"title": title, "postId": post_id})
            return jsonify({"success": True, "published": True, "postId": post_id, "draftId": draft_id})
        else:
            db.record_audit_log(session["user_id"], "CREATED_WIX_DRAFT", {"title": title, "draftId": draft_id})
            return jsonify({"success": True, "published": False, "draftId": draft_id})
    except Exception as e:
        return jsonify({"error": f"Failed to create post on Wix: {e}"}), 500

@app.post("/api/wix/drafts/<draft_id>/publish")
@login_required
def publish_existing_wix_draft(draft_id):
    """Publish an existing Wix draft post to live on client's website."""
    auth_token, site_id, auth_type = get_active_wix_auth(session["user_id"])
    if not auth_token or not site_id:
        return jsonify({"error": "Wix site not connected."}), 400

    try:
        post_id = wix_api.publish_draft_post(auth_token, site_id, draft_id, auth_type=auth_type)
        db.record_audit_log(session["user_id"], "PUBLISHED_WIX_DRAFT", {"draftId": draft_id, "postId": post_id})
        return jsonify({"success": True, "postId": post_id})
    except Exception as e:
        return jsonify({"error": f"Failed to publish draft: {e}"}), 500

@app.delete("/api/wix/posts/<post_id>")
@login_required
def delete_wix_post(post_id):
    """Delete a blog post or draft from the client's Wix website."""
    auth_token, site_id, auth_type = get_active_wix_auth(session["user_id"])
    if not auth_token or not site_id:
        return jsonify({"error": "Wix site not connected."}), 400

    is_draft = request.args.get("isDraft", "false").lower() == "true"
    try:
        wix_api.delete_post(auth_token, site_id, post_id, is_draft=is_draft, auth_type=auth_type)
        db.record_audit_log(session["user_id"], "DELETED_WIX_POST", {"postId": post_id, "isDraft": is_draft})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": f"Failed to delete post from Wix: {e}"}), 500

@app.get("/api/wix/categories")
@login_required
def get_wix_categories():
    """Fetch blog categories from connected Wix site."""
    auth_token, site_id, auth_type = get_active_wix_auth(session["user_id"])
    if not auth_token or not site_id:
        return jsonify([])
    categories = wix_api.list_categories(auth_token, site_id, auth_type=auth_type)
    return jsonify(categories)

# --- Local Drafts & Automation Queue -----------------------------------------

@app.post("/api/blogs")
@login_required
def create_blog_draft():
    data = request.get_json(force=True)
    title, content = data.get("title"), data.get("content")
    if not title or not content:
        return jsonify({"error": "Title and content are required."}), 400
    blog = db.save_blog(session["user_id"], title, content, data.get("imageUrl") or None)
    return jsonify(blog)

@app.get("/api/blogs")
@login_required
def list_local_blogs():
    return jsonify(db.get_blogs_for_user(session["user_id"]))

@app.post("/api/blogs/<blog_id>/publish")
@login_required
def publish_local_blog(blog_id):
    auth_token, site_id, auth_type = get_active_wix_auth(session["user_id"])
    if not auth_token or not site_id:
        return jsonify({"error": "No connected Wix website found. Connect one first."}), 400

    blog = db.get_blog(blog_id)
    if not blog or blog["user_id"] != session["user_id"]:
        return jsonify({"error": "Blog not found."}), 404

    try:
        wix_post_id = wix_api.publish_blog(
            auth_token, site_id, blog["title"], blog["content"], blog["image_url"], auth_type=auth_type
        )
        db.update_blog_status(blog_id, "published", wix_post_id=wix_post_id)
        db.record_audit_log(session["user_id"], "PUBLISHED_LOCAL_BLOG", {"blogId": blog_id, "wixPostId": wix_post_id})
        return jsonify({"success": True, "wixPostId": wix_post_id})
    except Exception as e:
        db.update_blog_status(blog_id, "failed")
        return jsonify({"error": "Publishing to Wix failed.", "details": str(e)}), 500

@app.post("/api/blogs/<blog_id>/schedule")
@login_required
def schedule_local_blog(blog_id):
    data = request.get_json(force=True)
    scheduled_for = data.get("scheduledFor")
    if not scheduled_for:
        return jsonify({"error": "scheduledFor is required."}), 400

    blog = db.get_blog(blog_id)
    if not blog or blog["user_id"] != session["user_id"]:
        return jsonify({"error": "Blog not found."}), 404

    db.update_blog_status(blog_id, "scheduled", scheduled_for=scheduled_for)
    db.record_audit_log(session["user_id"], "SCHEDULED_BLOG", {"blogId": blog_id, "scheduledFor": scheduled_for})
    return jsonify(db.get_blog(blog_id))

@app.delete("/api/blogs/<blog_id>")
@login_required
def delete_local_blog(blog_id):
    blog = db.get_blog(blog_id)
    if not blog or blog["user_id"] != session["user_id"]:
        return jsonify({"error": "Blog not found."}), 404
    db.delete_blog(blog_id)
    return jsonify({"success": True})

# --- Google Sheets / CSV Import ----------------------------------------------

@app.post("/api/sheets/import")
@login_required
def import_sheet():
    data = request.get_json(force=True)
    csv_url = data.get("csvUrl")
    if not csv_url:
        return jsonify({"error": "csvUrl is required."}), 400

    try:
        resp = requests.get(csv_url, timeout=15)
        resp.raise_for_status()
        reader = csv.DictReader(io.StringIO(resp.text))
        imported = 0
        for row in reader:
            title = (row.get("title") or row.get("Title") or "").strip()
            content = (row.get("content") or row.get("Content") or "").strip()
            image_url = (row.get("image") or row.get("image_url") or row.get("Image") or "").strip() or None
            if title and content:
                db.save_blog(session["user_id"], title, content, image_url=image_url)
                imported += 1
        db.record_audit_log(session["user_id"], "IMPORTED_SHEETS", {"importedCount": imported})
        return jsonify({"imported": imported})
    except Exception as e:
        return jsonify({"error": f"Could not read sheet. Ensure it is published as CSV ({e})"}), 500

# --- Audit Logs --------------------------------------------------------------

@app.get("/api/audit-logs")
@login_required
def get_audit_logs():
    logs = db.get_audit_logs(session["user_id"])
    return jsonify(logs)

# --- Background Scheduler ----------------------------------------------------

def scheduler_loop():
    while True:
        try:
            due_blogs = db.get_due_scheduled_blogs()
            for blog in due_blogs:
                auth_token, site_id, auth_type = get_active_wix_auth(blog["user_id"])
                if not auth_token or not site_id:
                    db.update_blog_status(blog["id"], "failed")
                    continue
                try:
                    wix_post_id = wix_api.publish_blog(
                        auth_token, site_id, blog["title"], blog["content"], blog["image_url"], auth_type=auth_type
                    )
                    db.update_blog_status(blog["id"], "published", wix_post_id=wix_post_id)
                    db.record_audit_log(blog["user_id"], "AUTO_PUBLISHED_SCHEDULED", {
                        "blogId": blog["id"],
                        "title": blog["title"],
                        "wixPostId": wix_post_id
                    })
                    print(f"[Scheduler] Published '{blog['title']}' to Wix.")
                except Exception as e:
                    print(f"[Scheduler] Publish failed for {blog['id']}: {e}")
                    db.update_blog_status(blog["id"], "failed")
        except Exception as e:
            # Handles DB not ready or connection hiccup gracefully
            pass
        time.sleep(60)

threading.Thread(target=scheduler_loop, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)