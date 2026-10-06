import csv
import hmac
import io
import ipaddress
import os
import re
import secrets
import socket
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlencode, urljoin, urlsplit

import requests
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, request, session, jsonify, send_from_directory, redirect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

import db
import wix_api
from crypto_utils import encrypt_key, decrypt_key, check_configured as check_encryption_configured

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

# --- Configuration -----------------------------------------------------------

# Render sets RENDER=true. Anything that looks like a real deployment must be fully configured.
IS_PROD = bool(os.environ.get("RENDER")) or os.environ.get("APP_ENV", "").lower() == "production"


def _load_session_secret() -> str:
    """No hard-coded fallback: a known default would let anyone forge login cookies."""
    secret = os.environ.get("SESSION_SECRET", "").strip()
    if len(secret) >= 32 and secret != "dev-secret-change-me":
        return secret
    if IS_PROD:
        raise RuntimeError("SESSION_SECRET must be set to a random value of at least 32 characters.")
    print("[Config] SESSION_SECRET missing/weak - using a random per-process secret (sessions reset on restart).")
    return secrets.token_hex(32)


app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.secret_key = _load_session_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)
if IS_PROD:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # Render's proxy: real client IP / https
    check_encryption_configured()  # fail fast instead of at the first Wix call

SIGNUP_INVITE_CODE = os.environ.get("SIGNUP_INVITE_CODE", "").strip()
ACCESS_TOKEN_SKEW_SECONDS = 60
OAUTH_STATE_TTL_SECONDS = 15 * 60

# Initialize PostgreSQL tables
db.init_db()


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# --- Helpers -----------------------------------------------------------------

def body() -> dict:
    data = request.get_json(force=True, silent=True)
    return data if isinstance(data, dict) else {}


_failures = defaultdict(list)
_failures_lock = threading.Lock()


def _blocked(key: str, limit: int = 10, window: int = 900) -> bool:
    now = time.time()
    with _failures_lock:
        _failures[key] = [t for t in _failures[key] if now - t < window]
        return len(_failures[key]) >= limit


def _record_failure(key: str) -> None:
    with _failures_lock:
        _failures[key].append(time.time())


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Please log in first."}), 401
        return fn(*args, **kwargs)
    return wrapper


class WixAuthError(Exception):
    """The stored Wix connection can no longer be used; the user must reconnect."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def get_wix_token(user_id):
    """
    Return (access_token, credential_row) or (None, None) if not connected.

    The 5-minute Wix access token is cached (encrypted) with its expiry and only
    refreshed when it is about to expire - not on every call.
    """
    cred = db.get_wix_credential(user_id)
    if not cred or cred.get("auth_type") != "oauth":
        return None, None

    try:
        exp = cred.get("access_token_expires_at")
        if cred.get("encrypted_access_token") and exp and exp > _now() + timedelta(seconds=ACCESS_TOKEN_SKEW_SECONDS):
            return decrypt_key(cred["encrypted_access_token"]), cred

        app_id, app_secret = os.environ.get("WIX_APP_ID"), os.environ.get("WIX_APP_SECRET")
        if not app_id or not app_secret:
            raise WixAuthError("Wix app credentials are not configured on the server.")

        def refresher(row):
            raw_refresh = decrypt_key(row.get("encrypted_refresh_token") or "")
            if not raw_refresh:
                raise WixAuthError("No refresh token stored. Please reconnect your Wix site.")
            tokens = wix_api.refresh_oauth_token(app_id, app_secret, raw_refresh)
            ttl = int(tokens.get("expires_in") or 300)
            return {
                "access": encrypt_key(tokens["access_token"]),
                "refresh": encrypt_key(tokens.get("refresh_token") or raw_refresh),
                "expires_at": _now() + timedelta(seconds=ttl),
            }

        fresh = db.refresh_oauth_tokens(user_id, refresher, ACCESS_TOKEN_SKEW_SECONDS)
        if not fresh:
            return None, None
        return decrypt_key(fresh["encrypted_access_token"]), fresh
    except WixAuthError:
        raise
    except wix_api.WixApiError as e:
        print(f"[OAuth] Refresh failed for {user_id}: {e}")
        raise WixAuthError("Wix rejected the saved connection (the app may have been uninstalled). Please reconnect your Wix site.")
    except Exception as e:  # e.g. cryptography InvalidToken after an ENCRYPTION_KEY change
        print(f"[OAuth] Could not load credentials for {user_id}: {type(e).__name__}")
        raise WixAuthError("Saved Wix credentials could not be read. Please reconnect your Wix site.")


def wix_required(fn):
    """Login + connected Wix site. Injects `token` and `cred` into the view."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Please log in first."}), 401
        try:
            token, cred = get_wix_token(session["user_id"])
        except WixAuthError as e:
            return jsonify({"error": str(e), "reconnect": True}), 400
        if not token:
            return jsonify({"error": "Wix site not connected."}), 400
        return fn(*args, token=token, cred=cred, **kwargs)
    return wrapper


def author_required_response(e):
    return jsonify({"error": str(e), "code": "AUTHOR_REQUIRED"}), 409


# --- Static Frontend Routes --------------------------------------------------

@app.get("/")
def root():
    return send_from_directory(FRONTEND_DIR, "login.html")


@app.get("/healthz")
def healthz():
    return "ok", 200


# --- User Authentication Routes ----------------------------------------------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DUMMY_HASH = generate_password_hash("not-a-real-password")


@app.get("/api/auth/config")
def auth_config():
    return jsonify({"signupEnabled": bool(SIGNUP_INVITE_CODE)})


@app.post("/api/auth/signup")
def signup():
    ip = request.remote_addr or "?"
    if not SIGNUP_INVITE_CODE:
        return jsonify({"error": "Sign-ups are closed. Ask the administrator for an account."}), 403
    if _blocked(f"signup:{ip}"):
        return jsonify({"error": "Too many attempts. Try again later."}), 429

    data = body()
    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")
    invite = str(data.get("inviteCode") or "")

    if not hmac.compare_digest(invite.encode(), SIGNUP_INVITE_CODE.encode()):
        _record_failure(f"signup:{ip}")
        return jsonify({"error": "Invalid invite code."}), 403
    if not EMAIL_RE.match(email) or len(email) > 255:
        return jsonify({"error": "Enter a valid email address."}), 400
    if not 10 <= len(password) <= 128:
        return jsonify({"error": "Password must be 10-128 characters."}), 400

    try:
        user_id = db.create_user(email, generate_password_hash(password))
    except ValueError:
        return jsonify({"error": "An account with that email already exists."}), 409
    except Exception as e:
        print(f"[Signup] DB error: {e}")
        return jsonify({"error": "Could not create the account right now."}), 500

    session.clear()
    session["user_id"] = user_id
    session.permanent = True
    return jsonify({"success": True, "userId": user_id, "email": email})


@app.post("/api/auth/login")
def login():
    ip = request.remote_addr or "?"
    if _blocked(f"login:{ip}"):
        return jsonify({"error": "Too many failed attempts. Try again in a few minutes."}), 429

    data = body()
    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")
    try:
        user = db.find_user_by_email(email)
    except Exception as e:
        print(f"[Login] DB error: {e}")
        return jsonify({"error": "Could not reach the database."}), 500

    ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
    if not user or not ok:
        _record_failure(f"login:{ip}")
        return jsonify({"error": "Invalid email or password."}), 401

    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
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


# --- Wix Connection (OAuth 2.0 only) ----------------------------------------

@app.get("/api/wix/status")
@login_required
def wix_status():
    cred = db.get_wix_credential(session["user_id"])
    if not cred:
        return jsonify({"connected": False})
    return jsonify({
        "connected": True,
        "siteId": cred.get("site_id"),
        "siteName": cred.get("site_display_name") or "Connected Wix Site",
        "siteUrl": cred.get("site_url") or "",
        "authType": "oauth",
        "authorMemberId": cred.get("author_member_id"),
        "permissions": cred.get("permissions") or {},
        "connectedAt": str(cred.get("connected_at") or ""),
    })


@app.post("/api/wix/test-connection")
@wix_required
def test_connection(token, cred):
    try:
        return jsonify({
            "success": True,
            "siteInfo": wix_api.verify_and_inspect_site(token),
            "permissions": wix_api.check_permissions(token),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.post("/api/wix/disconnect")
@login_required
def disconnect_wix():
    """Disconnect the Wix site and purge the encrypted tokens."""
    db.delete_wix_credential(session["user_id"])
    db.record_audit_log(session["user_id"], "DISCONNECTED_WIX_SITE")
    return jsonify({"success": True})


@app.get("/api/wix/oauth/start")
@login_required
def oauth_start():
    """Build the Wix installer URL. The `state` is a random, single-use, session-bound nonce."""
    app_id = os.environ.get("WIX_APP_ID")
    redirect_uri = os.environ.get("WIX_REDIRECT_URI", "http://localhost:5000/api/wix/oauth/callback")
    if not app_id:
        return jsonify({"error": "WIX_APP_ID is not configured on the server."}), 400

    nonce = secrets.token_urlsafe(32)
    session["wix_oauth_state"] = {"value": nonce, "issued": time.time()}
    query = urlencode({"appId": app_id, "redirectUrl": redirect_uri, "state": nonce})
    return jsonify({"installerUrl": f"https://www.wix.com/installer/install?{query}"})


@app.get("/api/wix/oauth/callback")
def oauth_callback():
    """
    Finish the Wix install. The account to attach the site to comes ONLY from the logged-in
    session, and only if the returned state matches the nonce we issued to that session.
    Nothing in the URL can choose which user receives the credentials.
    """
    if "user_id" not in session:
        return redirect("/login.html")

    saved = session.pop("wix_oauth_state", None)  # single use
    returned_state = request.args.get("state")
    state_ok = bool(
        saved
        and time.time() - saved.get("issued", 0) <= OAUTH_STATE_TTL_SECONDS
        and returned_state
        and hmac.compare_digest(saved["value"].encode(), returned_state.encode())
    )
    if not state_ok:
        return "Authorization failed: invalid or expired state. Start the connection again from the dashboard.", 400

    code, instance_id = request.args.get("code"), request.args.get("instanceId")
    if not code or not instance_id:
        return "Authorization failed: missing code or instanceId.", 400

    app_id, app_secret = os.environ.get("WIX_APP_ID"), os.environ.get("WIX_APP_SECRET")
    if not app_id or not app_secret:
        return "Server error: Wix app credentials are not configured.", 500

    try:
        tokens = wix_api.exchange_oauth_code(app_id, app_secret, code)
        access_token, refresh_token = tokens["access_token"], tokens["refresh_token"]
        site_info = wix_api.verify_and_inspect_site(access_token)
        permissions = wix_api.check_permissions(access_token)
        db.save_wix_credential(
            user_id=session["user_id"],
            site_id=instance_id,
            encrypted_refresh_token=encrypt_key(refresh_token),
            encrypted_access_token=encrypt_key(access_token),
            access_token_expires_at=_now() + timedelta(seconds=int(tokens.get("expires_in") or 300)),
            site_display_name=site_info.get("siteDisplayName"),
            site_url=site_info.get("url"),
            permissions=permissions,
        )
        db.record_audit_log(session["user_id"], "CONNECTED_WIX_SITE", {"siteId": instance_id, "siteName": site_info.get("siteDisplayName")})
        return redirect("/dashboard.html?connected=oauth")
    except db.SiteAlreadyLinked:
        return redirect("/connect-wix.html?error=site_taken")
    except Exception as e:
        print(f"[OAuth] Callback failed: {e}")
        return "Could not complete the Wix connection. Please try again.", 400


# --- Post author -------------------------------------------------------------

@app.get("/api/wix/members")
@wix_required
def get_members(token, cred):
    try:
        return jsonify({"members": wix_api.list_members(token), "authorMemberId": cred.get("author_member_id")})
    except Exception as e:
        return jsonify({"error": f"Could not load site members: {e}"}), 500


@app.put("/api/wix/author")
@wix_required
def set_author(token, cred):
    member_id = str(body().get("memberId") or "").strip()
    if not member_id:
        return jsonify({"error": "memberId is required."}), 400
    try:
        if member_id not in {m["id"] for m in wix_api.list_members(token)}:
            return jsonify({"error": "That member does not exist on the connected site."}), 400
    except Exception as e:
        return jsonify({"error": f"Could not verify member: {e}"}), 500
    db.set_author_member(session["user_id"], member_id)
    db.record_audit_log(session["user_id"], "SET_POST_AUTHOR", {"memberId": member_id})
    return jsonify({"success": True, "authorMemberId": member_id})


# --- Live Wix Blog Management (CRUD) ----------------------------------------

MAX_TITLE = 200


def _validate_post_fields(data, content_required=True):
    title = str(data.get("title") or "").strip()
    raw = data.get("content")
    content = None if raw is None else str(raw).strip()
    if not title or len(title) > MAX_TITLE:
        return None, None, f"Title is required (max {MAX_TITLE} characters)."
    if content_required and not content:
        return None, None, "Title and content are required."
    if content is not None and not content:
        return None, None, "Content can't be empty."
    return title, content, None


@app.get("/api/wix/posts")
@wix_required
def get_wix_posts(token, cred):
    try:
        published = wix_api.list_posts(token)
        drafts = wix_api.list_draft_posts(token)
        return jsonify({"published": published, "drafts": drafts, "totalPublished": len(published), "totalDrafts": len(drafts)})
    except Exception as e:
        return jsonify({"error": f"Failed to fetch posts from Wix: {e}"}), 500


@app.post("/api/wix/posts")
@wix_required
def create_wix_post(token, cred):
    data = body()
    title, content, err = _validate_post_fields(data)
    if err:
        return jsonify({"error": err}), 400
    image_url = data.get("imageUrl") or None
    if image_url and not re.match(r"^https?://", str(image_url)):
        return jsonify({"error": "Cover image must be an http(s) URL."}), 400
    publish_now = bool(data.get("publishNow", False))

    try:
        member_id = wix_api.resolve_author_member_id(token, cred.get("author_member_id"))
        draft_id = wix_api.create_draft_post(token, title, content, member_id, image_url=image_url)
        if publish_now:
            post_id = wix_api.publish_draft_post(token, draft_id)
            db.record_audit_log(session["user_id"], "PUBLISHED_POST_TO_WIX", {"title": title, "postId": post_id})
            return jsonify({"success": True, "published": True, "postId": post_id, "draftId": draft_id})
        db.record_audit_log(session["user_id"], "CREATED_WIX_DRAFT", {"title": title, "draftId": draft_id})
        return jsonify({"success": True, "published": False, "draftId": draft_id})
    except wix_api.AuthorRequired as e:
        return author_required_response(e)
    except Exception as e:
        return jsonify({"error": f"Failed to create post on Wix: {e}"}), 500


@app.get("/api/wix/posts/<post_id>")
@wix_required
def get_wix_post(post_id, token, cred):
    """Fetch one post/draft for the edit form, with its body converted back to editor text."""
    is_draft = request.args.get("isDraft", "false").lower() == "true"
    try:
        post = wix_api.get_draft_post(token, post_id) if is_draft else wix_api.get_post(token, post_id)
        text, unsupported = wix_api.ricos_to_text(post.get("richContent"))
        return jsonify({
            "id": post.get("id", post_id),
            "title": post.get("title", ""),
            "contentText": text,
            "unsupportedContent": sorted(unsupported),
        })
    except Exception as e:
        return jsonify({"error": f"Failed to load Wix post: {e}"}), 500


@app.patch("/api/wix/posts/<post_id>")
@wix_required
def update_wix_post(post_id, token, cred):
    """Edit a draft or published post. Omit `content` to leave the body (and any media in it) untouched."""
    data = body()
    title, content, err = _validate_post_fields(data, content_required=False)
    if err:
        return jsonify({"error": err}), 400
    is_draft = request.args.get("isDraft", "false").lower() == "true"
    try:
        wix_api.update_post(token, post_id, title, content, is_draft=is_draft)
        db.record_audit_log(session["user_id"], "UPDATED_WIX_POST", {"postId": post_id, "isDraft": is_draft, "bodyChanged": content is not None})
        return jsonify({"success": True, "isDraft": is_draft})
    except Exception as e:
        return jsonify({"error": f"Failed to update Wix post: {e}"}), 500


@app.post("/api/wix/drafts/<draft_id>/publish")
@wix_required
def publish_existing_wix_draft(draft_id, token, cred):
    try:
        post_id = wix_api.publish_draft_post(token, draft_id)
        db.record_audit_log(session["user_id"], "PUBLISHED_WIX_DRAFT", {"draftId": draft_id, "postId": post_id})
        return jsonify({"success": True, "postId": post_id})
    except Exception as e:
        return jsonify({"error": f"Failed to publish draft: {e}"}), 500


@app.delete("/api/wix/posts/<post_id>")
@wix_required
def delete_wix_post(post_id, token, cred):
    is_draft = request.args.get("isDraft", "false").lower() == "true"
    try:
        wix_api.delete_post(token, post_id, is_draft=is_draft)
        db.record_audit_log(session["user_id"], "DELETED_WIX_POST", {"postId": post_id, "isDraft": is_draft})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": f"Failed to delete post from Wix: {e}"}), 500


@app.get("/api/wix/categories")
@wix_required
def get_wix_categories(token, cred):
    return jsonify(wix_api.list_categories(token))


# --- Local Drafts & Automation Queue -----------------------------------------

def publish_claimed_blog(blog):
    """
    Publish a blog that the caller has ALREADY claimed (status='publishing').
    Used by both the manual button and the scheduler.

    The Wix draft id is stored as soon as it exists, so a retry after a failure or crash
    publishes that same draft instead of creating a second post.
    """
    token, cred = get_wix_token(blog["user_id"])
    if not token:
        raise WixAuthError("No connected Wix site.")

    draft_id = blog.get("wix_draft_id")
    if not draft_id:
        member_id = wix_api.resolve_author_member_id(token, cred.get("author_member_id"))
        draft_id = wix_api.create_draft_post(token, blog["title"], blog["content"], member_id, image_url=blog.get("image_url"))
        db.update_blog_status(blog["id"], "publishing", wix_draft_id=draft_id)

    post_id = wix_api.publish_draft_post(token, draft_id)
    db.update_blog_status(blog["id"], "published", wix_post_id=post_id)
    return post_id


@app.post("/api/blogs")
@login_required
def create_blog_draft():
    data = body()
    title, content, err = _validate_post_fields(data)
    if err:
        return jsonify({"error": err}), 400
    blog = db.save_blog(session["user_id"], title, content, data.get("imageUrl") or None)
    return jsonify(blog)


@app.get("/api/blogs")
@login_required
def list_local_blogs():
    return jsonify(db.get_blogs_for_user(session["user_id"]))


@app.post("/api/blogs/<blog_id>/publish")
@login_required
def publish_local_blog(blog_id):
    blog = db.claim_blog_for_publish(blog_id, session["user_id"])
    if not blog:
        existing = db.get_blog(blog_id)
        if not existing or existing["user_id"] != session["user_id"]:
            return jsonify({"error": "Blog not found."}), 404
        return jsonify({"error": f"This post is already {existing['status']}."}), 409

    try:
        post_id = publish_claimed_blog(blog)
        db.record_audit_log(session["user_id"], "PUBLISHED_LOCAL_BLOG", {"blogId": blog_id, "wixPostId": post_id})
        return jsonify({"success": True, "wixPostId": post_id})
    except wix_api.AuthorRequired as e:
        db.update_blog_status(blog_id, "failed")
        return author_required_response(e)
    except Exception as e:
        db.update_blog_status(blog_id, "failed")
        return jsonify({"error": "Publishing to Wix failed.", "details": str(e)}), 500


def _parse_schedule(value):
    """Accept an ISO-8601 timestamp; a missing timezone is treated as UTC. Returns aware datetime or None."""
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@app.post("/api/blogs/<blog_id>/schedule")
@login_required
def schedule_local_blog(blog_id):
    scheduled_for = _parse_schedule(body().get("scheduledFor"))
    if not scheduled_for:
        return jsonify({"error": "scheduledFor must be a valid date/time."}), 400

    blog = db.get_blog(blog_id)
    if not blog or blog["user_id"] != session["user_id"]:
        return jsonify({"error": "Blog not found."}), 404
    if blog["status"] in ("publishing", "published"):
        return jsonify({"error": f"This post is already {blog['status']}."}), 409

    db.update_blog_status(blog_id, "scheduled", scheduled_for=scheduled_for)
    db.record_audit_log(session["user_id"], "SCHEDULED_BLOG", {"blogId": blog_id, "scheduledFor": scheduled_for.isoformat()})
    return jsonify(db.get_blog(blog_id))


@app.delete("/api/blogs/<blog_id>")
@login_required
def delete_local_blog(blog_id):
    blog = db.get_blog(blog_id)
    if not blog or blog["user_id"] != session["user_id"]:
        return jsonify({"error": "Blog not found."}), 404
    db.delete_blog(blog_id)
    return jsonify({"success": True})


# --- Google Sheets / CSV Import (SSRF-safe) ----------------------------------

CSV_ALLOWED_HOSTS = {"docs.google.com"}
CSV_ALLOWED_SUFFIXES = (".googleusercontent.com",)
CSV_MAX_BYTES = 2 * 1024 * 1024
CSV_MAX_REDIRECTS = 3
CSV_MAX_ROWS = 200


class CsvFetchError(Exception):
    """Safe-to-show reason a sheet could not be fetched."""


def _validate_csv_url(url: str) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443):
        raise CsvFetchError("Use the https link from Google Sheets (File → Share → Publish to web → CSV).")
    if not (host in CSV_ALLOWED_HOSTS or host.endswith(CSV_ALLOWED_SUFFIXES)):
        raise CsvFetchError("Only published Google Sheets links (docs.google.com) are supported.")
    if host == "docs.google.com" and not parts.path.startswith("/spreadsheets/"):
        raise CsvFetchError("That doesn't look like a Google Sheets link.")
    try:
        addresses = {ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)}
    except socket.gaierror:
        raise CsvFetchError("Could not resolve that host.")
    # Even allow-listed names must never resolve to internal/loopback/link-local space.
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise CsvFetchError("That address is not allowed.")


def fetch_public_csv(url: str) -> str:
    """Fetch a published-sheet CSV, validating every redirect hop, with size and time caps."""
    for _ in range(CSV_MAX_REDIRECTS + 1):
        _validate_csv_url(url)
        resp = requests.get(url, timeout=(5, 10), allow_redirects=False, stream=True, headers={"User-Agent": "wix-blog-manager/1.0"})
        try:
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    raise CsvFetchError("Bad redirect from Google.")
                url = urljoin(url, location)
                continue
            if not resp.ok:
                raise CsvFetchError("Google returned an error. Make sure the sheet is published to the web as CSV.")
            chunks, total = [], 0
            for chunk in resp.iter_content(8192):
                total += len(chunk)
                if total > CSV_MAX_BYTES:
                    raise CsvFetchError("The sheet is too large (limit 2 MB).")
                chunks.append(chunk)
            return b"".join(chunks).decode("utf-8-sig", errors="replace")
        finally:
            resp.close()
    raise CsvFetchError("Too many redirects.")


@app.post("/api/sheets/import")
@login_required
def import_sheet():
    csv_url = str(body().get("csvUrl") or "").strip()
    if not csv_url:
        return jsonify({"error": "csvUrl is required."}), 400

    try:
        text = fetch_public_csv(csv_url)
        imported = 0
        for row in csv.DictReader(io.StringIO(text)):
            if imported >= CSV_MAX_ROWS:
                break
            title = (row.get("title") or row.get("Title") or "").strip()[:MAX_TITLE]
            content = (row.get("content") or row.get("Content") or "").strip()[:100_000]
            image_url = (row.get("image") or row.get("image_url") or row.get("Image") or "").strip() or None
            if image_url and not re.match(r"^https?://", image_url):
                image_url = None
            if title and content:
                db.save_blog(session["user_id"], title, content, image_url=image_url)
                imported += 1
        db.record_audit_log(session["user_id"], "IMPORTED_SHEETS", {"importedCount": imported})
        return jsonify({"imported": imported})
    except CsvFetchError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        # Deliberately generic: never reflect low-level fetch errors back to the caller.
        print(f"[Sheets] Import failed: {type(e).__name__}: {e}")
        return jsonify({"error": "Could not read the sheet. Ensure it is published to the web as CSV."}), 500


# --- Audit Logs --------------------------------------------------------------

@app.get("/api/audit-logs")
@login_required
def get_audit_logs():
    return jsonify(db.get_audit_logs(session["user_id"]))


# --- Background Scheduler ----------------------------------------------------

def process_due_blogs():
    """Claim and publish everything that's due. Safe to run from many workers/instances at once."""
    for blog in db.claim_due_scheduled_blogs():
        try:
            post_id = publish_claimed_blog(blog)
            db.record_audit_log(blog["user_id"], "AUTO_PUBLISHED_SCHEDULED", {"blogId": blog["id"], "title": blog["title"], "wixPostId": post_id})
            print(f"[Scheduler] Published '{blog['title']}' to Wix.")
        except Exception as e:
            print(f"[Scheduler] Publish failed for {blog['id']}: {e}")
            db.update_blog_status(blog["id"], "failed")


def scheduler_loop():
    while True:
        try:
            process_due_blogs()
        except Exception as e:
            print(f"[Scheduler] Loop error: {type(e).__name__}: {e}")
        time.sleep(60)


# Set ENABLE_INAPP_SCHEDULER=0 when an external job runs backend/run_scheduler.py instead.
if os.environ.get("ENABLE_INAPP_SCHEDULER", "1") == "1":
    threading.Thread(target=scheduler_loop, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # The Werkzeug debugger allows remote code execution - opt in explicitly, locally only.
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1", use_reloader=False)
