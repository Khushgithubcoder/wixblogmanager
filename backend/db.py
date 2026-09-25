# -----------------------------------------------------------------------
# PostgreSQL Database Interface for Wix Management Platform
# Strictly PostgreSQL - No SQLite
# -----------------------------------------------------------------------
import os
import time
import uuid
import json
from datetime import datetime, timezone
import psycopg2
from psycopg2.extras import RealDictCursor

def get_connection_params():
    """Extract PostgreSQL connection parameters from environment."""
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        return {"dsn": database_url}
    
    return {
        "host": os.environ.get("PGHOST", "localhost"),
        "port": int(os.environ.get("PGPORT", 5432)),
        "user": os.environ.get("PGUSER", "postgres"),
        "password": os.environ.get("PGPASSWORD", ""),
        "dbname": os.environ.get("PGDATABASE", "wix_db"),
    }

def get_conn():
    """Create and return a new PostgreSQL connection with dictionary cursor."""
    params = get_connection_params()
    if "dsn" in params:
        conn = psycopg2.connect(params["dsn"], cursor_factory=RealDictCursor)
    else:
        conn = psycopg2.connect(
            host=params["host"],
            port=params["port"],
            user=params["user"],
            password=params["password"],
            dbname=params["dbname"],
            cursor_factory=RealDictCursor,
        )
    conn.autocommit = False
    return conn

def init_db():
    """Initialize PostgreSQL tables if they do not exist."""
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(64) PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS wix_credentials (
                    user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    auth_type VARCHAR(32) NOT NULL DEFAULT 'api_key',
                    encrypted_api_key TEXT,
                    encrypted_refresh_token TEXT,
                    encrypted_access_token TEXT,
                    access_token_expires_at TIMESTAMP WITH TIME ZONE,
                    site_id VARCHAR(128) NOT NULL,
                    site_display_name TEXT,
                    site_url TEXT,
                    permissions JSONB DEFAULT '{}'::jsonb,
                    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS blogs (
                    id VARCHAR(64) PRIMARY KEY,
                    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    image_url TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'draft',
                    scheduled_for TIMESTAMP WITH TIME ZONE,
                    wix_post_id VARCHAR(128),
                    wix_draft_id VARCHAR(128),
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
                    action VARCHAR(64) NOT NULL,
                    details JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_blogs_user_id ON blogs(user_id);
                CREATE INDEX IF NOT EXISTS idx_blogs_status ON blogs(status);
                CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
                """
            )
            conn.commit()
            print("[PostgreSQL] Tables verified and initialized successfully.")
        conn.close()
    except Exception as e:
        print(f"[PostgreSQL] Notice: Could not connect to PostgreSQL ({e}). Please configure your password in .env")

# --- Users -------------------------------------------------------------

def create_user(email, password_hash):
    conn = get_conn()
    user_id = f"u_{uuid.uuid4().hex[:12]}"
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (id, email, password_hash) VALUES (%s, %s, %s)",
                (user_id, email, password_hash),
            )
            conn.commit()
            return user_id
    except psycopg2.IntegrityError:
        conn.rollback()
        raise ValueError("EMAIL_TAKEN")
    finally:
        conn.close()

def find_user_by_email(email):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()

def find_user_by_id(user_id):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()

# --- Wix Credentials ------------------------------------------------------

def save_wix_credential(
    user_id,
    site_id,
    encrypted_api_key=None,
    site_display_name=None,
    site_url=None,
    auth_type="api_key",
    encrypted_refresh_token=None,
    encrypted_access_token=None,
    access_token_expires_at=None,
    permissions=None,
):
    conn = get_conn()
    permissions_json = json.dumps(permissions or {})
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO wix_credentials (
                    user_id, auth_type, encrypted_api_key, encrypted_refresh_token,
                    encrypted_access_token, access_token_expires_at, site_id,
                    site_display_name, site_url, permissions, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    auth_type = EXCLUDED.auth_type,
                    encrypted_api_key = COALESCE(EXCLUDED.encrypted_api_key, wix_credentials.encrypted_api_key),
                    encrypted_refresh_token = COALESCE(EXCLUDED.encrypted_refresh_token, wix_credentials.encrypted_refresh_token),
                    encrypted_access_token = COALESCE(EXCLUDED.encrypted_access_token, wix_credentials.encrypted_access_token),
                    access_token_expires_at = COALESCE(EXCLUDED.access_token_expires_at, wix_credentials.access_token_expires_at),
                    site_id = EXCLUDED.site_id,
                    site_display_name = COALESCE(EXCLUDED.site_display_name, wix_credentials.site_display_name),
                    site_url = COALESCE(EXCLUDED.site_url, wix_credentials.site_url),
                    permissions = EXCLUDED.permissions,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    user_id,
                    auth_type,
                    encrypted_api_key,
                    encrypted_refresh_token,
                    encrypted_access_token,
                    access_token_expires_at,
                    site_id,
                    site_display_name,
                    site_url,
                    permissions_json,
                ),
            )
            conn.commit()
    finally:
        conn.close()

def get_wix_credential(user_id):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM wix_credentials WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()

def delete_wix_credential(user_id):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM wix_credentials WHERE user_id = %s", (user_id,))
            conn.commit()
    finally:
        conn.close()

# --- Blogs -------------------------------------------------------------------

def save_blog(user_id, title, content, image_url=None, status="draft", scheduled_for=None, wix_post_id=None, wix_draft_id=None):
    conn = get_conn()
    blog_id = f"b_{uuid.uuid4().hex[:12]}"
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO blogs (id, user_id, title, content, image_url, status, scheduled_for, wix_post_id, wix_draft_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (blog_id, user_id, title, content, image_url, status, scheduled_for, wix_post_id, wix_draft_id),
            )
            row = cur.fetchone()
            conn.commit()
            return dict(row) if row else None
    finally:
        conn.close()

def get_blog(blog_id):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM blogs WHERE id = %s", (blog_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()

def get_blogs_for_user(user_id):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM blogs WHERE user_id = %s ORDER BY created_at DESC", (user_id,)
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    finally:
        conn.close()

def update_blog_status(blog_id, status, wix_post_id=None, scheduled_for=None, wix_draft_id=None):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE blogs SET
                    status = %s,
                    wix_post_id = COALESCE(%s, wix_post_id),
                    scheduled_for = COALESCE(%s, scheduled_for),
                    wix_draft_id = COALESCE(%s, wix_draft_id),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (status, wix_post_id, scheduled_for, wix_draft_id, blog_id),
            )
            conn.commit()
    finally:
        conn.close()

def delete_blog(blog_id):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM blogs WHERE id = %s", (blog_id,))
            conn.commit()
    finally:
        conn.close()

def get_due_scheduled_blogs():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM blogs
                WHERE status = 'scheduled' AND scheduled_for <= CURRENT_TIMESTAMP
                """
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    finally:
        conn.close()

# --- Audit Logs --------------------------------------------------------------

def record_audit_log(user_id, action, details=None):
    conn = get_conn()
    details_json = json.dumps(details or {})
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_logs (user_id, action, details) VALUES (%s, %s, %s::jsonb)",
                (user_id, action, details_json),
            )
            conn.commit()
    except Exception as e:
        print(f"[AuditLog] Error recording log: {e}")
    finally:
        conn.close()

def get_audit_logs(user_id, limit=50):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_logs WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
                (user_id, limit),
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]
    finally:
        conn.close()
