# -----------------------------------------------------------------------
# PostgreSQL Database Interface for Wix Management Platform
# Strictly PostgreSQL - No SQLite
# -----------------------------------------------------------------------
import os
import time
import uuid
import json
from datetime import datetime, timezone, timedelta
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
                    auth_type VARCHAR(32) NOT NULL DEFAULT 'oauth',
                    encrypted_refresh_token TEXT,
                    encrypted_access_token TEXT,
                    access_token_expires_at TIMESTAMP WITH TIME ZONE,
                    site_id VARCHAR(128) NOT NULL,
                    site_display_name TEXT,
                    site_url TEXT,
                    author_member_id VARCHAR(64),
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
        _run_migrations(conn)
        print("[PostgreSQL] Tables verified and initialized successfully.")
        conn.close()
    except Exception as e:
        print(f"[PostgreSQL] Notice: Could not connect to PostgreSQL ({e}). Please configure your password in .env")

def _run_migrations(conn):
    """Idempotent upgrades for databases created by earlier versions."""
    steps = [
        # The API-key connection method was removed: purge any stored keys, then drop the column.
        ("DELETE FROM wix_credentials WHERE auth_type <> 'oauth'",),
        ("ALTER TABLE wix_credentials DROP COLUMN IF EXISTS encrypted_api_key",),
        ("ALTER TABLE wix_credentials ALTER COLUMN auth_type SET DEFAULT 'oauth'",),
        ("ALTER TABLE wix_credentials ADD COLUMN IF NOT EXISTS author_member_id VARCHAR(64)",),
        # A Wix site may be linked to one account only.
        ("CREATE UNIQUE INDEX IF NOT EXISTS uq_wix_credentials_site_id ON wix_credentials(site_id)",),
    ]
    for (sql,) in steps:
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[PostgreSQL] Migration skipped ({sql[:60]}...): {e}")


class SiteAlreadyLinked(Exception):
    """The Wix site is already connected to a different account."""


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
    encrypted_refresh_token,
    encrypted_access_token,
    access_token_expires_at,
    site_display_name=None,
    site_url=None,
    permissions=None,
):
    """Store the OAuth connection for a user (one site per user, one user per site)."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM wix_credentials WHERE site_id = %s AND user_id <> %s", (site_id, user_id))
            if cur.fetchone():
                raise SiteAlreadyLinked()
            cur.execute(
                """
                INSERT INTO wix_credentials (
                    user_id, auth_type, encrypted_refresh_token, encrypted_access_token,
                    access_token_expires_at, site_id, site_display_name, site_url, permissions, updated_at
                )
                VALUES (%s, 'oauth', %s, %s, %s, %s, %s, %s, %s::jsonb, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    auth_type = 'oauth',
                    encrypted_refresh_token = EXCLUDED.encrypted_refresh_token,
                    encrypted_access_token = EXCLUDED.encrypted_access_token,
                    access_token_expires_at = EXCLUDED.access_token_expires_at,
                    -- switching to a different site invalidates the chosen post author
                    author_member_id = CASE WHEN wix_credentials.site_id = EXCLUDED.site_id
                                            THEN wix_credentials.author_member_id ELSE NULL END,
                    site_id = EXCLUDED.site_id,
                    site_display_name = COALESCE(EXCLUDED.site_display_name, wix_credentials.site_display_name),
                    site_url = COALESCE(EXCLUDED.site_url, wix_credentials.site_url),
                    permissions = EXCLUDED.permissions,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    user_id, encrypted_refresh_token, encrypted_access_token, access_token_expires_at,
                    site_id, site_display_name, site_url, json.dumps(permissions or {}),
                ),
            )
            conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        raise SiteAlreadyLinked()
    finally:
        conn.close()


def refresh_oauth_tokens(user_id, refresher, skew_seconds=60):
    """
    Refresh the access token at most once per expiry window, safely across workers.

    The credential row is locked (SELECT .. FOR UPDATE) so concurrent callers queue up;
    whoever gets the lock second sees the fresh token and skips the Wix call. This also
    matters because refresh tokens may rotate - two simultaneous refreshes could
    invalidate each other.

    `refresher(row)` must return {"access": enc, "refresh": enc, "expires_at": datetime}.
    Returns the up-to-date credential row (or None if the user has no connection).
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM wix_credentials WHERE user_id = %s FOR UPDATE", (user_id,))
            row = cur.fetchone()
            if not row:
                conn.rollback()
                return None
            row = dict(row)
            exp = row.get("access_token_expires_at")
            if row.get("encrypted_access_token") and exp and exp > datetime.now(timezone.utc) + timedelta(seconds=skew_seconds):
                conn.rollback()
                return row

            new = refresher(row)
            cur.execute(
                """
                UPDATE wix_credentials SET
                    encrypted_access_token = %s,
                    encrypted_refresh_token = %s,
                    access_token_expires_at = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = %s
                RETURNING *
                """,
                (new["access"], new["refresh"], new["expires_at"], user_id),
            )
            updated = dict(cur.fetchone())
            conn.commit()
            return updated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def set_author_member(user_id, member_id):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE wix_credentials SET author_member_id = %s WHERE user_id = %s", (member_id, user_id))
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

# A row stuck in 'publishing' longer than this is assumed to belong to a crashed worker.
STALE_PUBLISHING_MINUTES = 10


def claim_due_scheduled_blogs(limit=10):
    """
    Atomically move due scheduled blogs to 'publishing' and return them.
    FOR UPDATE SKIP LOCKED means every worker/instance gets a disjoint set, so a blog
    can never be picked up (and published) twice.
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE blogs SET status = 'publishing', updated_at = CURRENT_TIMESTAMP
                WHERE id IN (
                    SELECT id FROM blogs
                    WHERE (status = 'scheduled' AND scheduled_for <= CURRENT_TIMESTAMP)
                       OR (status = 'publishing' AND scheduled_for IS NOT NULL
                           AND updated_at < CURRENT_TIMESTAMP - make_interval(mins => %s))
                    ORDER BY scheduled_for
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING *
                """,
                (STALE_PUBLISHING_MINUTES, limit),
            )
            rows = cur.fetchall()
            conn.commit()
            return [dict(r) for r in rows]
    finally:
        conn.close()


def claim_blog_for_publish(blog_id, user_id):
    """Claim one of the user's blogs for a manual publish. Returns the row, or None if not claimable."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE blogs SET status = 'publishing', updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND user_id = %s
                  AND (status IN ('draft', 'scheduled', 'failed')
                       OR (status = 'publishing' AND updated_at < CURRENT_TIMESTAMP - make_interval(mins => %s)))
                RETURNING *
                """,
                (blog_id, user_id, STALE_PUBLISHING_MINUTES),
            )
            row = cur.fetchone()
            conn.commit()
            return dict(row) if row else None
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
