-- ==============================================================================
-- Wix Account & Website Management System - PostgreSQL Schema
-- ==============================================================================

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Wix Connected Credentials
-- Never stores raw API keys or tokens in plain text. Stored as Fernet AES-256 ciphertext.
CREATE TABLE IF NOT EXISTS wix_credentials (
  user_id VARCHAR(64) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  auth_type VARCHAR(32) NOT NULL DEFAULT 'api_key', -- 'api_key' or 'oauth'
  encrypted_api_key TEXT,                           -- Used for API Key flow
  encrypted_refresh_token TEXT,                     -- Used for OAuth App flow
  encrypted_access_token TEXT,                      -- Ephemeral cached token for OAuth
  access_token_expires_at TIMESTAMP WITH TIME ZONE,
  site_id VARCHAR(128) NOT NULL,
  site_display_name TEXT,
  site_url TEXT,
  permissions JSONB DEFAULT '{}'::jsonb,
  connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Blog Posts & Scheduled Queue
CREATE TABLE IF NOT EXISTS blogs (
  id VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  image_url TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'draft', -- 'draft', 'scheduled', 'published', 'failed'
  scheduled_for TIMESTAMP WITH TIME ZONE,
  wix_post_id VARCHAR(128),
  wix_draft_id VARCHAR(128),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit Trail for Management Actions
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
