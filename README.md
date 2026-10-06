# Wix Account & Website Management Platform

A secure platform allowing clients to connect their existing Wix website and blog to our application without ever sharing their Wix login credentials. Once authorized, our backend manages their live blog posts, drafts, media, and site content programmatically.

---

## Architecture: Zero-Credential Sharing

```
┌─────────────────────────────────────────────────────────────────┐
│                          OUR PLATFORM                           │
│                                                                 │
│  Frontend (Dashboard, Blog Manager, Post Creator, Queue)       │
│                                │                                │
│  Backend (Flask + Python)      │                                │
│       ├── wix_api.py (Wix REST API Service Layer)               │
│       ├── crypto_utils.py (Fernet AES-256 Encryption at Rest)  │
│       └── db.py (PostgreSQL Database Engine)                    │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                 Authorization Flow (No Passwords)
                 - Wix App OAuth 2.0 (one-click install)
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                       CLIENT WIX ACCOUNT                        │
│                                                                 │
│  Client's Wix Website & Dashboard                               │
│       ├── Wix Blog v3 REST API (Manage Posts, Drafts, Tags)     │
│       ├── Wix Site Media Manager (Host Featured Images on CDN)  │
│       ├── Wix Site Properties (Name, Live URL, Publish State)   │
│       └── Wix CMS Collections / Data API (Dynamic Site Content) │
└─────────────────────────────────────────────────────────────────┘
```

---

## Research: What Wix Allows via Authorized 3rd-Party App vs. Wix Editor

Connecting to a Wix site via an authorized app does **not** grant unrestricted access to the visual drag-and-drop Wix Editor. Here are the exact boundaries:

### 1. What IS 100% Manageable via API:
* **Wix Blog (Full CRUD)**:
  * Fetch all published blog posts (`GET /blog/v3/posts`)
  * Fetch all draft posts (`GET /blog/v3/draft-posts`)
  * Create new posts with rich formatting (`POST /blog/v3/draft-posts`)
  * Edit and update existing posts/drafts (`PATCH /blog/v3/draft-posts/{id}`)
  * Publish drafts to live immediately (`POST /blog/v3/draft-posts/{id}/publish`)
  * Delete posts and drafts (`DELETE /blog/v3/posts/{id}`)
  * Manage categories, tags, and assign real site member authors
* **Wix Media Manager**:
  * Upload, import, and host images/media on Wix CDN (`POST /site-media/v1/files/import`)
* **Site Properties**:
  * Read site title, live URL, locale, timezone, and published status
* **Wix CMS / Data Collections (`wix-data`)**:
  * If the client's site uses Wix CMS (content collections / datasets) for dynamic pages, portfolios, testimonials, team members, or announcements, our API has **full CRUD** over all collection items (`/wix-data/v2/items`)
* **Wix eCommerce, Bookings & CRM**:
  * Products, orders, inventory, booking services, contacts, and form submissions

### 2. What CANNOT Be Managed via API (Wix Editor Boundary):
* **Visual Canvas / Drag-and-Drop Layout**: Wix does **not** provide a REST API to alter visual DOM canvas elements (e.g. moving buttons, changing header font styles, or dragging visual layout containers in the Wix Editor/Studio).
* **Workaround for Site Content**: Any website section the client wants dynamically managed (e.g. testimonials, announcements, banners, pricing tables) should be connected in the Wix Editor to a **Wix CMS Collection**. Once connected, our backend updates the collection via API, and the live site updates automatically!

---

## Database Configuration (PostgreSQL)

This application uses **PostgreSQL exclusively**.

1. In `backend/.env`, set your PostgreSQL password in `DATABASE_URL`:
   ```env
   DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/wix_db
   ```
   Or set individual parameters:
   ```env
   PGHOST=localhost
   PGPORT=5432
   PGUSER=postgres
   PGPASSWORD=YOUR_PASSWORD
   PGDATABASE=wix_db
   ```
2. When the backend starts, it automatically creates the necessary tables (`users`, `wix_credentials`, `blogs`, `audit_logs`). You can also inspect or run `database/schema.sql`.

---

## How Clients Connect (Step-by-Step)

### Wix App OAuth 2.0 (1-Click App Install)
1. Configure `WIX_APP_ID`, `WIX_APP_SECRET` and `WIX_REDIRECT_URI`. The backend supplies `WIX_REDIRECT_URI` as the `redirectUrl` query parameter when it builds the Wix installer URL; it is not configured in the Wix app settings.
2. The client clicks **Connect with Wix** on the *Connect Wix* page.
3. The server stores a random, single-use `state` in the client's session and sends them to Wix's installer.
4. The client reviews permissions and clicks **Add to Site**.
5. Wix redirects back with an authorization code **and our `state`**. The callback only proceeds if the state matches the one issued to that logged-in session; the account that receives the site is always the session user.
6. The backend exchanges the code, encrypts the tokens (Fernet/AES), and stores them. Access tokens last ~5 minutes; they are cached with their expiry and refreshed only when needed (under a row lock, so concurrent requests/workers refresh once).
7. Choose the **Post author** on the dashboard. Posts are never attributed to an automatically-picked member (exception: a site with exactly one member).

> The old site-scoped API-key method was removed. On startup, any stored API-key connections are deleted and the `encrypted_api_key` column is dropped - those users must reconnect with OAuth.

---

## Running the Application

### 1. Configure Environment
```bash
cd backend
# Edit .env and enter your PostgreSQL password and secrets
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Backend
```bash
python app.py
```
Visit `http://localhost:5000` to access the application.

## Deploying on Render

This repository includes `render.yaml` for a Render Blueprint deployment. From the Render dashboard:

1. Select **New → Blueprint** and connect the GitHub repository.
2. Apply the Blueprint. It creates the Flask web service and PostgreSQL database and generates `SESSION_SECRET`.
3. In the web service environment, set `ENCRYPTION_KEY` to a Fernet key generated with:
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
4. After the web service has a public URL, set `WIX_REDIRECT_URI` in the web service environment to the public callback endpoint:
  `https://YOUR-RENDER-DOMAIN.onrender.com/api/wix/oauth/callback`
5. Set `WIX_APP_ID` and `WIX_APP_SECRET` in Render. The app passes the callback URL to Wix's installer flow at connection time.

Render supplies `DATABASE_URL` automatically from the managed PostgreSQL database.

### Required environment variables (production)

| Variable | Purpose |
|---|---|
| `SESSION_SECRET` | Signs login cookies. **The app refuses to start in production without a random value of 32+ chars.** (Render generates it.) |
| `ENCRYPTION_KEY` | Fernet key used to encrypt Wix tokens at rest. |
| `SIGNUP_INVITE_CODE` | Sign-ups are **closed** unless this is set; people need the code to register. |
| `WIX_APP_ID` / `WIX_APP_SECRET` / `WIX_REDIRECT_URI` | Wix OAuth app. |
| `ENABLE_INAPP_SCHEDULER` | `1` (default) runs the scheduler thread in the web process; set `0` if you use the cron job (`backend/run_scheduler.py`). |
| `FLASK_DEBUG` | Local only. `1` enables the Werkzeug debugger (remote code execution if exposed). |

### Render free-tier limits to know about
* Free web services sleep after ~15 minutes without traffic, so the in-app scheduler is not running while asleep. Scheduled posts are published late, when the service next wakes. Use a paid plan, or a Render Cron Job running `python backend/run_scheduler.py` every minute (see `render.yaml`).
* Free Render Postgres **expires 30 days after creation** (14-day grace period, then deleted) and has no backups.
* `GET /healthz` is a cheap health check that doesn't touch the database.

---

## Features Built

1. **Authentication**: Invite-only signup, login with rate limiting, hardened session cookies.
2. **Site Connection**: Live validation against `wixapis.com/site-properties/v4/properties` with permission audits.
3. **Wix Blog Manager (`wix-posts.html`)**:
   * View live published posts and drafts directly from the client's Wix site
   * Preview posts on the live site
   * Publish Wix drafts to live with 1 click
   * Delete posts from Wix
4. **Post Authoring & Scheduling (`create-blog.html`)**:
   * Create drafts or publish live; the body supports headings, lists, quotes, bold/italic and links (Markdown-lite)
   * Edit published posts (via draft `UPDATE_PUBLICATION` + publish)
   * Automatic image upload to Wix Media Manager
   * Background automated scheduler for future publication
5. **Batch Import (`import-sheets.html`)**: Import up to 200 articles from a published Google Sheets CSV (only `docs.google.com` links; internal addresses are blocked).
6. **Activity Log & Audit Trail (`history.html`)**: Complete log of all management actions performed on Wix.
