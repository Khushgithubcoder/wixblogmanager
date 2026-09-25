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
                 - Method 1: Site-Scoped API Key
                 - Method 2: Wix App OAuth 2.0
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

Connecting to a Wix site via an authorized app or API key does **not** grant unrestricted access to the visual drag-and-drop Wix Editor. Here are the exact boundaries:

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

### Method 1: Site-Scoped Wix API Key (Direct & Self-Serve)
1. The client logs into their Wix account.
2. Navigates to **Account Settings → API Keys Manager**.
3. Clicks **Generate API Key**:
   * Scopes: Select **Manage Blog**, **Read Site Properties**, and **Read Members**.
   * Site Access: Restrict specifically to the single website to be managed.
4. Copies the key immediately (Wix shows it once).
5. Enters the **API Key** and **Site ID** in our platform's **Connect Wix** portal.
6. Our backend verifies the key with Wix, audits permissions, encrypts it with **AES-256 (Fernet)**, and stores the encrypted credential in PostgreSQL.
7. *Client can revoke the key at any time in their Wix account settings with 1 click.*

### Method 2: Wix App OAuth 2.0 (1-Click App Install)
1. We configure our registered Wix App ID and Secret in `backend/.env`.
2. The client clicks **Connect via Wix OAuth App**.
3. Client is redirected to Wix's authorization dialog: `wix.com/installer/install?appId=...`.
4. Client reviews permissions and clicks **Add to Site**.
5. Wix redirects back with an authorization code.
6. Backend exchanges code for access and refresh tokens, encrypts them, and binds the site.

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
4. After the web service has a public URL, set `WIX_REDIRECT_URI` in the web service environment to:
  `https://YOUR-RENDER-DOMAIN.onrender.com/api/wix/oauth/callback`
5. If using Wix OAuth, also register that exact callback URL in the Wix app and set `WIX_APP_ID` and `WIX_APP_SECRET` in Render.

The API-key connection flow works without the optional Wix OAuth variables. Render supplies `DATABASE_URL` automatically from the managed PostgreSQL database.

---

## Features Built

1. **Authentication**: Email/password signup and login with secure session handling.
2. **Site Connection**: Live validation against `wixapis.com/site-properties/v4/properties` with permission audits.
3. **Wix Blog Manager (`wix-posts.html`)**:
   * View live published posts and drafts directly from the client's Wix site
   * Preview posts on the live site
   * Publish Wix drafts to live with 1 click
   * Delete posts from Wix
4. **Post Authoring & Scheduling (`create-blog.html`)**:
   * Create drafts or publish live
   * Automatic image upload to Wix Media Manager
   * Background automated scheduler for future publication
5. **Batch Import (`import-sheets.html`)**: Import multiple articles from published Google Sheets CSV.
6. **Activity Log & Audit Trail (`history.html`)**: Complete log of all management actions performed on Wix.
