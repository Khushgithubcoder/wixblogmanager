# -----------------------------------------------------------------------
# Wix API Service Layer
# Supports both:
# 1) Client Scoped API Key (Site-level Authorization)
# 2) Wix App OAuth 2.0 (Access Token + Refresh Token Flow)
# -----------------------------------------------------------------------
import requests
import json
from typing import Dict, Any, Optional, List

WIX_API_BASE = "https://www.wixapis.com"

def _headers(auth_token: str, site_id: str, auth_type: str = "api_key") -> Dict[str, str]:
    """Generate headers for Wix REST API requests based on authorization type.

    Wix REST expects the raw token in the Authorization header (no "Bearer" prefix).
    - api_key: account/site API keys need the wix-site-id header to pick the site.
    - oauth:   app access tokens already carry the app instance, so wix-site-id must NOT be sent
               (the value we store for OAuth is the app instanceId, which is not a site ID).
    """
    headers = {
        "Authorization": auth_token.strip(),
        "Content-Type": "application/json",
    }
    if auth_type != "oauth" and site_id:
        headers["wix-site-id"] = site_id.strip()
    return headers

# --- OAuth 2.0 Token Management ---------------------------------------------

def exchange_oauth_code(app_id: str, app_secret: str, code: str) -> Dict[str, Any]:
    """Exchange authorization code from Wix redirect for access and refresh tokens."""
    url = f"{WIX_API_BASE}/oauth/access"
    payload = {
        "grant_type": "authorization_code",
        "client_id": app_id,
        "client_secret": app_secret,
        "code": code,
    }
    resp = requests.post(url, json=payload, timeout=15)
    if not resp.ok:
        raise RuntimeError(f"Failed to exchange Wix OAuth code: {resp.text}")
    return resp.json()

def refresh_oauth_token(app_id: str, app_secret: str, refresh_token: str) -> Dict[str, Any]:
    """Refresh an expired OAuth access token using long-lived refresh token."""
    url = f"{WIX_API_BASE}/oauth/access"
    payload = {
        "grant_type": "refresh_token",
        "client_id": app_id,
        "client_secret": app_secret,
        "refresh_token": refresh_token,
    }
    resp = requests.post(url, json=payload, timeout=15)
    if not resp.ok:
        raise RuntimeError(f"Failed to refresh Wix OAuth token: {resp.text}")
    return resp.json()

# --- Site Verification & Properties -----------------------------------------

def verify_and_inspect_site(auth_token: str, site_id: str, auth_type: str = "api_key") -> Dict[str, Any]:
    """
    Validates credentials by fetching site properties.
    Returns site metadata including name, URL, and publishing state.
    """
    url = f"{WIX_API_BASE}/site-properties/v4/properties"
    try:
        resp = requests.get(url, headers=_headers(auth_token, site_id, auth_type), timeout=12)
    except requests.RequestException as e:
        raise ConnectionError(f"Network error connecting to Wix API: {e}")

    if resp.status_code == 401:
        raise ValueError("Wix rejected this credential (401 Unauthorized). Verify your API key or OAuth token.")
    if resp.status_code == 403:
        raise ValueError("Permission denied (403 Forbidden). Ensure the credential has 'Site Properties' and 'Blog' permissions.")
    if resp.status_code == 404:
        raise ValueError("Site ID not found (404 Not Found). Double-check the Wix Site ID.")

    resp.raise_for_status()
    data = resp.json().get("properties", {})
    return {
        "title": data.get("title") or data.get("siteDisplayName") or "My Wix Site",
        "url": data.get("url") or "",
        "published": data.get("published", False),
        "language": data.get("language") or "en",
        "timeZone": data.get("timeZone") or "UTC",
        "siteDisplayName": data.get("siteDisplayName") or data.get("title") or "Wix Site",
    }

def check_permissions(auth_token: str, site_id: str, auth_type: str = "api_key") -> Dict[str, bool]:
    """Audit which scopes are successfully authorized on the connected site."""
    headers = _headers(auth_token, site_id, auth_type)
    perms = {
        "site_properties": False,
        "blog_management": False,
        "members_read": False,
        "site_media": False,
    }

    # 1. Test Site Properties
    try:
        r = requests.get(f"{WIX_API_BASE}/site-properties/v4/properties", headers=headers, timeout=8)
        perms["site_properties"] = r.status_code == 200
    except Exception:
        pass

    # 2. Test Blog API
    try:
        r = requests.get(f"{WIX_API_BASE}/blog/v3/posts?paging.limit=1", headers=headers, timeout=8)
        if r.status_code != 200:
            r = requests.get(f"{WIX_API_BASE}/v3/posts?paging.limit=1", headers=headers, timeout=8)
        perms["blog_management"] = r.status_code == 200
    except Exception:
        pass

    # 3. Test Members API
    try:
        r = requests.get(f"{WIX_API_BASE}/members/v1/members?paging.limit=1", headers=headers, timeout=8)
        perms["members_read"] = r.status_code == 200
    except Exception:
        pass

    # 4. Test Media API
    try:
        r = requests.get(f"{WIX_API_BASE}/site-media/v1/files?paging.limit=1", headers=headers, timeout=8)
        perms["site_media"] = r.status_code in [200, 404]
    except Exception:
        pass

    return perms

# --- Member & Media Helpers -------------------------------------------------

def get_site_member_id(auth_token: str, site_id: str, auth_type: str = "api_key") -> Optional[str]:
    """Finds an existing site member to assign as blog post author."""
    try:
        resp = requests.get(
            f"{WIX_API_BASE}/members/v1/members",
            headers=_headers(auth_token, site_id, auth_type),
            params={"fieldsets": "PUBLIC", "paging.limit": 1},
            timeout=10,
        )
        if resp.ok:
            members = resp.json().get("members", [])
            if members:
                return members[0]["id"]
    except Exception:
        pass
    return None

def import_image(auth_token: str, site_id: str, image_url: str, auth_type: str = "api_key") -> str:
    """Imports an external image URL into Wix Site Media Manager and returns Wix Media ID."""
    resp = requests.post(
        f"{WIX_API_BASE}/site-media/v1/files/import",
        headers=_headers(auth_token, site_id, auth_type),
        json={"url": image_url, "mediaType": "IMAGE", "displayName": "Blog cover image"},
        timeout=15,
    )
    if not resp.ok:
        raise RuntimeError(f"Wix Media Import failed: {resp.text}")
    return resp.json()["file"]["id"]

# --- Blog Post Management (CRUD) -------------------------------------------

def list_posts(auth_token: str, site_id: str, limit: int = 50, offset: int = 0, auth_type: str = "api_key") -> List[Dict[str, Any]]:
    """Retrieve published blog posts from the client's Wix website."""
    headers = _headers(auth_token, site_id, auth_type)
    url = f"{WIX_API_BASE}/blog/v3/posts"
    params = {"paging.limit": limit, "paging.offset": offset}
    
    resp = requests.get(url, headers=headers, params=params, timeout=12)
    if resp.status_code == 404:
        # Fallback to alternate endpoint path supported by some Wix versions
        url = f"{WIX_API_BASE}/v3/posts"
        resp = requests.get(url, headers=headers, params=params, timeout=12)
    
    if not resp.ok:
        raise RuntimeError(f"Failed to fetch posts from Wix: {resp.status_code} {resp.text}")
    
    data = resp.json()
    raw_posts = data.get("posts", [])
    
    formatted = []
    for p in raw_posts:
        # Extract cover image if present
        cover_image = None
        media = p.get("media", {})
        if media and "wixMedia" in media:
            img = media["wixMedia"].get("image", {})
            cover_image = img.get("url") or img.get("id")
        
        formatted.append({
            "id": p.get("id"),
            "title": p.get("title", "Untitled"),
            "slug": p.get("slug", ""),
            "excerpt": p.get("excerpt", ""),
            "coverImage": cover_image,
            "status": "published",
            "publishedDate": p.get("firstPublishedDate") or p.get("lastPublishedDate"),
            "metrics": p.get("metrics", {}),
            "memberId": p.get("memberId"),
        })
    return formatted

def list_draft_posts(auth_token: str, site_id: str, limit: int = 50, offset: int = 0, auth_type: str = "api_key") -> List[Dict[str, Any]]:
    """Retrieve draft blog posts from the client's Wix website."""
    headers = _headers(auth_token, site_id, auth_type)
    url = f"{WIX_API_BASE}/blog/v3/draft-posts"
    params = {"paging.limit": limit, "paging.offset": offset}
    
    resp = requests.get(url, headers=headers, params=params, timeout=12)
    if not resp.ok:
        return []
    
    raw_drafts = resp.json().get("draftPosts", [])
    formatted = []
    for d in raw_drafts:
        formatted.append({
            "id": d.get("id"),
            "title": d.get("title", "Untitled Draft"),
            "excerpt": d.get("excerpt", ""),
            "status": "draft",
            "lastModified": d.get("lastModified"),
            "memberId": d.get("memberId"),
        })
    return formatted

def get_post(auth_token: str, site_id: str, post_id: str, auth_type: str = "api_key") -> Dict[str, Any]:
    """Retrieve a single published blog post by ID."""
    headers = _headers(auth_token, site_id, auth_type)
    url = f"{WIX_API_BASE}/blog/v3/posts/{post_id}"
    resp = requests.get(url, headers=headers, timeout=12)
    if resp.status_code == 404:
        url = f"{WIX_API_BASE}/v3/posts/{post_id}"
        resp = requests.get(url, headers=headers, timeout=12)
    resp.raise_for_status()
    return resp.json().get("post", {})

def create_draft_post(
    auth_token: str,
    site_id: str,
    title: str,
    content: str,
    image_url: Optional[str] = None,
    category_ids: Optional[List[str]] = None,
    tag_ids: Optional[List[str]] = None,
    auth_type: str = "api_key",
) -> str:
    """Create a draft blog post on Wix. Returns the draft post ID."""
    headers = _headers(auth_token, site_id, auth_type)
    member_id = get_site_member_id(auth_token, site_id, auth_type)

    # Build richContent (Ricos format supported by Wix Blog API)
    content_nodes = [
        {
            "type": "PARAGRAPH",
            "id": "p1",
            "nodes": [
                {
                    "type": "TEXT",
                    "id": "",
                    "nodes": [],
                    "textData": {"text": content, "decorations": []},
                }
            ],
            "paragraphData": {},
        }
    ]

    media_id = None
    if image_url:
        try:
            media_id = import_image(auth_token, site_id, image_url, auth_type)
            content_nodes.append(
                {
                    "type": "IMAGE",
                    "id": "img1",
                    "nodes": [],
                    "imageData": {
                        "containerData": {"width": {"size": "CONTENT"}, "alignment": "CENTER"},
                        "image": {"src": {"id": media_id}, "width": 900, "height": 600},
                        "altText": title,
                    },
                }
            )
        except Exception as e:
            print(f"[Wix Media] Image import skipped or failed: {e}")

    draft_post: Dict[str, Any] = {
        "title": title,
        "richContent": {"nodes": content_nodes},
    }
    if member_id:
        draft_post["memberId"] = member_id
    if media_id:
        draft_post["media"] = {"wixMedia": {"image": {"id": media_id}}, "displayed": True, "custom": True}
    if category_ids:
        draft_post["categoryIds"] = category_ids
    if tag_ids:
        draft_post["tagIds"] = tag_ids

    create_resp = requests.post(
        f"{WIX_API_BASE}/blog/v3/draft-posts",
        headers=headers,
        json={"draftPost": draft_post},
        timeout=15,
    )
    if not create_resp.ok:
        if create_resp.status_code == 401 and "instanceId" in create_resp.text:
            raise RuntimeError(
                "Wix could not find a Blog app for this connection. Make sure Wix Blog is installed on the "
                "client's site, and that the API key / Wix app has Blog + Site Media permissions "
                "(re-install the app or regenerate the key if you added them recently). "
                f"Raw response: {create_resp.text}"
            )
        raise RuntimeError(f"Wix rejected the draft post: {create_resp.status_code} {create_resp.text}")

    return create_resp.json()["draftPost"]["id"]

def publish_draft_post(auth_token: str, site_id: str, draft_post_id: str, auth_type: str = "api_key") -> str:
    """Publish an existing Wix draft post to live. Returns published post ID."""
    headers = _headers(auth_token, site_id, auth_type)
    publish_resp = requests.post(
        f"{WIX_API_BASE}/blog/v3/draft-posts/{draft_post_id}/publish",
        headers=headers,
        json={},
        timeout=15,
    )
    if not publish_resp.ok:
        raise RuntimeError(f"Wix rejected publishing the draft post: {publish_resp.status_code} {publish_resp.text}")
    return publish_resp.json().get("postId") or draft_post_id

def publish_blog(
    auth_token: str,
    site_id: str,
    title: str,
    content: str,
    image_url: Optional[str] = None,
    auth_type: str = "api_key",
) -> str:
    """Creates a draft on Wix and publishes it immediately."""
    draft_id = create_draft_post(auth_token, site_id, title, content, image_url, auth_type=auth_type)
    return publish_draft_post(auth_token, site_id, draft_id, auth_type=auth_type)

def update_draft_post(
    auth_token: str,
    site_id: str,
    draft_post_id: str,
    title: Optional[str] = None,
    content: Optional[str] = None,
    auth_type: str = "api_key",
) -> bool:
    """Update title or content of an existing draft post on Wix."""
    headers = _headers(auth_token, site_id, auth_type)
    update_data: Dict[str, Any] = {}
    if title:
        update_data["title"] = title
    if content:
        update_data["richContent"] = {
            "nodes": [
                {
                    "type": "PARAGRAPH",
                    "id": "p1",
                    "nodes": [{"type": "TEXT", "id": "", "nodes": [], "textData": {"text": content, "decorations": []}}],
                    "paragraphData": {},
                }
            ]
        }
    
    resp = requests.patch(
        f"{WIX_API_BASE}/blog/v3/draft-posts/{draft_post_id}",
        headers=headers,
        json={"draftPost": update_data},
        timeout=15,
    )
    if not resp.ok:
        raise RuntimeError(f"Failed to update Wix draft: {resp.status_code} {resp.text}")
    return True

def delete_post(auth_token: str, site_id: str, post_id: str, is_draft: bool = False, auth_type: str = "api_key") -> bool:
    """Delete a blog post or draft post from Wix."""
    headers = _headers(auth_token, site_id, auth_type)
    endpoint = f"draft-posts/{post_id}" if is_draft else f"posts/{post_id}"
    url = f"{WIX_API_BASE}/blog/v3/{endpoint}"
    
    resp = requests.delete(url, headers=headers, timeout=12)
    if not resp.ok:
        raise RuntimeError(f"Failed to delete post from Wix: {resp.status_code} {resp.text}")
    return True

def list_categories(auth_token: str, site_id: str, auth_type: str = "api_key") -> List[Dict[str, Any]]:
    """Fetch blog categories from the Wix site."""
    headers = _headers(auth_token, site_id, auth_type)
    resp = requests.get(f"{WIX_API_BASE}/blog/v3/categories", headers=headers, timeout=10)
    if resp.ok:
        return resp.json().get("categories", [])
    return []

def list_tags(auth_token: str, site_id: str, auth_type: str = "api_key") -> List[Dict[str, Any]]:
    """Fetch blog tags from the Wix site."""
    headers = _headers(auth_token, site_id, auth_type)
    resp = requests.get(f"{WIX_API_BASE}/blog/v3/tags", headers=headers, timeout=10)
    if resp.ok:
        return resp.json().get("tags", [])
    return []