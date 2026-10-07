# -----------------------------------------------------------------------
# Wix API Service Layer (Wix App OAuth 2.0 only)
#
# Every call here takes an OAuth *access token*. App access tokens already
# identify the app instance (= the client's site), so no site-id header is
# sent. Wix expects the raw token in `Authorization` (no "Bearer" prefix).
# -----------------------------------------------------------------------
import re
import uuid
import requests
from typing import Dict, Any, Optional, List, Tuple, Set

WIX_API_BASE = "https://www.wixapis.com"
PAGING_LIMIT_PARAM = "paging.limit"


class WixApiError(RuntimeError):
    """A non-2xx response from Wix."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class AuthorRequired(Exception):
    """No (unambiguous) blog author has been chosen for this site."""


def _headers(access_token: str) -> Dict[str, str]:
    return {"Authorization": access_token.strip(), "Content-Type": "application/json"}


# --- OAuth 2.0 Token Management ---------------------------------------------

def exchange_oauth_code(app_id: str, app_secret: str, code: str) -> Dict[str, Any]:
    """Exchange the authorization code from the Wix redirect for access + refresh tokens."""
    resp = requests.post(
        f"{WIX_API_BASE}/oauth/access",
        json={"grant_type": "authorization_code", "client_id": app_id, "client_secret": app_secret, "code": code},
        timeout=15,
    )
    if not resp.ok:
        raise WixApiError(f"Failed to exchange Wix OAuth code: {resp.text}", resp.status_code)
    return resp.json()


def refresh_oauth_token(app_id: str, app_secret: str, refresh_token: str) -> Dict[str, Any]:
    """Mint a new (5 minute) access token from the long-lived refresh token."""
    resp = requests.post(
        f"{WIX_API_BASE}/oauth/access",
        json={"grant_type": "refresh_token", "client_id": app_id, "client_secret": app_secret, "refresh_token": refresh_token},
        timeout=15,
    )
    if not resp.ok:
        raise WixApiError(f"Failed to refresh Wix OAuth token: {resp.text}", resp.status_code)
    return resp.json()


# --- Site Verification & Properties -----------------------------------------

def verify_and_inspect_site(access_token: str) -> Dict[str, Any]:
    """Validate the token by fetching site properties; returns site metadata."""
    try:
        resp = requests.get(f"{WIX_API_BASE}/site-properties/v4/properties", headers=_headers(access_token), timeout=12)
    except requests.RequestException as e:
        raise ConnectionError(f"Network error connecting to Wix API: {e}")

    if resp.status_code == 401:
        raise ValueError("Wix rejected this credential (401 Unauthorized). Reconnect your Wix site.")
    if resp.status_code == 403:
        raise ValueError("Permission denied (403 Forbidden). Make sure the app has 'Site Properties' and 'Blog' permissions.")
    if resp.status_code == 404:
        raise ValueError("Site not found (404 Not Found).")

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


def check_permissions(access_token: str) -> Dict[str, bool]:
    """Audit which scopes are successfully authorized on the connected site."""
    headers = _headers(access_token)
    checks = {
        "site_properties": ("/site-properties/v4/properties", (200,)),
        "blog_management": (f"/blog/v3/posts?{PAGING_LIMIT_PARAM}=1", (200,)),
        "members_read": (f"/members/v1/members?{PAGING_LIMIT_PARAM}=1", (200,)),
        "site_media": (f"/site-media/v1/files?{PAGING_LIMIT_PARAM}=1", (200, 404)),
    }
    perms = {}
    for name, (path, ok_codes) in checks.items():
        try:
            r = requests.get(f"{WIX_API_BASE}{path}", headers=headers, timeout=8)
            perms[name] = r.status_code in ok_codes
        except Exception:
            perms[name] = False
    return perms


# --- Members (blog authors) -------------------------------------------------

def list_members(access_token: str, limit: int = 100) -> List[Dict[str, Any]]:
    """List site members that can be chosen as the author of blog posts."""
    resp = requests.get(
        f"{WIX_API_BASE}/members/v1/members",
        headers=_headers(access_token),
        params={"fieldsets": "PUBLIC", PAGING_LIMIT_PARAM: limit},
        timeout=12,
    )
    if not resp.ok:
        raise WixApiError(f"Could not list site members: {resp.status_code} {resp.text}", resp.status_code)
    out = []
    for m in resp.json().get("members", []):
        profile = m.get("profile") or {}
        contact = m.get("contact") or {}
        name = (
            profile.get("nickname")
            or " ".join(filter(None, [contact.get("firstName"), contact.get("lastName")]))
            or m.get("loginEmail")
            or m.get("id")
        )
        out.append({"id": m["id"], "name": name})
    return out


def resolve_author_member_id(access_token: str, chosen_member_id: Optional[str]) -> str:
    """
    Posts must be attributed to a deliberately chosen member. We never guess:
    - an explicit choice wins;
    - otherwise it is only automatic when the site has exactly one member.
    """
    if chosen_member_id:
        return chosen_member_id
    members = list_members(access_token, limit=2)
    if len(members) == 1:
        return members[0]["id"]
    raise AuthorRequired("Choose which site member new posts are published as (Dashboard → Post author) before publishing.")


def import_image(access_token: str, image_url: str) -> str:
    """Import an external image URL into the Wix Media Manager and return the Wix media ID."""
    resp = requests.post(
        f"{WIX_API_BASE}/site-media/v1/files/import",
        headers=_headers(access_token),
        json={"url": image_url, "mediaType": "IMAGE", "displayName": "Blog cover image"},
        timeout=15,
    )
    if not resp.ok:
        raise WixApiError(f"Wix Media Import failed: {resp.text}", resp.status_code)
    return resp.json()["file"]["id"]


# --- Rich content (Ricos) <-> light Markdown ---------------------------------
# The article box accepts a small Markdown subset, so formatting survives:
#   blank/new line = new paragraph, "# " .. "###### " headings, "- " / "* " bullets,
#   "1. " numbered lists, "> " quotes, ``` code fences, "---" divider,
#   **bold**, *italic*, [text](https://link)

_INLINE_RE = re.compile(
    r"\*\*(?P<bold>.+?)\*\*"
    r"|\*(?!\s)(?P<ital>.+?)(?<!\s)\*"
    r"|\[(?P<ltext>[^\]]+)\]\((?P<url>https?://[^\s)]+)\)"
)


def _nid() -> str:
    return uuid.uuid4().hex[:12]


def _text_node(text: str, decorations: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"type": "TEXT", "id": _nid(), "nodes": [], "textData": {"text": text, "decorations": list(decorations)}}


def _inline_nodes(text: str, decorations: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    decorations = decorations or []
    nodes: List[Dict[str, Any]] = []
    pos = 0
    for m in _INLINE_RE.finditer(text):
        if m.start() > pos:
            nodes.append(_text_node(text[pos:m.start()], decorations))
        if m.group("bold") is not None:
            nodes += _inline_nodes(m.group("bold"), decorations + [{"type": "BOLD", "fontWeightValue": 700}])
        elif m.group("ital") is not None:
            nodes += _inline_nodes(m.group("ital"), decorations + [{"type": "ITALIC", "italicData": True}])
        else:
            link = {"type": "LINK", "linkData": {"link": {"url": m.group("url"), "target": "BLANK"}}}
            nodes += _inline_nodes(m.group("ltext"), decorations + [link])
        pos = m.end()
    if pos < len(text):
        nodes.append(_text_node(text[pos:], decorations))
    return nodes


def _paragraph(text: str) -> Dict[str, Any]:
    return {"type": "PARAGRAPH", "id": _nid(), "nodes": _inline_nodes(text), "paragraphData": {}}


def _heading_node(stripped: str) -> Optional[Dict[str, Any]]:
    heading = re.match(r"^(#{1,6})\s+(\S(?:.*\S)?)\s*$", stripped)
    if not heading:
        return None
    return {
        "type": "HEADING",
        "id": _nid(),
        "nodes": _inline_nodes(heading.group(2)),
        "headingData": {"level": len(heading.group(1))},
    }


def _divider_node(stripped: str) -> Optional[Dict[str, Any]]:
    if not re.fullmatch(r"(-{3,}|\*{3,}|_{3,})", stripped):
        return None
    return {"type": "DIVIDER", "id": _nid(), "nodes": [], "dividerData": {}}


def _blockquote_node(lines: List[str], start: int) -> Tuple[Optional[Dict[str, Any]], int]:
    if not lines[start].strip().startswith(">"):
        return None, start

    i = start
    quoted: List[Dict[str, Any]] = []
    while i < len(lines) and lines[i].strip().startswith(">"):
        q = lines[i].strip()[1:].strip()
        if q:
            quoted.append(_paragraph(q))
        i += 1
    return {"type": "BLOCKQUOTE", "id": _nid(), "nodes": quoted or [_paragraph("")], "blockquoteData": {}}, i


def _list_item_text(line: str) -> Tuple[Optional[str], bool]:
    stripped = line.strip()
    if not stripped:
        return None, False

    unordered = re.fullmatch(r"[*+-]\s+(\S.*)", stripped)
    if unordered:
        item = unordered.group(1).strip()
        return (item or None), False

    ordered = re.fullmatch(r"\d+[.)]\s+(\S.*)", stripped)
    if ordered:
        item = ordered.group(1).strip()
        return (item or None), True

    return None, False


def _list_node(lines: List[str], start: int) -> Tuple[Optional[Dict[str, Any]], int]:
    item_text, ordered = _list_item_text(lines[start])
    if item_text is None:
        return None, start

    items = []
    i = start
    while i < len(lines):
        current_text, current_ordered = _list_item_text(lines[i])
        if current_text is None or current_ordered != ordered:
            break
        items.append({"type": "LIST_ITEM", "id": _nid(), "nodes": [_paragraph(current_text)], "listItemData": {}})
        i += 1

    node = {
        "type": "ORDERED_LIST" if ordered else "BULLETED_LIST",
        "id": _nid(),
        "nodes": items,
        "orderedListData" if ordered else "bulletedListData": {},
    }
    return node, i


def _code_block_node(lines: List[str], start: int) -> Tuple[Optional[Dict[str, Any]], int]:
    if not lines[start].strip().startswith("```"):
        return None, start

    i = start + 1
    code: List[str] = []
    while i < len(lines) and not lines[i].strip().startswith("```"):
        code.append(lines[i])
        i += 1
    i += 1  # closing fence
    node = {
        "type": "CODE_BLOCK",
        "id": _nid(),
        "nodes": [_text_node("\n".join(code), [])],
        "codeBlockData": {},
    }
    return node, i


def text_to_ricos_nodes(content: str) -> List[Dict[str, Any]]:
    """Convert the editor's plain/Markdown-lite text into Ricos nodes."""
    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    nodes: List[Dict[str, Any]] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped:
            i += 1
            continue

        if stripped.startswith("```"):
            node, i = _code_block_node(lines, i)
            nodes.append(node)
            continue

        node = _heading_node(stripped)
        if node is not None:
            nodes.append(node)
            i += 1
            continue

        node = _divider_node(stripped)
        if node is not None:
            nodes.append(node)
            i += 1
            continue

        node, i = _blockquote_node(lines, i)
        if node is not None:
            nodes.append(node)
            continue

        node, i = _list_node(lines, i)
        if node is not None:
            nodes.append(node)
            continue

        nodes.append(_paragraph(stripped))
        i += 1

    return nodes or [_paragraph(content.strip() or " ")]


_SUPPORTED_NODES = {"PARAGRAPH", "TEXT", "HEADING", "BULLETED_LIST", "ORDERED_LIST", "LIST_ITEM", "BLOCKQUOTE", "CODE_BLOCK", "DIVIDER"}
_SUPPORTED_DECOS = {"BOLD", "ITALIC", "LINK"}


def _inline_rico_text(node: Dict[str, Any], unsupported: Set[str]) -> str:
    if node.get("type") != "TEXT":
        if node.get("type") not in _SUPPORTED_NODES:
            unsupported.add(node.get("type", "UNKNOWN"))
        return "".join(_inline_rico_text(child, unsupported) for child in node.get("nodes", []))
    return _inline_rico_text_data(node, unsupported)


def _inline_rico_text_data(node: Dict[str, Any], unsupported: Set[str]) -> str:
    text = (node.get("textData") or {}).get("text", "")
    for deco in (node.get("textData") or {}).get("decorations", []):
        text = _inline_rico_decoration(text, deco, unsupported)
    return text


def _inline_rico_decoration(text: str, deco: Dict[str, Any], unsupported: Set[str]) -> str:
    deco_type = deco.get("type")
    if deco_type == "BOLD":
        return f"**{text}**"
    if deco_type == "ITALIC":
        return f"*{text}*"
    if deco_type == "LINK":
        url = (((deco.get("linkData") or {}).get("link")) or {}).get("url")
        return f"[{text}]({url})" if url else text
    if deco_type not in _SUPPORTED_DECOS:
        unsupported.add(f"text:{deco_type}")
    return text


def _list_rico_block(block_type: str, items: List[Dict[str, Any]], unsupported: Set[str]) -> List[str]:
    out: List[str] = []
    for index, item in enumerate(items, 1):
        text = " ".join(
            part
            for child in item.get("nodes", [])
            for part in _block_rico_text(child, unsupported)
        )
        prefix = f"{index}. " if block_type == "ORDERED_LIST" else "- "
        out.append(f"{prefix}{text}")
    return out


def _block_rico_text(node: Dict[str, Any], unsupported: Set[str]) -> List[str]:
    node_type = node.get("type")
    kids = node.get("nodes", [])

    if node_type == "PARAGRAPH":
        return ["".join(_inline_rico_text(child, unsupported) for child in kids)]
    if node_type == "HEADING":
        level = (node.get("headingData") or {}).get("level", 2)
        heading = "#" * max(1, min(6, level))
        return [f"{heading} {''.join(_inline_rico_text(child, unsupported) for child in kids)}"]
    if node_type in ("BULLETED_LIST", "ORDERED_LIST"):
        return _list_rico_block(node_type, kids, unsupported)
    if node_type == "BLOCKQUOTE":
        return ["> " + text for child in kids for text in _block_rico_text(child, unsupported)]
    if node_type == "CODE_BLOCK":
        return ["```", "".join(_inline_rico_text(child, unsupported) for child in kids), "```"]
    if node_type == "DIVIDER":
        return ["---"]
    unsupported.add(node_type or "UNKNOWN")
    return []


def ricos_to_text(rich_content: Optional[Dict[str, Any]]) -> Tuple[str, Set[str]]:
    """
    Turn Ricos back into the editor's Markdown-lite text.
    Returns (text, unsupported) where `unsupported` names anything the editor can't
    represent (images, embeds, colours...). Saving edited text replaces the body, so
    the UI warns when this set is non-empty.
    """
    unsupported: Set[str] = set()
    lines: List[str] = []
    for node in (rich_content or {}).get("nodes", []):
        lines.extend(_block_rico_text(node, unsupported))
    return "\n".join(lines), unsupported


# --- Blog Post Management (CRUD) -------------------------------------------

def _check(resp: requests.Response, what: str) -> None:
    if not resp.ok:
        raise WixApiError(f"{what}: {resp.status_code} {resp.text}", resp.status_code)


def list_posts(access_token: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    resp = requests.get(
        f"{WIX_API_BASE}/blog/v3/posts", headers=_headers(access_token),
        params={PAGING_LIMIT_PARAM: limit, "paging.offset": offset}, timeout=12,
    )
    _check(resp, "Failed to fetch posts from Wix")

    formatted = []
    for p in resp.json().get("posts", []):
        cover_image = None
        media = p.get("media") or {}
        if "wixMedia" in media:
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


def list_draft_posts(access_token: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    resp = requests.get(
        f"{WIX_API_BASE}/blog/v3/draft-posts", headers=_headers(access_token),
        params={PAGING_LIMIT_PARAM: limit, "paging.offset": offset}, timeout=12,
    )
    if not resp.ok:
        return []
    return [
        {
            "id": d.get("id"),
            "title": d.get("title", "Untitled Draft"),
            "excerpt": d.get("excerpt", ""),
            "status": "draft",
            "lastModified": d.get("lastModified"),
            "memberId": d.get("memberId"),
        }
        for d in resp.json().get("draftPosts", [])
    ]


def get_post(access_token: str, post_id: str) -> Dict[str, Any]:
    """Fetch a published post *including* its rich content (not returned by default)."""
    resp = requests.get(
        f"{WIX_API_BASE}/blog/v3/posts/{post_id}", headers=_headers(access_token),
        params={"fieldsets": ["RICH_CONTENT"]}, timeout=12,
    )
    _check(resp, "Failed to load post")
    return resp.json().get("post", {})


def get_draft_post(access_token: str, draft_post_id: str) -> Dict[str, Any]:
    resp = requests.get(
        f"{WIX_API_BASE}/blog/v3/draft-posts/{draft_post_id}", headers=_headers(access_token),
        params={"fieldsets": ["RICH_CONTENT"]}, timeout=12,
    )
    _check(resp, "Failed to load draft")
    return resp.json().get("draftPost", {})


def create_draft_post(
    access_token: str,
    title: str,
    content: str,
    member_id: str,
    image_url: Optional[str] = None,
    category_ids: Optional[List[str]] = None,
    tag_ids: Optional[List[str]] = None,
) -> str:
    """Create a draft blog post on Wix. `member_id` is the explicit author. Returns the draft ID."""
    content_nodes = text_to_ricos_nodes(content)

    media_id = None
    if image_url:
        try:
            media_id = import_image(access_token, image_url)
            content_nodes.append({
                "type": "IMAGE", "id": _nid(), "nodes": [],
                "imageData": {
                    "containerData": {"width": {"size": "CONTENT"}, "alignment": "CENTER"},
                    "image": {"src": {"id": media_id}, "width": 900, "height": 600},
                    "altText": title,
                },
            })
        except Exception as e:
            print(f"[Wix Media] Image import skipped or failed: {e}")

    draft_post: Dict[str, Any] = {"title": title, "memberId": member_id, "richContent": {"nodes": content_nodes}}
    if media_id:
        draft_post["media"] = {"wixMedia": {"image": {"id": media_id}}, "displayed": True, "custom": True}
    if category_ids:
        draft_post["categoryIds"] = category_ids
    if tag_ids:
        draft_post["tagIds"] = tag_ids

    resp = requests.post(
        f"{WIX_API_BASE}/blog/v3/draft-posts", headers=_headers(access_token),
        json={"draftPost": draft_post}, timeout=15,
    )
    if not resp.ok:
        if resp.status_code == 401 and "instanceId" in resp.text:
            raise WixApiError(
                "Wix could not find a Blog app for this site. Make sure Wix Blog is installed and the app has "
                "Blog + Site Media permissions (reinstall the app if you added them recently).",
                resp.status_code,
            )
        raise WixApiError(f"Wix rejected the draft post: {resp.status_code} {resp.text}", resp.status_code)
    return resp.json()["draftPost"]["id"]


def publish_draft_post(access_token: str, draft_post_id: str) -> str:
    """Publish a draft. If it was already published, this updates the live post. Returns the post ID."""
    resp = requests.post(
        f"{WIX_API_BASE}/blog/v3/draft-posts/{draft_post_id}/publish",
        headers=_headers(access_token), json={}, timeout=15,
    )
    _check(resp, "Wix rejected publishing the draft post")
    return resp.json().get("postId") or draft_post_id


def update_post(
    access_token: str,
    post_id: str,
    title: str,
    content: Optional[str] = None,
    is_draft: bool = False,
) -> bool:
    """
    Edit a draft or a published post.

    Wix has no "update published post" endpoint. Published posts are edited through
    their draft: PATCH the draft with action UPDATE_PUBLICATION (the live post stays
    up), then publish the draft, which overwrites the live post.

    `content=None` leaves the body untouched (so images/embeds that the text editor
    can't represent aren't destroyed by a title-only edit).
    """
    draft: Dict[str, Any] = {"id": post_id, "title": title}
    if content is not None:
        draft["richContent"] = {"nodes": text_to_ricos_nodes(content)}

    resp = requests.patch(
        f"{WIX_API_BASE}/blog/v3/draft-posts/{post_id}",
        headers=_headers(access_token),
        json={"draftPost": draft, "action": "UPDATE" if is_draft else "UPDATE_PUBLICATION"},
        timeout=15,
    )
    _check(resp, "Failed to update Wix post")

    if not is_draft:
        publish_draft_post(access_token, post_id)
    return True


def delete_post(access_token: str, post_id: str, is_draft: bool = False) -> bool:
    endpoint = f"draft-posts/{post_id}" if is_draft else f"posts/{post_id}"
    resp = requests.delete(f"{WIX_API_BASE}/blog/v3/{endpoint}", headers=_headers(access_token), timeout=12)
    _check(resp, "Failed to delete post from Wix")
    return True


def list_categories(access_token: str) -> List[Dict[str, Any]]:
    resp = requests.get(f"{WIX_API_BASE}/blog/v3/categories", headers=_headers(access_token), timeout=10)
    return resp.json().get("categories", []) if resp.ok else []
