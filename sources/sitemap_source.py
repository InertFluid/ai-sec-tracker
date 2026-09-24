"""Watch sitemaps of sites that have no RSS feed (Anthropic, Mistral, xAI,
AI-security vendors) and surface pages that weren't there last run.

New-URL detection is used instead of <lastmod> because many sites bump
lastmod whenever an old post is edited, and some omit it entirely. The set of
known URLs per site lives in state.json (as short hashes). The first run for a
site records a baseline without emitting anything.

Baselines are only committed after the digest is delivered, so a failed post
doesn't lose new pages: main.py copies ``pending_baselines`` into state.
"""
from __future__ import annotations

import hashlib
import html
import re
from concurrent.futures import ThreadPoolExecutor

from core import Finding, http_get, record_health, normalize_url
from config import SITEMAP_WATCHES, SITEMAP_MAX_NEW

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>")
_META_RE = {
    "title": [
        re.compile(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)', re.I),
        re.compile(r"<title[^>]*>([^<]+)</title>", re.I),
    ],
    "description": [
        re.compile(r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)', re.I),
        re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', re.I),
    ],
}

# Set by fetch(); main.py persists it only after a successful post.
pending_baselines: dict[str, list[str]] = {}


def _hash(url: str) -> str:
    return hashlib.sha1(normalize_url(url).encode()).hexdigest()[:12]


def _sitemap_urls(url: str, depth: int = 0) -> list[str]:
    text = http_get(url, timeout=30).text
    locs = _LOC_RE.findall(text)
    if "<sitemapindex" in text and depth < 2:
        out: list[str] = []
        for child in locs[:25]:
            out.extend(_sitemap_urls(html.unescape(child), depth + 1))
        return out
    return [html.unescape(u) for u in locs]


def _page_meta(url: str) -> tuple[str, str]:
    try:
        text = http_get(url, timeout=20, retries=1).text[:200_000]
    except Exception:
        return "", ""
    found = {}
    for key, patterns in _META_RE.items():
        for p in patterns:
            m = p.search(text)
            if m:
                found[key] = " ".join(html.unescape(m.group(1)).split())
                break
    return found.get("title", ""), found.get("description", "")


def _slug_title(url: str) -> str:
    slug = url.rstrip("/").rsplit("/", 1)[-1]
    return slug.replace("-", " ").replace("_", " ").strip().capitalize() or url


def _watch(watch: dict, known: list[str] | None) -> tuple[list[Finding], list[str]]:
    name = watch["name"]
    health_name = f"sitemap:{name}"
    try:
        urls = _sitemap_urls(watch["sitemap"])
    except Exception as e:
        record_health(health_name, False, str(e))
        return [], known or []

    include = re.compile(watch["include"])
    exclude = re.compile(watch["exclude"]) if watch.get("exclude") else None
    matched = [u for u in urls if include.search(u) and not (exclude and exclude.search(u))]
    if not matched:
        record_health(health_name, False, f"{len(urls)} URLs, none match include pattern")
        return [], known or []

    hashes = {_hash(u): u for u in matched}
    if known is None:
        record_health(health_name, True, f"baseline recorded: {len(hashes)} pages")
        return [], sorted(hashes)

    known_set = set(known)
    new_urls = [u for h, u in hashes.items() if h not in known_set]
    # Keep hashes of pages that vanished too, so a page that briefly drops out
    # of the sitemap isn't reported as new when it returns.
    baseline = sorted(known_set | set(hashes))
    if len(new_urls) > SITEMAP_MAX_NEW:
        record_health(health_name, True, f"re-baselined: {len(new_urls)} new URLs looks like a site restructure")
        return [], baseline
    record_health(health_name, True, f"{len(matched)} pages, {len(new_urls)} new")

    lane = "developments" if watch["lane"] == "developments" else "security"
    findings: list[Finding] = []
    for url in new_urls:
        title, desc = _page_meta(url)
        findings.append(Finding(
            source=f"site:{name}",
            category="news" if lane == "developments" else "blog",
            title=title or _slug_title(url),
            url=url,
            summary=desc[:600],
            lane=lane,
            trusted=lane == "security",
            boost=4 if lane == "developments" else 0,
        ))
    return findings, baseline


def fetch(baselines: dict[str, list[str]]) -> list[Finding]:
    global pending_baselines
    pending_baselines = dict(baselines)
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = pool.map(lambda w: (w["name"], _watch(w, baselines.get(w["name"]))), SITEMAP_WATCHES)
        for name, (items, baseline) in results:
            findings.extend(items)
            pending_baselines[name] = baseline
    return findings


if __name__ == "__main__":
    for f in fetch({}):
        print(f.source, f.title)
