"""Standout posts from AI and security accounts on Bluesky (public API, no auth).

A post surfaces when its likes clear max(BSKY_MIN_LIKES, BSKY_MEDIAN_MULT x
the account's recent median likes). That adapts to each account: a prolific
poster needs an unusually popular post, a quiet one needs less.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from statistics import median

from core import Finding, http_get, record_health, ai_related, parse_dt
from config import (
    BSKY_AI_ACCOUNTS, BSKY_GENERAL_ACCOUNTS, BSKY_MIN_LIKES, BSKY_MEDIAN_MULT, LOOKBACK_DAYS,
)

FEED_API = "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed"


def _external(post: dict) -> dict:
    """The link card attached to a post, if any (plain or with media)."""
    embed = post.get("embed") or {}
    ext = embed.get("external") or (embed.get("media") or {}).get("external")
    return ext or {}


def _account(handle: str, ai_only: bool) -> list[Finding]:
    health_name = f"bluesky:{handle}"
    try:
        feed = http_get(FEED_API, params={"actor": handle, "limit": 50, "filter": "posts_no_replies"}).json()
    except Exception as e:
        record_health(health_name, False, str(e))
        return []
    posts = [i["post"] for i in feed.get("feed", []) if "reason" not in i]  # drop reposts
    record_health(health_name, True, f"{len(posts)} posts")
    if not posts:
        return []

    threshold = max(BSKY_MIN_LIKES, BSKY_MEDIAN_MULT * median(p.get("likeCount", 0) for p in posts))
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    findings: list[Finding] = []
    for p in posts:
        record = p.get("record") or {}
        created = parse_dt(record.get("createdAt"))
        likes = p.get("likeCount", 0)
        if not created or created < cutoff or likes < threshold:
            continue
        text = record.get("text", "")
        ext = _external(p)
        if not ext.get("uri") and len(text.strip()) < 60:
            continue  # a bare "yes." with no link or substance isn't a development
        if ai_only and not ai_related(f"{text} {ext.get('title', '')} {ext.get('description', '')}"):
            continue
        post_url = f"https://bsky.app/profile/{handle}/post/{p['uri'].rsplit('/', 1)[-1]}"
        title = ext.get("title") or " ".join(text.split())[:140]
        findings.append(Finding(
            source=f"bluesky:{handle}",
            category="discussion",
            title=title or post_url,
            url=ext.get("uri") or post_url,
            summary=" ".join(f"{text} {ext.get('description', '')}".split())[:600],
            published=created.isoformat(),
            lane="developments",
            boost=min(likes // 50, 6) + 1,
            popularity=f"♥ {likes:,} on Bluesky (@{handle})",
            discussion_url=post_url if ext.get("uri") else "",
        ))
    return findings


def fetch() -> list[Finding]:
    accounts = [(h, False) for h in BSKY_AI_ACCOUNTS] + [(h, True) for h in BSKY_GENERAL_ACCOUNTS]
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        for items in pool.map(lambda a: _account(*a), accounts):
            findings.extend(items)
    return findings


if __name__ == "__main__":
    for f in fetch():
        print(f.popularity, "|", f.title, "|", f.url)
