"""Popular posts from AI labs, researchers, and AI-security people on X.

Optional: runs only when X_BEARER_TOKEN is set, because reading from the X
API requires a paid plan. Uses v2 recent search with a "from:a OR from:b"
query per chunk of accounts, then keeps posts with at least X_MIN_LIKES.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from core import Finding, http_get, record_health
from config import X_ACCOUNTS, X_MIN_LIKES, LOOKBACK_DAYS

SEARCH_API = "https://api.x.com/2/tweets/search/recent"
QUERY_MAX_LEN = 512  # lowest limit across X API plans
MAX_PAGES = 3


def _query_chunks(accounts: list[str]) -> list[str]:
    suffix = " -is:retweet -is:reply"
    chunks, current = [], []
    for a in accounts:
        candidate = " OR ".join(f"from:{x}" for x in current + [a])
        if current and len(f"({candidate}){suffix}") > QUERY_MAX_LEN:
            chunks.append(current)
            current = [a]
        else:
            current.append(a)
    if current:
        chunks.append(current)
    return ["(" + " OR ".join(f"from:{x}" for x in c) + ")" + suffix for c in chunks]


def fetch() -> list[Finding]:
    token = os.environ.get("X_BEARER_TOKEN")
    if not token:
        print("[x] X_BEARER_TOKEN not set; skipping X")
        return []

    start = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers = {"Authorization": f"Bearer {token}"}
    findings: list[Finding] = []
    ok, errors = 0, []
    for query in _query_chunks(X_ACCOUNTS):
        next_token = None
        for _ in range(MAX_PAGES):
            params = {
                "query": query,
                "start_time": start,
                "max_results": 100,
                "tweet.fields": "created_at,public_metrics,entities",
                "expansions": "author_id",
                "user.fields": "username",
            }
            if next_token:
                params["next_token"] = next_token
            try:
                data = http_get(SEARCH_API, params=params, headers=headers).json()
            except Exception as e:
                errors.append(str(e))
                break
            ok += 1
            users = {u["id"]: u["username"] for u in data.get("includes", {}).get("users", [])}
            for t in data.get("data", []):
                likes = t.get("public_metrics", {}).get("like_count", 0)
                if likes < X_MIN_LIKES:
                    continue
                username = users.get(t.get("author_id"), "i")
                post_url = f"https://x.com/{username}/status/{t['id']}"
                links = [
                    u.get("expanded_url", "") for u in t.get("entities", {}).get("urls", [])
                    if u.get("expanded_url") and not u["expanded_url"].startswith(("https://x.com", "https://twitter.com"))
                ]
                text = " ".join(t.get("text", "").split())
                findings.append(Finding(
                    source=f"x:@{username}",
                    category="discussion",
                    title=text[:140],
                    url=links[0] if links else post_url,
                    summary=text[:600],
                    published=t.get("created_at"),
                    lane="developments",
                    boost=min(likes // 500, 8) + 1,
                    popularity=f"♥ {likes:,} on X (@{username})",
                    discussion_url=post_url if links else "",
                ))
            next_token = data.get("meta", {}).get("next_token")
            if not next_token:
                break
    record_health("x", ok > 0 and not errors, "; ".join(errors) or f"{ok} page(s)")
    return findings


if __name__ == "__main__":
    for f in fetch():
        print(f.popularity, "|", f.title)
