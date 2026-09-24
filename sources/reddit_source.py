"""Top-of-day posts from AI subreddits via RSS.

Reddit's JSON API now needs OAuth, but the top/.rss feed is still public. It
rate-limits unauthenticated clients hard (a second request within seconds
gets a 429), so all subreddits are fetched in ONE combined "a+b+c" feed and
split back out by each entry's subreddit tag. The feed carries no vote
counts, so rank within the subreddit's slice is the popularity signal.
"""
from __future__ import annotations

import feedparser
import html
import re
from datetime import datetime, timedelta, timezone

from core import Finding, http_get, record_health
from config import REDDIT_SUBS, LOOKBACK_DAYS

_LINK_RE = re.compile(r'<a href="([^"]+)">\[link\]</a>')
_TAG_RE = re.compile(r"<[^>]+>")


def _subreddit(entry) -> str:
    for tag in entry.get("tags") or []:
        if tag.get("term"):
            return tag["term"].lower()
    return ""


def fetch() -> list[Finding]:
    if not REDDIT_SUBS:
        return []
    combined = "+".join(sub for sub, _, _ in REDDIT_SUBS)
    try:
        r = http_get(f"https://www.reddit.com/r/{combined}/top/.rss", params={"t": "day", "limit": 100})
    except Exception as e:
        record_health("reddit", False, str(e))
        return []
    entries = feedparser.parse(r.content).entries
    record_health("reddit", bool(entries), f"{len(entries)} entries across {len(REDDIT_SUBS)} subs")

    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    findings: list[Finding] = []
    for sub, top_n, lane in REDDIT_SUBS:
        mine = [e for e in entries if _subreddit(e) == sub.lower()][:top_n]
        for rank, e in enumerate(mine, start=1):
            published = e.get("published_parsed") or e.get("updated_parsed")
            if published and datetime(*published[:6], tzinfo=timezone.utc) < cutoff:
                continue
            content = (e.get("content") or [{}])[0].get("value", "") or e.get("summary", "")
            link = _LINK_RE.search(content)
            external = html.unescape(link.group(1)) if link else ""
            if "reddit.com" in external or "redd.it" in external:
                external = ""
            text = " ".join(html.unescape(_TAG_RE.sub(" ", content)).split())
            text = text.replace("[link]", "").replace("[comments]", "").strip()
            findings.append(Finding(
                source=f"reddit:r/{sub}",
                category="discussion",
                title=e.get("title", "").strip(),
                url=external or e.get("link", ""),
                summary=text[:600],
                published=e.get("published") or e.get("updated"),
                lane=lane,
                boost=3 if rank <= 2 else 1,
                popularity=f"r/{sub} #{rank} today",
                discussion_url=e.get("link", "") if external else "",
            ))
    return findings


if __name__ == "__main__":
    for f in fetch():
        print(f.popularity, "|", f.title, "|", f.url)
