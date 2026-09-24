"""Top-of-day posts from AI subreddits via RSS.

Reddit's JSON API now needs OAuth, but the per-subreddit top/.rss feed is
still public. It carries no vote counts, so rank within the day's top list is
used as the popularity signal. Reddit sometimes blocks cloud IPs; the health
check will flag it if GitHub Actions gets refused.
"""
from __future__ import annotations

import feedparser
import html
import re
import time
from datetime import datetime, timedelta, timezone

from core import Finding, http_get, record_health
from config import REDDIT_SUBS, LOOKBACK_DAYS

_LINK_RE = re.compile(r'<a href="([^"]+)">\[link\]</a>')
_TAG_RE = re.compile(r"<[^>]+>")


def fetch() -> list[Finding]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    findings: list[Finding] = []
    for i, (sub, top_n, lane) in enumerate(REDDIT_SUBS):
        if i:
            time.sleep(4)  # Reddit rate-limits unauthenticated feed requests aggressively
        health_name = f"reddit:r/{sub}"
        try:
            r = http_get(f"https://www.reddit.com/r/{sub}/top/.rss", params={"t": "day"})
        except Exception as e:
            record_health(health_name, False, str(e))
            continue
        entries = feedparser.parse(r.content).entries
        record_health(health_name, bool(entries), f"{len(entries)} entries")
        for rank, e in enumerate(entries[:top_n], start=1):
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
