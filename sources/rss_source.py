"""Fetch recent posts from security research blogs via RSS."""
from __future__ import annotations

import feedparser
from datetime import datetime, timedelta, timezone

from core import Finding
from config import RSS_FEEDS, LOOKBACK_DAYS


def _entry_published(entry) -> datetime | None:
    for attr in ("published_parsed", "updated_parsed"):
        t = getattr(entry, attr, None)
        if t:
            try:
                return datetime(*t[:6], tzinfo=timezone.utc)
            except Exception:
                pass
    return None


def fetch() -> list[Finding]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    findings: list[Finding] = []
    for name, url in RSS_FEEDS:
        try:
            parsed = feedparser.parse(url)
        except Exception as e:
            print(f"[rss:{name}] error: {e}")
            continue
        for entry in parsed.entries[:20]:
            published = _entry_published(entry)
            if not published or published < cutoff:
                continue
            summary = getattr(entry, "summary", "") or getattr(entry, "description", "")
            findings.append(Finding(
                source=f"rss:{name}",
                category="blog",
                title=entry.title.strip(),
                url=entry.link,
                summary=summary[:600],
                published=published.isoformat(),
            ))
    return findings


if __name__ == "__main__":
    for f in fetch():
        print(f.source, f.title)
