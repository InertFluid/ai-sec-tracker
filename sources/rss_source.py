"""Fetch recent posts from RSS/Atom feeds for both lanes."""
from __future__ import annotations

import feedparser
import html
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from core import Finding, http_get, record_health, ai_related
from config import (
    SECURITY_FEEDS, AI_SECURITY_FEEDS, DEVELOPMENT_FEEDS, LOOKBACK_DAYS, STALE_DAYS,
)

# kind -> (boost, max items per run, require AI term). Labs publish plenty of
# customer stories too, so their boost is only a head start: a big HN thread
# still outranks them, and the LLM filter drops the fluff.
DEV_KIND = {
    "lab": (4, 6, False),
    "press": (1, 6, False),
    "press-general": (1, 6, True),
    "newsletter": (2, 3, False),
}

_TAG_RE = re.compile(r"<[^>]+>")


def _entry_published(entry) -> datetime | None:
    for attr in ("published_parsed", "updated_parsed"):
        t = getattr(entry, attr, None)
        if t:
            try:
                return datetime(*t[:6], tzinfo=timezone.utc)
            except Exception:
                pass
    return None


def clean_html(s: str) -> str:
    return " ".join(html.unescape(_TAG_RE.sub(" ", s or "")).split())


def _read_feed(name: str, url: str) -> list:
    """Fetch + parse one feed, recording health. Returns entries (maybe empty)."""
    health_name = f"rss:{name}"
    try:
        r = http_get(url, timeout=25)
    except Exception as e:
        record_health(health_name, False, str(e))
        return []
    parsed = feedparser.parse(r.content)
    if not parsed.entries:
        record_health(health_name, False, f"HTTP {r.status_code} but 0 entries (not a feed?)")
        return []
    newest = max((d for d in map(_entry_published, parsed.entries) if d), default=None)
    stale = bool(newest and newest < datetime.now(timezone.utc) - timedelta(days=STALE_DAYS))
    detail = f"{len(parsed.entries)} entries, newest {newest.date() if newest else '?'}"
    record_health(health_name, True, detail, stale=stale)
    return parsed.entries


def _feed_findings(name: str, url: str, lane: str, kind: str | None, trusted: bool) -> list[Finding]:
    entries = _read_feed(name, url)
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    boost, cap, needs_ai = DEV_KIND.get(kind or "", (0, 20, False))
    category = "news" if lane == "developments" else "blog"

    findings: list[Finding] = []
    for entry in entries[:30]:
        published = _entry_published(entry)
        if not published or published < cutoff:
            continue
        title = clean_html(getattr(entry, "title", ""))
        link = getattr(entry, "link", "")
        if not title or not link:
            continue
        summary = clean_html(getattr(entry, "summary", "") or getattr(entry, "description", ""))
        if needs_ai and not ai_related(f"{title} {summary[:300]}"):
            continue
        findings.append(Finding(
            source=f"rss:{name}",
            category=category,
            title=title,
            url=link,
            summary=summary[:600],
            published=published.isoformat(),
            lane=lane,
            trusted=trusted,
            boost=boost,
        ))
        if len(findings) >= cap:
            break
    return findings


def fetch() -> list[Finding]:
    jobs = (
        [(n, u, "security", None, False) for n, u in SECURITY_FEEDS]
        + [(n, u, "security", None, True) for n, u in AI_SECURITY_FEEDS]
        + [(n, u, "developments", k, False) for n, u, k in DEVELOPMENT_FEEDS]
    )
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for items in pool.map(lambda j: _feed_findings(*j), jobs):
            findings.extend(items)
    return findings


if __name__ == "__main__":
    for f in fetch():
        print(f.lane, f.source, f.title)
