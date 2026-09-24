"""Hacker News stories about AI that are getting real traction.

Uses the free Algolia HN API. Stories below HN_MIN_POINTS are not returned
(so not marked seen) and get re-checked on the next run while still inside
the lookback window — launches often take a few hours to climb.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core import Finding, http_get, record_health, ai_related
from config import HN_MIN_POINTS, LOOKBACK_DAYS
from sources.rss_source import clean_html

HN_API = "https://hn.algolia.com/api/v1/search_by_date"


def fetch() -> list[Finding]:
    since = int((datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).timestamp())
    params = {
        "tags": "story",
        "numericFilters": f"created_at_i>{since},points>={HN_MIN_POINTS}",
        "hitsPerPage": 500,
    }
    try:
        hits = http_get(HN_API, params=params).json().get("hits", [])
    except Exception as e:
        record_health("hn", False, str(e))
        return []
    record_health("hn", True, f"{len(hits)} stories >= {HN_MIN_POINTS} pts")

    findings: list[Finding] = []
    for h in hits:
        title = h.get("title") or ""
        if not ai_related(title):
            continue
        points = h.get("points") or 0
        comments = h.get("num_comments") or 0
        thread = f"https://news.ycombinator.com/item?id={h.get('objectID')}"
        findings.append(Finding(
            source="hn",
            category="discussion",
            title=title,
            url=h.get("url") or thread,
            summary=clean_html(h.get("story_text") or "")[:600],
            published=h.get("created_at"),
            lane="developments",
            boost=min(points // 100, 15),
            popularity=f"HN {points:,} pts · {comments:,} comments",
            discussion_url=thread,
        ))
    return findings


if __name__ == "__main__":
    for f in sorted(fetch(), key=lambda f: f.boost, reverse=True):
        print(f.popularity, "|", f.title)
