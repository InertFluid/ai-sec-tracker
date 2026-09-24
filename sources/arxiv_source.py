"""Fetch recent AI-security papers from arXiv."""
from __future__ import annotations

import feedparser
from datetime import datetime, timedelta, timezone

from core import Finding, http_get, record_health
from config import ARXIV_CATEGORIES, ARXIV_QUERY_TERMS, LOOKBACK_DAYS

# Must be https: the http endpoint 301-redirects, and the redirected request
# was silently returning nothing, so the digest reported 0 papers for weeks.
ARXIV_API = "https://export.arxiv.org/api/query"


def _build_query() -> str:
    cats = " OR ".join(f"cat:{c}" for c in ARXIV_CATEGORIES)
    terms = " OR ".join(f'abs:"{t}"' for t in ARXIV_QUERY_TERMS)
    return f"({cats}) AND ({terms})"


def fetch(max_results: int = 100) -> list[Finding]:
    params = {
        "search_query": _build_query(),
        "sortBy": "submittedDate",
        "sortOrder": "descending",
        "max_results": max_results,
    }
    try:
        # arXiv asks API clients to back off on 503; http_get retries with delay.
        r = http_get(ARXIV_API, params=params, timeout=60, retries=3)
    except Exception as e:
        record_health("arxiv", False, str(e))
        return []
    parsed = feedparser.parse(r.content)
    # A successful query for these terms always has results; zero entries
    # means arXiv returned an error page or throttled us.
    record_health("arxiv", bool(parsed.entries), f"{len(parsed.entries)} entries")
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)

    findings: list[Finding] = []
    for entry in parsed.entries:
        try:
            published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        except Exception:
            continue
        if published < cutoff:
            continue
        findings.append(Finding(
            source="arxiv",
            category="paper",
            title=" ".join(entry.title.split()),
            url=entry.link,
            summary=" ".join(entry.summary.split())[:600],
            published=published.isoformat(),
        ))
    return findings


if __name__ == "__main__":
    for f in fetch():
        print(f.title, f.url)
