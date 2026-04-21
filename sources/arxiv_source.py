"""Fetch recent AI-security papers from arXiv."""
from __future__ import annotations

import feedparser
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from core import Finding
from config import ARXIV_CATEGORIES, ARXIV_QUERY_TERMS, LOOKBACK_DAYS

ARXIV_API = "http://export.arxiv.org/api/query"


def _build_query() -> str:
    cats = " OR ".join(f"cat:{c}" for c in ARXIV_CATEGORIES)
    terms = " OR ".join(f'abs:"{t}"' for t in ARXIV_QUERY_TERMS)
    return f"({cats}) AND ({terms})"


def fetch(max_results: int = 40) -> list[Finding]:
    query = _build_query()
    url = (
        f"{ARXIV_API}?search_query={quote(query)}"
        f"&sortBy=submittedDate&sortOrder=descending&max_results={max_results}"
    )
    parsed = feedparser.parse(url)
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
            title=entry.title.strip().replace("\n", " "),
            url=entry.link,
            summary=entry.summary.strip().replace("\n", " ")[:600],
            published=published.isoformat(),
        ))
    return findings


if __name__ == "__main__":
    for f in fetch():
        print(f.title, f.url)
