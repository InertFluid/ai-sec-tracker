"""Shared types and scoring logic."""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Optional
import hashlib

from config import KEYWORDS


@dataclass
class Finding:
    """A single item pulled from any source."""
    source: str              # e.g. "arxiv", "nvd", "github-advisory", "rss:Embrace The Red"
    category: str            # "paper" | "cve" | "advisory" | "blog" | "release"
    title: str
    url: str
    summary: str = ""
    published: Optional[str] = None   # ISO format
    severity: Optional[str] = None    # for CVEs: CRITICAL/HIGH/MEDIUM/LOW
    score: int = 0
    matched_keywords: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Stable ID used for dedup. Based on URL (canonical) or title+source."""
        basis = self.url or f"{self.source}:{self.title}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        return d


def score_finding(f: Finding) -> Finding:
    """Score a finding by keyword matches against title + summary.

    CVEs get a floor boost based on severity because even a brief CVE line
    should surface if it's Critical/High on a tracked product.
    """
    haystack = f"{f.title} {f.summary}".lower()
    score = 0
    matches: list[str] = []
    for kw, weight in KEYWORDS.items():
        if kw in haystack:
            score += weight
            matches.append(kw)

    # Severity-based floor for CVEs — CVEs are already filtered to AI/ML
    # products upstream, so a Critical should never be dropped by the
    # keyword threshold.
    if f.category == "cve" and f.severity:
        floor = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4}.get(f.severity.upper(), 0)
        score = max(score, floor)

    f.score = score
    f.matched_keywords = matches
    return f


def iso_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
