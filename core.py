"""Shared types, HTTP helper, source-health registry, and scoring logic."""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import hashlib
import re
import time

import requests

from config import KEYWORDS, MIN_SCORE, AI_TERMS

USER_AGENT = "Mozilla/5.0 (compatible; ai-sec-tracker/2.0; +https://github.com/features/actions)"

# Query params that never change what a URL points to.
_TRACKING_PARAMS = re.compile(r"^(utm_.*|ref|ref_src|source|fbclid|gclid|mc_cid|mc_eid|s)$", re.I)


def normalize_url(url: str) -> str:
    """Canonical form for dedup: https, no www, no tracking params/fragment/trailing slash."""
    try:
        parts = urlsplit(url.strip())
    except Exception:
        return url
    host = parts.netloc.lower().removeprefix("www.")
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query) if not _TRACKING_PARAMS.match(k)])
    path = parts.path.rstrip("/") or "/"
    return urlunsplit(("https", host, path, query, ""))


@dataclass
class Finding:
    """A single item pulled from any source."""
    source: str              # e.g. "arxiv", "nvd", "hn", "rss:Embrace The Red"
    category: str            # "paper" | "cve" | "advisory" | "blog" | "news" | "discussion" | "model" | "repo"
    title: str
    url: str
    summary: str = ""
    published: Optional[str] = None   # ISO format
    severity: Optional[str] = None    # for CVEs: CRITICAL/HIGH/MEDIUM/LOW
    score: int = 0
    matched_keywords: list[str] = field(default_factory=list)
    lane: str = "security"            # "security" | "developments"
    trusted: bool = False             # AI-security source: bypasses the keyword threshold
    boost: int = 0                    # authority/popularity bonus (developments ranking)
    popularity: str = ""              # human label, e.g. "HN 1,978 pts"
    discussion_url: str = ""          # HN/Reddit/Bluesky thread when url points elsewhere
    angle: str = ""                   # LLM-suggested guard0 research angle
    also_in: list[str] = field(default_factory=list)  # other sources that carried the same URL

    @property
    def id(self) -> str:
        """Stable ID used for dedup. Based on the normalized URL (or title+source)."""
        basis = normalize_url(self.url) if self.url else f"{self.source}:{self.title}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]

    @property
    def legacy_id(self) -> str:
        """Pre-normalization ID, so items seen before the upgrade aren't re-posted."""
        basis = self.url or f"{self.source}:{self.title}"
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        return d


def score_finding(f: Finding) -> Finding:
    """Score a finding by keyword matches against title + summary.

    CVEs get a floor boost based on severity because even a brief CVE line
    should surface if it's Critical/High on a tracked product. Trusted
    AI-security sources and the developments lane are floored at MIN_SCORE;
    developments are then ranked by their source/popularity boost.
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

    if f.trusted:
        score = max(score, MIN_SCORE)
    if f.lane == "developments":
        score = max(score, MIN_SCORE) + f.boost

    f.score = score
    f.matched_keywords = matches
    return f


_AI_RE = re.compile(r"\b(" + "|".join(re.escape(t) for t in AI_TERMS) + r")\b", re.I)


def ai_related(text: str) -> bool:
    return bool(_AI_RE.search(text or ""))


def iso_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def http_get(url: str, *, params=None, headers: dict | None = None,
             timeout: int = 25, retries: int = 2) -> requests.Response:
    """GET with a real User-Agent and retries on 429/5xx/connection errors."""
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, params=params, headers=h, timeout=timeout)
            if r.status_code == 429 or r.status_code >= 500:
                if attempt < retries:
                    wait = min(int(r.headers.get("Retry-After", "0") or 0) or 3 * (attempt + 1), 30)
                    time.sleep(wait)
                    continue
            r.raise_for_status()
            return r
        except requests.HTTPError:
            raise
        except requests.RequestException as e:
            last_exc = e
            if attempt < retries:
                time.sleep(3 * (attempt + 1))
    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Source health. Each fetcher records whether each endpoint it hit worked, so
# a silently broken feed (404, blocked, empty) shows up instead of hiding
# behind "0 new items".
# ---------------------------------------------------------------------------

_HEALTH: dict[str, dict] = {}


def record_health(name: str, ok: bool, detail: str = "", stale: bool = False) -> None:
    _HEALTH[name] = {"ok": ok, "detail": detail[:200], "stale": stale}
    if not ok:
        print(f"[health] {name} FAILED: {detail}")


def health_results() -> dict[str, dict]:
    return dict(_HEALTH)
