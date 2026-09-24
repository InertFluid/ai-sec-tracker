"""Fetch AI-ecosystem security advisories and new repos from AI lab orgs."""
from __future__ import annotations

import os
import requests
from datetime import datetime, timedelta, timezone

from core import Finding, record_health
from config import (
    LOOKBACK_DAYS, LAB_GITHUB_ORGS, LAB_REPO_MIN_STARS, LAB_REPO_LOOKBACK_DAYS,
)

GITHUB_API = "https://api.github.com"


def _headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _parse_dt(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def fetch_advisories() -> list[Finding]:
    """Uses the global advisory search API filtered to tracked repos.

    GitHub's /advisories endpoint is public and doesn't strictly require
    authentication, but a token raises the rate limit substantially.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    findings: list[Finding] = []

    # Query by ecosystem is broader than by repo; we post-filter.
    # Advisories endpoint supports ?ecosystem=pip,npm,etc.
    for ecosystem in ("pip", "npm", "go", "rust"):
        try:
            r = requests.get(
                f"{GITHUB_API}/advisories",
                params={"ecosystem": ecosystem, "per_page": 50, "sort": "published"},
                headers=_headers(),
                timeout=30,
            )
            r.raise_for_status()
        except Exception as e:
            record_health(f"gh-advisory:{ecosystem}", False, str(e))
            continue
        record_health(f"gh-advisory:{ecosystem}", True, f"{len(r.json())} advisories")

        for adv in r.json():
            published = _parse_dt(adv.get("published_at") or "")
            if not published or published < cutoff:
                continue
            # Keep only if affects a tracked repo OR an AI-ecosystem package.
            vulns = adv.get("vulnerabilities", []) or []
            affected = [v.get("package", {}).get("name", "") for v in vulns]
            haystack = " ".join(affected).lower() + " " + (adv.get("summary") or "").lower()
            ai_terms = ("langchain", "llama", "autogen", "openai", "anthropic",
                        "ollama", "vllm", "transformers", "crewai", "semantic-kernel",
                        "mcp", "pydantic-ai", "haystack", "dspy")
            if not any(t in haystack for t in ai_terms):
                continue
            findings.append(Finding(
                source="github-advisory",
                category="advisory",
                title=f"{adv.get('ghsa_id', '')}: {adv.get('summary', '')[:120]}",
                url=adv.get("html_url", ""),
                summary=(adv.get("description") or "")[:600],
                published=adv.get("published_at"),
                severity=(adv.get("severity") or "").upper() or None,
            ))
    return findings


def fetch_lab_repos() -> list[Finding]:
    """New public repos from AI lab orgs — model code and tools often land here first.

    Repos under LAB_REPO_MIN_STARS aren't returned (so not marked seen) and are
    re-checked on later runs while inside LAB_REPO_LOOKBACK_DAYS.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=LAB_REPO_LOOKBACK_DAYS)
    findings: list[Finding] = []
    for org in LAB_GITHUB_ORGS:
        try:
            r = requests.get(
                f"{GITHUB_API}/orgs/{org}/repos",
                params={"sort": "created", "direction": "desc", "per_page": 10, "type": "public"},
                headers=_headers(),
                timeout=20,
            )
            r.raise_for_status()
        except Exception as e:
            record_health(f"gh-org:{org}", False, str(e))
            continue
        record_health(f"gh-org:{org}", True)

        for repo in r.json():
            created = _parse_dt(repo.get("created_at") or "")
            stars = repo.get("stargazers_count", 0)
            if repo.get("fork") or not created or created < cutoff or stars < LAB_REPO_MIN_STARS:
                continue
            desc = repo.get("description") or ""
            findings.append(Finding(
                source=f"github-org:{org}",
                category="repo",
                title=f"New repo {repo.get('full_name')}" + (f": {desc[:120]}" if desc else ""),
                url=repo.get("html_url", ""),
                summary=desc[:600],
                published=repo.get("created_at"),
                lane="developments",
                boost=min(stars // 200, 8) + 2,
                popularity=f"★ {stars:,}",
            ))
    return findings


def fetch() -> list[Finding]:
    return fetch_advisories() + fetch_lab_repos()


if __name__ == "__main__":
    for f in fetch():
        print(f.category, f.title)
