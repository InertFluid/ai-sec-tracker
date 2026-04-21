"""Fetch security advisories + releases for tracked GitHub repos."""
from __future__ import annotations

import os
import requests
from datetime import datetime, timedelta, timezone

from core import Finding
from config import TRACKED_REPOS, LOOKBACK_DAYS

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
            print(f"[gh-advisory] {ecosystem} error: {e}")
            continue

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


def fetch_releases() -> list[Finding]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    findings: list[Finding] = []
    for repo in TRACKED_REPOS:
        try:
            r = requests.get(
                f"{GITHUB_API}/repos/{repo}/releases",
                params={"per_page": 5},
                headers=_headers(),
                timeout=20,
            )
            r.raise_for_status()
        except Exception as e:
            print(f"[gh-release] {repo} error: {e}")
            continue

        for rel in r.json():
            published = _parse_dt(rel.get("published_at") or "")
            if not published or published < cutoff:
                continue
            body = (rel.get("body") or "")[:600]
            findings.append(Finding(
                source=f"github-release:{repo}",
                category="release",
                title=f"{repo} {rel.get('tag_name', '')}: {rel.get('name', '') or ''}".strip(),
                url=rel.get("html_url", ""),
                summary=body,
                published=rel.get("published_at"),
            ))
    return findings


def fetch() -> list[Finding]:
    return fetch_advisories() + fetch_releases()


if __name__ == "__main__":
    for f in fetch():
        print(f.category, f.title)
