"""Fetch recent CVEs from NVD and filter for AI/ML relevance."""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from core import Finding, http_get, record_health
from config import NVD_RELEVANT_TERMS, LOOKBACK_DAYS

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # NVD maximum


def _is_relevant(cve_item: dict) -> tuple[bool, str]:
    """Return (relevant, matched_term). Match against CPE configs + description."""
    # Check CPEs
    configurations = cve_item.get("configurations", [])
    for cfg in configurations:
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                criteria = cpe.get("criteria", "").lower()
                for term in NVD_RELEVANT_TERMS:
                    if term in criteria:
                        return True, term
    # Fallback: description text
    for desc in cve_item.get("descriptions", []):
        text = desc.get("value", "").lower()
        for term in NVD_RELEVANT_TERMS:
            if term in text:
                return True, term
    return False, ""


def _severity(cve_item: dict) -> str | None:
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            sev = data.get("baseSeverity")
            if sev:
                return sev
    return None


def fetch() -> list[Finding]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=LOOKBACK_DAYS)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": PAGE_SIZE,
    }
    headers = {}
    # Optional API key increases rate limit from 5 to 50 req / 30s.
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    # NVD publishes a few hundred CVEs a day, so the window spans several
    # pages. Without a key the limit is 5 req / 30s, hence the pause.
    findings: list[Finding] = []
    vulns: list[dict] = []
    total = None
    start_index = 0
    failed = False
    while total is None or start_index < total:
        try:
            r = http_get(NVD_API, params={**params, "startIndex": start_index},
                         headers=headers, timeout=60, retries=3)
            data = r.json()
        except Exception as e:
            record_health("nvd", False, f"page at {start_index}: {e}")
            failed = True
            break
        total = data.get("totalResults", 0)
        page = data.get("vulnerabilities", [])
        vulns.extend(page)
        if not page:
            break
        start_index += len(page)
        if start_index < total:
            time.sleep(1 if api_key else 6)
    if not failed:
        record_health("nvd", True, f"{len(vulns)} CVEs in window")

    for item in vulns:
        cve = item.get("cve", {})
        relevant, matched = _is_relevant(cve)
        if not relevant:
            continue
        cve_id = cve.get("id", "UNKNOWN")
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        findings.append(Finding(
            source="nvd",
            category="cve",
            title=f"{cve_id} ({matched})",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            summary=desc[:600],
            published=cve.get("published"),
            severity=_severity(cve),
        ))
    return findings


if __name__ == "__main__":
    for f in fetch():
        print(f.severity, f.title)
