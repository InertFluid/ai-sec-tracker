"""Format findings into a Slack message and POST to an incoming webhook."""
from __future__ import annotations

import os
import json
import requests
from collections import defaultdict

from core import Finding

CATEGORY_META = {
    "cve": ("🚨", "CVEs / Advisories"),
    "advisory": ("🚨", "CVEs / Advisories"),
    "paper": ("📄", "Research Papers"),
    "blog": ("✍️", "Research Blogs"),
    "release": ("📦", "Framework Releases"),
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def build_blocks(findings: list[Finding]) -> list[dict]:
    # Merge CVE + advisory under one section; order sections intentionally.
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        bucket = "cve" if f.category in ("cve", "advisory") else f.category
        grouped[bucket].append(f)

    order = ["cve", "paper", "release", "blog"]
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ AI / Agent Security Digest"},
        },
        {
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"*{len(findings)} new item(s)* across sources",
            }],
        },
        {"type": "divider"},
    ]

    for key in order:
        items = grouped.get(key, [])
        if not items:
            continue
        emoji, label = CATEGORY_META.get(key, ("•", key.title()))
        # Sort within section by score desc, then published desc.
        items.sort(key=lambda f: (f.score, f.published or ""), reverse=True)

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{emoji} {label}* ({len(items)})"},
        })

        # Slack block limit is 50. Show top 8 per section to stay well under.
        for f in items[:8]:
            sev_prefix = f"{SEVERITY_EMOJI.get((f.severity or '').upper(), '')} " if f.severity else ""
            title_line = f"{sev_prefix}<{f.url}|{_truncate(f.title, 140)}>"
            meta_bits = [f"score *{f.score}*"]
            if f.matched_keywords:
                meta_bits.append("`" + "`, `".join(f.matched_keywords[:4]) + "`")
            meta_bits.append(f._source_short() if hasattr(f, "_source_short") else f.source)
            meta = " · ".join(meta_bits)

            body = _truncate(f.summary, 240) if f.summary else ""
            text = f"{title_line}\n{meta}"
            if body:
                text += f"\n_{body}_"
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})

        if len(items) > 8:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"…and {len(items) - 8} more"}],
            })
        blocks.append({"type": "divider"})

    return blocks


def post(findings: list[Finding]) -> bool:
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        print("[slack] SLACK_WEBHOOK_URL not set; skipping post")
        return False
    if not findings:
        print("[slack] nothing to post")
        return True

    blocks = build_blocks(findings)
    payload = {"blocks": blocks, "text": f"AI Security Digest: {len(findings)} item(s)"}
    try:
        r = requests.post(webhook, json=payload, timeout=15)
        r.raise_for_status()
        print(f"[slack] posted {len(findings)} item(s)")
        return True
    except Exception as e:
        print(f"[slack] error: {e}")
        # Dump payload for debugging
        print(json.dumps(payload)[:1000])
        return False
