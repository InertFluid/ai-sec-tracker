"""Format findings into Discord messages and POST to a webhook."""
from __future__ import annotations

import os
import time
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

# Discord hard limit per message content.
MAX_CONTENT = 2000


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def build_lines(findings: list[Finding]) -> list[str]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        bucket = "cve" if f.category in ("cve", "advisory") else f.category
        grouped[bucket].append(f)

    order = ["cve", "paper", "release", "blog"]
    lines: list[str] = [
        f"# 🛡️ AI / Agent Security Digest",
        f"_{len(findings)} new item(s) across sources_",
        "",
    ]

    for key in order:
        items = grouped.get(key, [])
        if not items:
            continue
        emoji, label = CATEGORY_META.get(key, ("•", key.title()))
        items.sort(key=lambda f: (f.score, f.published or ""), reverse=True)

        lines.append(f"## {emoji} {label} ({len(items)})")

        for f in items[:8]:
            sev = f"{SEVERITY_EMOJI.get((f.severity or '').upper(), '')} " if f.severity else ""
            # Discord masked link: [text](url). Angle brackets around url suppress embed preview.
            title_line = f"{sev}[{_truncate(f.title, 140)}](<{f.url}>)"
            meta_bits = [f"score **{f.score}**"]
            if f.matched_keywords:
                meta_bits.append("`" + "`, `".join(f.matched_keywords[:4]) + "`")
            meta_bits.append(f.source)
            meta = " · ".join(meta_bits)
            lines.append(f"• {title_line}")
            lines.append(f"  {meta}")
            if f.summary:
                lines.append(f"  _{_truncate(f.summary, 240)}_")

        if len(items) > 8:
            lines.append(f"…and {len(items) - 8} more")
        lines.append("")

    return lines


def chunk_lines(lines: list[str], limit: int = MAX_CONTENT) -> list[str]:
    """Pack lines into messages under the Discord content limit."""
    chunks: list[str] = []
    buf: list[str] = []
    size = 0
    for line in lines:
        # +1 for the newline we'd add when joining.
        add = len(line) + 1
        if size + add > limit and buf:
            chunks.append("\n".join(buf))
            buf = [line]
            size = add
        else:
            buf.append(line)
            size += add
    if buf:
        chunks.append("\n".join(buf))
    return chunks


def post(findings: list[Finding]) -> bool:
    webhook = os.environ.get("DISCORD_WEBHOOK_URL")
    if not webhook:
        print("[discord] DISCORD_WEBHOOK_URL not set; skipping post")
        return False
    if not findings:
        print("[discord] nothing to post")
        return True

    lines = build_lines(findings)
    chunks = chunk_lines(lines)
    for i, content in enumerate(chunks):
        try:
            r = requests.post(webhook, json={"content": content}, timeout=15)
            r.raise_for_status()
        except Exception as e:
            print(f"[discord] error on chunk {i + 1}/{len(chunks)}: {e}")
            return False
        # Gentle pacing — Discord webhooks rate-limit ~5 req/2s per webhook.
        if i < len(chunks) - 1:
            time.sleep(0.4)

    print(f"[discord] posted {len(findings)} item(s) in {len(chunks)} message(s)")
    return True
