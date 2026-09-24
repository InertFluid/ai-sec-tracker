"""Format findings into Discord messages and POST to a webhook."""
from __future__ import annotations

import os
import time
import requests
from collections import defaultdict

from core import Finding

CATEGORY_META = {
    "developments": ("🚀", "Top AI Developments"),
    "cve": ("🚨", "CVEs / Advisories"),
    "advisory": ("🚨", "CVEs / Advisories"),
    "blog": ("✍️", "Research Blogs"),
    "paper": ("📄", "Research Papers"),
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
PER_SECTION = 8


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _bucket(f: Finding) -> str:
    if f.lane == "developments":
        return "developments"
    if f.category in ("cve", "advisory"):
        return "cve"
    if f.category in ("paper", "release"):
        return f.category
    return "blog"  # blogs, trusted research sites, security discussion


def _developments_lines(items: list[Finding]) -> list[str]:
    lines: list[str] = []
    for f in items:
        lines.append(f"• **[{_truncate(f.title, 140)}](<{f.url}>)**")
        meta = [f.source]
        if f.popularity:
            meta.append(f.popularity)
        if f.also_in:
            meta.append("also: " + ", ".join(_truncate(a, 40) for a in f.also_in[:2]))
        if f.discussion_url:
            meta.append(f"[discussion](<{f.discussion_url}>)")
        lines.append("  " + " · ".join(meta))
        if f.summary:
            lines.append(f"  _{_truncate(f.summary, 240)}_")
        if f.angle:
            lines.append(f"  🔬 {_truncate(f.angle, 200)}")
    return lines


def _security_lines(items: list[Finding]) -> list[str]:
    lines: list[str] = []
    for f in items[:PER_SECTION]:
        sev = f"{SEVERITY_EMOJI.get((f.severity or '').upper(), '')} " if f.severity else ""
        # Discord masked link: [text](url). Angle brackets around url suppress embed preview.
        title_line = f"{sev}[{_truncate(f.title, 140)}](<{f.url}>)"
        meta_bits = [f"score **{f.score}**"]
        if f.matched_keywords:
            meta_bits.append("`" + "`, `".join(f.matched_keywords[:4]) + "`")
        meta_bits.append(f.source)
        lines.append(f"• {title_line}")
        lines.append(f"  {' · '.join(meta_bits)}")
        if f.summary:
            lines.append(f"  _{_truncate(f.summary, 240)}_")
        if f.angle:
            lines.append(f"  🔬 {_truncate(f.angle, 200)}")
    if len(items) > PER_SECTION:
        lines.append(f"…and {len(items) - PER_SECTION} more")
    return lines


def build_lines(findings: list[Finding], health_line: str = "") -> list[str]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[_bucket(f)].append(f)

    n_dev = len(grouped.get("developments", []))
    lines: list[str] = [
        "# 🛡️ AI / Agent Security Digest",
        f"_{n_dev} AI development(s) · {len(findings) - n_dev} security item(s)_",
        "",
    ]

    for key in ("developments", "cve", "blog", "paper", "release"):
        items = grouped.get(key, [])
        if not items:
            continue
        emoji, label = CATEGORY_META[key]
        items.sort(key=lambda f: (f.score, f.published or ""), reverse=True)
        lines.append(f"## {emoji} {label} ({len(items)})")
        lines.extend(_developments_lines(items) if key == "developments" else _security_lines(items))
        lines.append("")

    if health_line:
        lines.append(health_line)
    return lines


def build_weekly_lines(developments: list[dict], security: list[dict], threads: list[dict],
                       all_items: list[dict], stats: dict[str, int], health_line: str = "") -> list[str]:
    lines = [
        "# 🗓️ Weekly AI Security Roll-up",
        "_" + " · ".join(f"{v} {k}" for k, v in stats.items()) + "_",
        "",
    ]
    if threads:
        lines.append("## 🧭 Research threads worth pursuing")
        for t in threads:
            lines.append(f"• **{_truncate(t.get('title', ''), 100)}**")
            if t.get("why_now"):
                lines.append(f"  _Why now:_ {_truncate(t['why_now'], 220)}")
            if t.get("next_step"):
                lines.append(f"  _Next step:_ {_truncate(t['next_step'], 220)}")
            refs = [all_items[i] for i in t.get("refs", []) if isinstance(i, int) and 0 <= i < len(all_items)]
            if refs:
                lines.append("  " + " · ".join(f"[{_truncate(r['title'], 50)}](<{r['url']}>)" for r in refs[:3]))
        lines.append("")
    for label, items in (("🚀 Biggest AI developments", developments), ("🚨 Top security items", security)):
        if not items:
            continue
        lines.append(f"## {label}")
        for it in items:
            meta = " · ".join(x for x in (it.get("source", ""), it.get("popularity", "")) if x)
            lines.append(f"• [{_truncate(it['title'], 140)}](<{it['url']}>) — {meta}")
            if it.get("angle"):
                lines.append(f"  🔬 {_truncate(it['angle'], 200)}")
        lines.append("")
    if health_line:
        lines.append(health_line)
    return lines


def chunk_lines(lines: list[str], limit: int = MAX_CONTENT) -> list[str]:
    """Pack lines into messages under the Discord content limit."""
    chunks: list[str] = []
    buf: list[str] = []
    size = 0
    for line in lines:
        line = _truncate(line, limit - 1) if len(line) >= limit else line
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


def post_lines(lines: list[str], dry_run: bool = False) -> bool:
    chunks = chunk_lines(lines)
    if dry_run:
        print("\n\n----- (message break) -----\n\n".join(chunks))
        return True
    webhook = os.environ.get("DISCORD_WEBHOOK_URL")
    if not webhook:
        print("[discord] DISCORD_WEBHOOK_URL not set; skipping post")
        return False
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
    print(f"[discord] posted {len(chunks)} message(s)")
    return True


def post(findings: list[Finding], health_line: str = "", dry_run: bool = False) -> bool:
    if not findings and not health_line:
        print("[discord] nothing to post")
        return True
    if not findings:
        return post_lines(["# 🛡️ AI / Agent Security Digest", "_No new items today._", "", health_line], dry_run)
    return post_lines(build_lines(findings, health_line), dry_run)
