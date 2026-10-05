"""Deliver digest lines to every configured channel (Discord and/or Slack).

A channel is enabled by setting its webhook env var. Lines are built once in
Discord markdown (see ``discord_notifier``); each notifier adapts the format.
"""
from __future__ import annotations

import os

from core import Finding
import discord_notifier
import slack_notifier

CHANNELS = [
    ("discord", "DISCORD_WEBHOOK_URL", discord_notifier),
    ("slack", "SLACK_WEBHOOK_URL", slack_notifier),
]


def post_lines(lines: list[str], dry_run: bool = False) -> tuple[bool, bool]:
    """Returns (delivered, all_ok): delivered if at least one channel got the
    digest, all_ok if every configured channel did."""
    enabled = [(name, mod) for name, env, mod in CHANNELS if os.environ.get(env)]
    if dry_run:
        # Always preview the Discord format; add Slack's when it's configured.
        for name, mod in enabled or [("discord", discord_notifier)]:
            mod.post_lines(lines, dry_run=True)
        return True, True
    if not enabled:
        print("[notify] no webhook configured; set DISCORD_WEBHOOK_URL and/or SLACK_WEBHOOK_URL")
        return False, False
    results = {name: mod.post_lines(lines) for name, mod in enabled}
    failed = [n for n, ok in results.items() if not ok]
    if failed:
        print(f"[notify] delivery failed for: {', '.join(failed)}")
    return any(results.values()), not failed


def post(findings: list[Finding], health_line: str = "", dry_run: bool = False) -> tuple[bool, bool]:
    if not findings and not health_line:
        print("[notify] nothing to post")
        return True, True
    if not findings:
        return post_lines(["# 🛡️ AI / Agent Security Digest", "_No new items today._", "", health_line], dry_run)
    return post_lines(discord_notifier.build_lines(findings, health_line), dry_run)
