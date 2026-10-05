"""Convert the digest's Discord-flavored markdown to Slack mrkdwn and POST to
a Slack incoming webhook."""
from __future__ import annotations

import os
import re
import time
import requests

from discord_notifier import WebhookError, chunk_lines, safe_error

# Slack accepts up to 40k chars per message but truncates long messages in the
# UI; keep each message short enough to read without "Show more".
MAX_CONTENT = 3000

# Discord masked link: [text](<url>) or [text](url)
_LINK = re.compile(r"\[([^\]]*)\]\(<?([^)>\s]+)>?\)")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_HEADING = re.compile(r"^#{1,3}\s+(.*)$")


def _escape(s: str) -> str:
    # Slack treats these three as control characters in mrkdwn text.
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def to_mrkdwn(line: str) -> str:
    out: list[str] = []
    pos = 0
    for m in _LINK.finditer(line):
        out.append(_escape(line[pos:m.start()]))
        # "|" separates url from label in Slack links, so it can't appear in the label.
        label = _escape(m.group(1)).replace("|", "¦")
        out.append(f"<{m.group(2)}|{label}>")
        pos = m.end()
    out.append(_escape(line[pos:]))
    s = _BOLD.sub(r"*\1*", "".join(out))
    h = _HEADING.match(s)
    return f"*{h.group(1)}*" if h else s


def post_lines(lines: list[str], dry_run: bool = False) -> bool:
    chunks = chunk_lines([to_mrkdwn(l) for l in lines], MAX_CONTENT)
    if dry_run:
        print("\n\n----- (slack message break) -----\n\n".join(chunks))
        return True
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        print("[slack] SLACK_WEBHOOK_URL not set; skipping post")
        return False
    for i, text in enumerate(chunks):
        try:
            r = requests.post(
                webhook,
                json={"text": text, "mrkdwn": True, "unfurl_links": False, "unfurl_media": False},
                timeout=15,
            )
            if r.status_code != 200:
                raise WebhookError(f"HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            print(f"[slack] error on chunk {i + 1}/{len(chunks)}: {safe_error(e)}")
            return False
        # Slack incoming webhooks allow ~1 message/second.
        if i < len(chunks) - 1:
            time.sleep(1.1)
    print(f"[slack] posted {len(chunks)} message(s)")
    return True
