"""Main entry point. Runs all fetchers, scores, dedupes, posts to Discord, persists state."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from core import Finding, score_finding, iso_now
from config import MIN_SCORE
from sources import arxiv_source, nvd_source, github_source, rss_source
import discord_notifier
import llm_filter

STATE_PATH = Path(__file__).parent / "state.json"
# Cap on IDs to keep in state — prevents unbounded growth.
STATE_CAP = 2000


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            pass
    return {"seen_ids": [], "last_run": None}


def save_state(state: dict) -> None:
    # Keep most recent IDs only.
    state["seen_ids"] = state["seen_ids"][-STATE_CAP:]
    state["last_run"] = iso_now()
    STATE_PATH.write_text(json.dumps(state, indent=2))


def run() -> int:
    state = load_state()
    seen: set[str] = set(state.get("seen_ids", []))

    all_findings: list[Finding] = []
    fetchers = [
        ("arxiv", arxiv_source.fetch),
        ("nvd", nvd_source.fetch),
        ("github", github_source.fetch),
        ("rss", rss_source.fetch),
    ]
    for name, fn in fetchers:
        try:
            items = fn()
            print(f"[{name}] fetched {len(items)}")
            all_findings.extend(items)
        except Exception as e:
            print(f"[{name}] fatal: {e}", file=sys.stderr)

    # Dedupe within this run
    unique: dict[str, Finding] = {}
    for f in all_findings:
        unique.setdefault(f.id, f)

    # Filter against previously seen
    fresh = [f for f in unique.values() if f.id not in seen]
    print(f"[dedupe] {len(unique)} unique, {len(fresh)} new")

    # Score + threshold filter
    scored = [score_finding(f) for f in fresh]
    relevant = [f for f in scored if f.score >= MIN_SCORE]
    print(f"[score] {len(relevant)} above threshold {MIN_SCORE}")

    # LLM pass: drop coincidental keyword matches, rewrite summaries to 1-liners.
    # Best-effort — unchanged on failure or missing GROQ_API_KEY.
    relevant = llm_filter.filter_and_rewrite(relevant)

    # Post. Only persist state if delivery succeeded — otherwise items marked
    # "seen" would never be delivered on the next run.
    posted = discord_notifier.post(relevant)

    if posted:
        state["seen_ids"] = list(seen.union(f.id for f in fresh))
        save_state(state)
    else:
        print("[state] post failed; skipping state update")

    # In GitHub Actions, write a short summary to the step summary file.
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as fh:
            fh.write(f"# AI Security Digest\n\n")
            fh.write(f"- Fetched: **{len(all_findings)}**\n")
            fh.write(f"- New (unseen): **{len(fresh)}**\n")
            fh.write(f"- Posted to Discord: **{len(relevant)}**\n\n")
            for f in sorted(relevant, key=lambda x: x.score, reverse=True)[:15]:
                fh.write(f"- `{f.score}` [{f.title}]({f.url}) — `{f.source}`\n")

    return 0 if posted else 1


if __name__ == "__main__":
    sys.exit(run())
