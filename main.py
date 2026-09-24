"""Main entry point. Runs all fetchers, scores, dedupes, posts to Discord, persists state.

Usage:
  python main.py                 daily digest
  python main.py --weekly        weekly roll-up from the last 7 days of posted items
  python main.py --check-health  exit 1 if any source has failed HEALTH_FAIL_STREAK runs in a row
  python main.py --dry-run       print the digest instead of posting; don't touch state.json
  python main.py --skip-if-posted-within 10
                                 exit quietly if a digest was delivered in the last 10h
                                 (lets a backup cron cover for a delayed/dropped one)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import Finding, score_finding, iso_now, health_results, parse_dt, record_health
from config import (
    MIN_SCORE, DEVELOPMENTS_MAX, DEVELOPMENTS_LLM_MAX, SECURITY_LLM_MAX, HEALTH_FAIL_STREAK,
)
from sources import (
    arxiv_source, nvd_source, github_source, rss_source, sitemap_source, hn_source,
    reddit_source, bluesky_source, x_source, huggingface_source,
)
import discord_notifier
import llm_filter

STATE_PATH = Path(__file__).parent / "state.json"
# Cap on IDs to keep in state — prevents unbounded growth. The lookback is
# only a few days, so this comfortably covers every item still in the window.
STATE_CAP = 6000
# Posted items kept for the weekly roll-up.
HISTORY_DAYS = 8
# Health entries for sources not seen in this long (removed from config) are pruned.
HEALTH_PRUNE_DAYS = 14


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


# ---------------------------------------------------------------------------
# Source health
# ---------------------------------------------------------------------------

def update_health(state: dict, results: dict[str, dict]) -> None:
    health = state.setdefault("health", {})
    now = iso_now()
    for name, r in results.items():
        entry = health.setdefault(name, {"fail_streak": 0})
        if r["ok"]:
            entry["fail_streak"] = 0
            entry["last_ok"] = now
        else:
            entry["fail_streak"] = entry.get("fail_streak", 0) + 1
        entry["detail"] = r["detail"]
        entry["stale"] = r["stale"]
        entry["last_run"] = now
    cutoff = datetime.now(timezone.utc) - timedelta(days=HEALTH_PRUNE_DAYS)
    for name in [n for n, e in health.items() if (parse_dt(e.get("last_run")) or cutoff) < cutoff]:
        del health[name]


def failing_sources(state: dict) -> dict[str, dict]:
    return {n: e for n, e in state.get("health", {}).items() if e.get("fail_streak", 0) >= HEALTH_FAIL_STREAK}


def stale_sources(state: dict) -> dict[str, dict]:
    return {n: e for n, e in state.get("health", {}).items() if e.get("stale")}


def health_line(state: dict, include_stale: bool = False) -> str:
    failing = failing_sources(state)
    parts = []
    if failing:
        names = ", ".join(f"`{n}`" for n in sorted(failing)[:8])
        more = f" +{len(failing) - 8} more" if len(failing) > 8 else ""
        parts.append(f"⚠️ **Source health:** {len(failing)} failing {HEALTH_FAIL_STREAK}+ runs: {names}{more}")
    stale = stale_sources(state)
    if include_stale and stale:
        parts.append(f"🕸️ Stale feeds (no posts in a long time): {', '.join(f'`{n}`' for n in sorted(stale))}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Daily digest
# ---------------------------------------------------------------------------

def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse items with the same normalized URL; the higher-boost copy wins
    and gets a small bump for being carried by several sources."""
    unique: dict[str, Finding] = {}
    for f in findings:
        existing = unique.get(f.id)
        if existing is None:
            unique[f.id] = f
            continue
        primary, other = (f, existing) if f.boost > existing.boost else (existing, f)
        primary.also_in.append(other.popularity or other.source)
        primary.boost += 2
        primary.discussion_url = primary.discussion_url or other.discussion_url
        primary.trusted = primary.trusted or other.trusted
        if other.lane == "developments":
            primary.lane = "developments"
        unique[f.id] = primary
    return list(unique.values())


def run_daily(dry_run: bool = False) -> int:
    state = load_state()
    seen: set[str] = set(state.get("seen_ids", []))

    all_findings: list[Finding] = []
    fetchers = [
        ("arxiv", arxiv_source.fetch),
        ("nvd", nvd_source.fetch),
        ("github", github_source.fetch),
        ("rss", rss_source.fetch),
        ("sitemaps", lambda: sitemap_source.fetch(state.get("sitemaps", {}))),
        ("hn", hn_source.fetch),
        ("reddit", reddit_source.fetch),
        ("bluesky", bluesky_source.fetch),
        ("x", x_source.fetch),
        ("huggingface", huggingface_source.fetch),
    ]
    for name, fn in fetchers:
        try:
            items = fn()
            print(f"[{name}] fetched {len(items)}")
            all_findings.extend(items)
        except Exception as e:
            print(f"[{name}] fatal: {e}", file=sys.stderr)
            record_health(f"fetcher:{name}", False, f"crashed: {e}")

    unique = dedupe(all_findings)

    # Filter against previously seen (legacy IDs predate URL normalization).
    fresh = [f for f in unique if f.id not in seen and f.legacy_id not in seen]
    print(f"[dedupe] {len(unique)} unique, {len(fresh)} new")

    # Score + threshold filter
    scored = [score_finding(f) for f in fresh]
    relevant = [f for f in scored if f.score >= MIN_SCORE]
    rank = lambda f: (f.score, f.published or "")
    developments = sorted((f for f in relevant if f.lane == "developments"), key=rank, reverse=True)
    security = sorted((f for f in relevant if f.lane != "developments"), key=rank, reverse=True)
    print(f"[score] {len(security)} security + {len(developments)} developments above threshold {MIN_SCORE}")

    # LLM pass: drop coincidental keyword matches / non-notable news, rewrite
    # summaries, suggest research angles. Best-effort — unchanged on failure.
    security = llm_filter.filter_and_rewrite(security[:SECURITY_LLM_MAX])
    developments = llm_filter.filter_developments(developments[:DEVELOPMENTS_LLM_MAX])
    developments = sorted(developments, key=rank, reverse=True)[:DEVELOPMENTS_MAX]
    to_post = developments + security

    update_health(state, health_results())
    line = health_line(state)

    if dry_run:
        discord_notifier.post(to_post, line, dry_run=True)
        print_health(state)
        return 0

    # Post. Only mark items seen if delivery succeeded — otherwise they'd
    # never be delivered on the next run. Health is saved either way.
    posted = discord_notifier.post(to_post, line)

    if posted:
        state["last_posted"] = iso_now()
        state["seen_ids"] = list(seen.union(f.id for f in fresh))
        state["sitemaps"] = sitemap_source.pending_baselines
        append_history(state, to_post)
    else:
        print("[state] post failed; saving source health only")
    save_state(state)

    write_step_summary(all_findings, fresh, to_post, state)
    return 0 if posted else 1


def append_history(state: dict, posted: list[Finding]) -> None:
    now = iso_now()
    history = state.setdefault("history", [])
    for f in posted:
        history.append({
            "id": f.id, "lane": f.lane, "category": f.category, "title": f.title, "url": f.url,
            "source": f.source, "score": f.score, "severity": f.severity, "summary": f.summary[:300],
            "angle": f.angle, "popularity": f.popularity, "posted_at": now,
        })
    cutoff = datetime.now(timezone.utc) - timedelta(days=HISTORY_DAYS)
    state["history"] = [h for h in history if (parse_dt(h.get("posted_at")) or cutoff) >= cutoff]


def write_step_summary(all_findings, fresh, posted, state) -> None:
    """In GitHub Actions, write a short summary to the step summary file."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a") as fh:
        fh.write("# AI Security Digest\n\n")
        fh.write(f"- Fetched: **{len(all_findings)}**\n")
        fh.write(f"- New (unseen): **{len(fresh)}**\n")
        fh.write(f"- Posted to Discord: **{len(posted)}**\n\n")
        for f in sorted(posted, key=lambda x: x.score, reverse=True)[:20]:
            fh.write(f"- `{f.lane[:3]}` `{f.score}` [{f.title}]({f.url}) — `{f.source}`\n")
        health = state.get("health", {})
        bad = {n: e for n, e in health.items() if e.get("fail_streak") or e.get("stale")}
        fh.write(f"\n## Source health ({len(health) - len(bad)}/{len(health)} healthy)\n\n")
        if bad:
            fh.write("| Source | Fail streak | Stale | Detail |\n|---|---|---|---|\n")
            for n, e in sorted(bad.items(), key=lambda kv: -kv[1].get("fail_streak", 0)):
                fh.write(f"| `{n}` | {e.get('fail_streak', 0)} | {'yes' if e.get('stale') else ''} | {e.get('detail', '')} |\n")


def print_health(state: dict) -> None:
    for n, e in sorted(state.get("health", {}).items()):
        flag = "FAIL" if e.get("fail_streak") else ("STALE" if e.get("stale") else "ok")
        print(f"[health] {flag:5} {n}: {e.get('detail', '')}")


# ---------------------------------------------------------------------------
# Weekly roll-up and health check
# ---------------------------------------------------------------------------

def run_weekly(dry_run: bool = False) -> int:
    state = load_state()
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    items = [h for h in state.get("history", []) if (parse_dt(h.get("posted_at")) or cutoff) >= cutoff]
    if not items:
        print("[weekly] no posted items in the last 7 days")
        return 0

    by_score = sorted(items, key=lambda h: h.get("score", 0), reverse=True)
    developments = [h for h in by_score if h.get("lane") == "developments"][:8]
    security = [h for h in by_score if h.get("lane") != "developments"][:8]

    stats: dict[str, int] = {}
    for h in items:
        key = "developments" if h.get("lane") == "developments" else {
            "cve": "CVEs", "advisory": "CVEs", "paper": "papers", "release": "releases",
        }.get(h.get("category", ""), "research posts")
        stats[key] = stats.get(key, 0) + 1

    # Give the LLM the strongest items only, to stay within free-tier limits.
    candidates = by_score[:60]
    threads = llm_filter.research_threads(candidates)
    lines = discord_notifier.build_weekly_lines(
        developments, security, threads, candidates, stats, health_line(state, include_stale=True),
    )
    return 0 if discord_notifier.post_lines(lines, dry_run=dry_run) else 1


def run_check_health() -> int:
    state = load_state()
    failing = failing_sources(state)
    for n, e in sorted(failing.items()):
        # GitHub Actions annotation, shown on the run page.
        print(f"::error title=Source failing ({e['fail_streak']} runs)::{n}: {e.get('detail', '')}")
    for n, e in sorted(stale_sources(state).items()):
        print(f"::warning title=Stale feed::{n}: {e.get('detail', '')}")
    if failing:
        print(f"{len(failing)} source(s) failing {HEALTH_FAIL_STREAK}+ runs in a row — fix or remove them in config.py")
        return 1
    print("All sources healthy.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--weekly", action="store_true")
    parser.add_argument("--check-health", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-if-posted-within", type=float, metavar="HOURS")
    args = parser.parse_args()
    if args.check_health:
        return run_check_health()
    if args.skip_if_posted_within and not args.weekly:
        last = parse_dt(load_state().get("last_posted"))
        if last and datetime.now(timezone.utc) - last < timedelta(hours=args.skip_if_posted_within):
            print(f"[skip] digest already delivered at {last.isoformat()}; nothing to do")
            return 0
    if args.weekly:
        return run_weekly(args.dry_run)
    return run_daily(args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
