"""Optional Groq-powered filter/summarizer for findings.

Runs after keyword scoring, before posting. Uses Groq's LLM API to:
  1. Security lane: drop items where the keyword match was coincidental and
     rewrite verbose abstracts/advisory text into a single skimmable line.
  2. Developments lane: keep only notable AI developments, merge duplicate
     coverage of the same story, and suggest a guard0 research angle.
  3. Weekly roll-up: propose research threads from the week's items.

Best-effort: if GROQ_API_KEY is unset or the API call fails for any reason,
the original findings are returned unchanged (and the failure is recorded in
source health so it can't go unnoticed for weeks again).
"""
from __future__ import annotations

import json
import os
import time
import requests

from core import Finding, record_health

GROQ_API = "https://api.groq.com/openai/v1/chat/completions"
# llama-3.3-70b-versatile was decommissioned on 2026-08-16; Groq's
# recommended replacement is openai/gpt-oss-120b. If a model is retired
# again, the next one in the chain is tried automatically.
GROQ_MODELS = [m for m in [os.environ.get("GROQ_MODEL"), "openai/gpt-oss-120b", "openai/gpt-oss-20b"] if m]
BATCH_SIZE = 15
DEV_BATCH_SIZE = 25

SYSTEM_PROMPT = """You are filtering security findings for a daily digest focused on AI / LLM / agent security, read by the guard0 security research team.

For each finding, decide:
  keep: true if the item is genuinely about AI, LLMs, agents, ML infrastructure, prompt injection, model security, vector stores, agent frameworks (LangChain, LlamaIndex, AutoGen, CrewAI, MCP, etc.), or vulnerabilities in AI/ML tooling. false if the keyword match was coincidental (e.g. a CVE that happens to contain "ray" or "openai" in its text but is about unrelated software like project-management tools, OSINT tools, chat UIs with no AI focus, etc.). Also false for vendor marketing, webinars, event recaps, listicles, and hiring posts with no technical substance.
  summary: one crisp sentence (max 160 chars) describing what the item is AND which product/project it affects. Bad: "Server-side request forgery vulnerability." Good: "SSRF in modelscope agentscope's OpenAI tool parser allows fetching arbitrary URLs." Always name the affected software by name. Plain prose, no markdown.
  angle: a short follow-up research idea for an AI-agent security team (max 140 chars), ONLY when there is a clear one (a novel attack class, a new agent surface, a technique worth reproducing). Empty string for most items.

Respond with a JSON object of the form: {"items": [{"idx": 0, "keep": true, "summary": "...", "angle": ""}, ...]} — one entry per input item, preserving idx."""

DEV_SYSTEM_PROMPT = """You triage AI industry news for the guard0 security research team. guard0 builds security for AI agents and publishes fast takes (within 72h) on major AI developments, plus deeper research on agent, model, and MCP security.

For each item decide:
  keep: true if it is a NOTABLE development someone tracking AI should know about today: a new model or major model version, a major product/agent/coding-agent/framework launch or protocol change, a significant research result, a notable AI incident, outage, leak, or security event, a major AI policy/regulatory move, or a big AI-security funding/acquisition. false for routine marketing, minor feature updates, opinion pieces with no news, tutorials, listicles, customer case studies, and items not really about AI.
  duplicate_of: if this item covers the same story as an earlier item in this batch, the idx of that earlier item; otherwise null.
  summary: one crisp sentence (max 180 chars): what happened and who shipped it. Name the product/model. Plain prose, no markdown.
  angle: one sentence (max 160 chars) on the guard0 angle — what a security researcher could test, measure, or write about (e.g. new tool-use surface to probe for prompt injection, new agent permissions model, new open-weight model to red-team). Empty string if there is genuinely no security angle.

Respond with a JSON object: {"items": [{"idx": 0, "keep": true, "duplicate_of": null, "summary": "...", "angle": "..."}, ...]} — one entry per input item, preserving idx."""

THREADS_SYSTEM_PROMPT = """You are the research lead for guard0, an AI-agent security company. Its research team publishes fast takes on major AI developments and deeper research (conference talks, papers, data reports) on agent, model, coding-agent, and MCP security.

Given this week's digest items, propose 3 to 5 research threads worth pursuing. Prefer threads that connect several items, are timely, and could produce a public artifact (fast take, experiment write-up, or talk). Each thread:
  title: short name (max 80 chars)
  why_now: one sentence on what changed this week (max 200 chars)
  next_step: one concrete first experiment or analysis (max 200 chars)
  refs: list of item idx values it builds on

Respond with a JSON object: {"threads": [{"title": "...", "why_now": "...", "next_step": "...", "refs": [0, 3]}]}"""

_active_model_idx = 0
_failures = 0
_calls = 0


def _call_groq(api_key: str, system: str, user_msg: str) -> dict:
    """POST to Groq, retrying on rate limits and falling back on retired models."""
    global _active_model_idx, _failures, _calls
    _calls += 1
    last_err: Exception | None = None
    while _active_model_idx < len(GROQ_MODELS):
        model = GROQ_MODELS[_active_model_idx]
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        if "gpt-oss" in model:
            payload["reasoning_effort"] = "low"
        for attempt in range(4):
            try:
                r = requests.post(
                    GROQ_API,
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json=payload,
                    timeout=90,
                )
            except requests.RequestException as e:
                last_err = e
                time.sleep(5 * (attempt + 1))
                continue
            if r.status_code == 429 and attempt < 3:
                # Free tier has a tokens-per-minute cap; wait it out.
                time.sleep(min(float(r.headers.get("retry-after", 0) or 0) or 15 * (attempt + 1), 60))
                continue
            if r.status_code in (400, 404) and "model" in r.text.lower() and (
                "decommission" in r.text.lower() or "not found" in r.text.lower()
                or "does not exist" in r.text.lower()
            ):
                print(f"[llm] model {model} unavailable ({r.status_code}): {r.text[:200]}; trying next")
                _active_model_idx += 1
                break
            try:
                r.raise_for_status()
                return json.loads(r.json()["choices"][0]["message"]["content"])
            except Exception as e:
                last_err = e
                if r.status_code >= 500 and attempt < 3:
                    time.sleep(5 * (attempt + 1))
                    continue
                _failures += 1
                raise RuntimeError(f"{e}: {r.text[:200]}") from e
        else:
            _failures += 1
            raise RuntimeError(f"retries exhausted: {last_err}")
    _failures += 1
    raise RuntimeError(f"no usable Groq model in {GROQ_MODELS}")


def _record_llm_health() -> None:
    if _calls:
        model = GROQ_MODELS[min(_active_model_idx, len(GROQ_MODELS) - 1)]
        record_health("llm:groq", _failures == 0,
                      f"{_calls - _failures}/{_calls} calls ok, model {model}")


def filter_and_rewrite(findings: list[Finding]) -> list[Finding]:
    """Security lane: drop coincidental matches, rewrite summaries."""
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[llm] GROQ_API_KEY not set; skipping LLM filter")
        return findings
    if not findings:
        return findings

    kept: list[Finding] = []
    dropped = 0

    for start in range(0, len(findings), BATCH_SIZE):
        batch_findings = findings[start : start + BATCH_SIZE]
        batch_input = [
            {
                "idx": i,
                "category": f.category,
                "title": f.title,
                "summary": (f.summary or "")[:800],
                "source": f.source,
            }
            for i, f in enumerate(batch_findings)
        ]
        try:
            results = _call_groq(api_key, SYSTEM_PROMPT,
                                 "Classify these findings:\n\n" + json.dumps(batch_input, indent=2)).get("items", [])
        except Exception as e:
            print(f"[llm] batch {start}–{start + len(batch_findings)} failed: {e}; keeping unfiltered")
            kept.extend(batch_findings)
            continue

        by_idx = {r.get("idx"): r for r in results if isinstance(r, dict)}
        for i, f in enumerate(batch_findings):
            verdict = by_idx.get(i)
            if not verdict:
                # LLM dropped this item from its response — keep to be safe.
                kept.append(f)
                continue
            if verdict.get("keep") is False:
                dropped += 1
                continue
            new_summary = (verdict.get("summary") or "").strip()
            if new_summary:
                f.summary = new_summary
            f.angle = (verdict.get("angle") or "").strip()
            kept.append(f)

    print(f"[llm] security: kept {len(kept)}, dropped {dropped}")
    _record_llm_health()
    return kept


def filter_developments(findings: list[Finding]) -> list[Finding]:
    """Developments lane: keep notable items, merge duplicates, add angles.

    Input should already be sorted best-first, so duplicates collapse onto
    the highest-ranked copy.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key or not findings:
        return findings

    kept: list[Finding] = []
    dropped = merged = 0
    for start in range(0, len(findings), DEV_BATCH_SIZE):
        batch = findings[start : start + DEV_BATCH_SIZE]
        batch_input = [
            {
                "idx": i,
                "source": f.source,
                "title": f.title,
                "summary": (f.summary or "")[:400],
                "popularity": f.popularity,
            }
            for i, f in enumerate(batch)
        ]
        try:
            results = _call_groq(api_key, DEV_SYSTEM_PROMPT,
                                 "Triage these items:\n\n" + json.dumps(batch_input, indent=2)).get("items", [])
        except Exception as e:
            print(f"[llm] developments batch {start} failed: {e}; keeping unfiltered")
            kept.extend(batch)
            continue

        by_idx = {r.get("idx"): r for r in results if isinstance(r, dict)}
        batch_kept: dict[int, Finding] = {}
        for i, f in enumerate(batch):
            verdict = by_idx.get(i)
            if not verdict:
                batch_kept[i] = f
                continue
            if verdict.get("keep") is False:
                dropped += 1
                continue
            dup = verdict.get("duplicate_of")
            if isinstance(dup, int) and dup in batch_kept and dup != i:
                target = batch_kept[dup]
                target.also_in.append(f.popularity or f.source)
                target.boost += 2
                target.score += 2
                if f.discussion_url and not target.discussion_url:
                    target.discussion_url = f.discussion_url
                merged += 1
                continue
            new_summary = (verdict.get("summary") or "").strip()
            if new_summary:
                f.summary = new_summary
            f.angle = (verdict.get("angle") or "").strip()
            batch_kept[i] = f
        kept.extend(batch_kept.values())

    print(f"[llm] developments: kept {len(kept)}, dropped {dropped}, merged {merged} duplicates")
    _record_llm_health()
    return kept


def research_threads(items: list[dict]) -> list[dict]:
    """Weekly roll-up: suggest research threads. Returns [] without a key or on failure."""
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key or not items:
        return []
    payload = [
        {"idx": i, "lane": it.get("lane"), "title": it.get("title"),
         "summary": (it.get("summary") or "")[:300], "angle": it.get("angle", "")}
        for i, it in enumerate(items)
    ]
    try:
        threads = _call_groq(api_key, THREADS_SYSTEM_PROMPT,
                             "This week's items:\n\n" + json.dumps(payload, indent=2)).get("threads", [])
    except Exception as e:
        print(f"[llm] research threads failed: {e}")
        return []
    return [t for t in threads if isinstance(t, dict) and t.get("title")]
