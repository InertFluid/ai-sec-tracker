"""Optional Groq-powered filter/summarizer for findings.

Runs after keyword scoring, before posting. Uses Groq's free-tier LLM to:
  1. Drop items where the keyword match was coincidental (e.g. a CVE that
     mentions "ray" but is about unrelated software).
  2. Rewrite verbose abstracts/advisory text into a single skimmable line.

Best-effort: if GROQ_API_KEY is unset or the API call fails for any reason,
the original findings are returned unchanged.
"""
from __future__ import annotations

import json
import os
import requests

from core import Finding

GROQ_API = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
BATCH_SIZE = 15

SYSTEM_PROMPT = """You are filtering security findings for a daily digest focused on AI / LLM / agent security.

For each finding, decide:
  keep: true if the item is genuinely about AI, LLMs, agents, ML infrastructure, prompt injection, model security, vector stores, agent frameworks (LangChain, LlamaIndex, AutoGen, CrewAI, MCP, etc.), or vulnerabilities in AI/ML tooling. false if the keyword match was coincidental (e.g. a CVE that happens to contain "ray" or "openai" in its text but is about unrelated software like project-management tools, OSINT tools, chat UIs with no AI focus, etc.).
  summary: one crisp sentence (max 160 chars) describing what it actually is. Plain prose, no markdown.

Respond with a JSON object of the form: {"items": [{"idx": 0, "keep": true, "summary": "..."}, ...]} — one entry per input item, preserving idx."""


def _call_groq(api_key: str, batch: list[dict]) -> list[dict]:
    user_msg = "Classify these findings:\n\n" + json.dumps(batch, indent=2)
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    r = requests.post(
        GROQ_API,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=60,
    )
    r.raise_for_status()
    content = r.json()["choices"][0]["message"]["content"]
    data = json.loads(content)
    return data.get("items", [])


def filter_and_rewrite(findings: list[Finding]) -> list[Finding]:
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
            results = _call_groq(api_key, batch_input)
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
            kept.append(f)

    print(f"[llm] kept {len(kept)}, dropped {dropped} via LLM filter")
    return kept
