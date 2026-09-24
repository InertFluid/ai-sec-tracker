"""Newly released models that are trending on the Hugging Face Hub.

Open-weight releases often show up here before any blog post. Quantized
re-uploads (GGUF, MLX, AWQ, ...) are skipped so the base model is what surfaces.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from core import Finding, http_get, record_health, parse_dt
from config import HF_TRENDING_LIMIT, HF_MAX_AGE_DAYS, HF_MIN_LIKES

HF_API = "https://huggingface.co/api/models"
_QUANT_RE = re.compile(r"(gguf|mlx|awq|gptq|exl2|bnb|\b\d-?bit\b|-fp8|-int[48])", re.I)


def fetch() -> list[Finding]:
    params = [("sort", "trendingScore"), ("limit", str(HF_TRENDING_LIMIT))] + [
        ("expand[]", k) for k in ("createdAt", "likes", "trendingScore", "pipeline_tag", "downloads")
    ]
    try:
        models = http_get(HF_API, params=params).json()
    except Exception as e:
        record_health("huggingface", False, str(e))
        return []
    record_health("huggingface", bool(models), f"{len(models)} trending models")

    cutoff = datetime.now(timezone.utc) - timedelta(days=HF_MAX_AGE_DAYS)
    findings: list[Finding] = []
    for m in models:
        model_id = m.get("id", "")
        created = parse_dt(m.get("createdAt"))
        likes = m.get("likes", 0)
        if not created or created < cutoff or likes < HF_MIN_LIKES or _QUANT_RE.search(model_id):
            continue
        task = m.get("pipeline_tag") or "model"
        findings.append(Finding(
            source="huggingface",
            category="model",
            title=f"Trending new model: {model_id}",
            url=f"https://huggingface.co/{model_id}",
            summary=f"{task} · {likes:,} likes · {m.get('downloads', 0):,} downloads · created {created.date()}",
            published=created.isoformat(),
            lane="developments",
            boost=min(likes // 250, 8) + 1,
            popularity=f"🤗 {likes:,} likes",
        ))
    return findings


if __name__ == "__main__":
    for f in fetch():
        print(f.popularity, "|", f.title)
