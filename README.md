# AI / Agent Security Tracker

Automated daily digest of new CVEs, advisories, research papers, framework
releases, and blog posts relevant to AI and agent security. Runs on GitHub
Actions (free) and posts to a Discord channel.

## Pipeline

Each run executes:

1. **Fetch** — every source in `sources/` is queried for items published in
   the last `LOOKBACK_DAYS` (default 2).
2. **Dedupe** — IDs already in `state.json` are dropped.
3. **Score** — remaining items are keyword-scored via `core.score_finding`.
   Items below `MIN_SCORE` drop out. CVEs get a severity-based floor so
   Criticals/Highs can't be filtered out by a weak keyword score.
4. **LLM filter (optional)** — if `GROQ_API_KEY` is set, surviving items
   (excluding releases, which are passed through) go to Groq for a
   relevance recheck + 1-line summary rewrite. See *LLM filter* below.
5. **Post** — all kept items are sent to Discord in chunked messages
   under the 2000-char content limit.
6. **Persist** — `state.json` is updated *only on successful delivery*,
   and the workflow exits non-zero if the Discord post fails so failures
   show up as red X in the Actions UI.

## Sources

| Source | Category | Fetcher |
|---|---|---|
| arXiv (`cs.CR`, `cs.AI`, `cs.LG`) | Papers | `sources/arxiv_source.py` |
| NVD CVE API 2.0 | CVEs | `sources/nvd_source.py` |
| GitHub Security Advisories | Advisories | `sources/github_source.py` |
| GitHub Releases (tracked repos) | Framework releases | `sources/github_source.py` |
| RSS (Embrace The Red, HiddenLayer, ToB, PortSwigger, etc.) | Blogs | `sources/rss_source.py` |

## Setup

1. **Create a new GitHub repo** and drop this folder into it. Public is fine — no secrets live in the code, and public repos get unlimited free Actions minutes.
2. **Create a Discord webhook** → in your server, open channel settings (gear icon) → *Integrations* → *Webhooks* → *New Webhook* → name it → *Copy Webhook URL*.
3. **Add secrets** to the repo (Settings → Secrets and variables → Actions):
   - `DISCORD_WEBHOOK_URL` (required)
   - `NVD_API_KEY` (optional — [request one here](https://nvd.nist.gov/developers/request-an-api-key), raises your rate limit)
   - `GROQ_API_KEY` (optional — enables an LLM filter that drops coincidental keyword matches and rewrites summaries into 1-liners. Get a free key at [console.groq.com](https://console.groq.com))
   - `GITHUB_TOKEN` is provided automatically by Actions.
4. **Enable workflow write permissions**: Settings → Actions → General → Workflow permissions → *Read and write*. This lets the workflow commit `state.json` back.
5. **Test it**: Actions tab → *AI Security Digest* → *Run workflow*.

## Customization

All knobs live in `config.py`:

- `KEYWORDS` — add terms and weights. Score threshold is `MIN_SCORE`.
- `TRACKED_REPOS` — watched for releases and advisory matches.
- `RSS_FEEDS` — add new blogs as tuples of `(name, feed_url)`.
- `NVD_RELEVANT_TERMS` — substrings to consider a CVE relevant.
- `LOOKBACK_DAYS` — how far back each run looks.

## Local run

```bash
pip install -r requirements.txt
export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
export GROQ_API_KEY=gsk_...   # optional
python main.py
```

To run without posting to Discord, just don't set the env var — you'll still
see what *would* have been sent in the console output. Note that without a
webhook the run exits non-zero and skips the state update, so nothing gets
marked "seen".

## LLM filter

When `GROQ_API_KEY` is set, `llm_filter.py` runs between scoring and posting:

- Drops items where the keyword match was coincidental (e.g. a CVE that
  happens to mention "ray" but is about an unrelated product).
- Rewrites verbose abstracts / advisory text into one crisp sentence that
  names the affected product.
- **Releases bypass the LLM** — their raw changelog bullets are more
  informative than any rewrite.
- **Best-effort** — if the API key is missing or a call fails, the affected
  batch passes through unchanged. The digest always goes out.

Model defaults to `llama-3.3-70b-versatile`; override with the `GROQ_MODEL`
env var if you want to swap (e.g. to `llama-3.1-8b-instant` for faster, or
a newer Groq-hosted model).

## State

`state.json` is committed back to the repo at the end of each run, *but
only if Discord delivery succeeded*. It stores the IDs of items already
seen so you never get duplicates. It is capped at 2000 IDs to prevent
unbounded growth.

## Extending

- **New source?** Add `sources/yoursource.py` exposing `fetch() -> list[Finding]` and register it in `main.py`.
- **New delivery channel?** Mirror `discord_notifier.py` — e.g. `email_notifier.py` using SMTP or SES — and call it from `main.py`.
- **Per-category thresholds?** Modify `core.score_finding` or the filter in `main.run`.

## Tuning signal vs noise

After a week of digests, review items flagged as low-value and:
- Lower weights on noisy keywords (e.g. bare `llm` is deliberately weak).
- Raise `MIN_SCORE` if the Discord channel feels too busy.
- Remove RSS feeds that don't pull their weight.
