# AI / Agent Security Tracker

Automated daily digest of new CVEs, advisories, research papers, framework
releases, and blog posts relevant to AI and agent security. Runs on GitHub
Actions (free) and posts to a Discord channel.

## Sources

| Source | Category | Fetcher |
|---|---|---|
| arXiv (`cs.CR`, `cs.AI`, `cs.LG`) | Papers | `sources/arxiv_source.py` |
| NVD CVE API 2.0 | CVEs | `sources/nvd_source.py` |
| GitHub Security Advisories | Advisories | `sources/github_source.py` |
| GitHub Releases (tracked repos) | Framework releases | `sources/github_source.py` |
| RSS (Embrace The Red, HiddenLayer, ToB, PortSwigger, etc.) | Blogs | `sources/rss_source.py` |

## Setup

1. **Create a new private GitHub repo** and drop this folder into it.
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
python main.py
```

To run without posting to Discord, just don't set the env var — you'll still see
what *would* have been sent in the console output.

## State

`state.json` is committed back to the repo each run. It stores the IDs of
items already seen so you never get duplicates. It is capped at 2000 IDs to
prevent unbounded growth.

## Extending

- **New source?** Add `sources/yoursource.py` exposing `fetch() -> list[Finding]` and register it in `main.py`.
- **New delivery channel?** Mirror `discord_notifier.py` — e.g. `email_notifier.py` using SMTP or SES — and call it from `main.py`.
- **Per-category thresholds?** Modify `core.score_finding` or the filter in `main.run`.

## Tuning signal vs noise

After a week of digests, review items flagged as low-value and:
- Lower weights on noisy keywords (e.g. bare `llm` is deliberately weak).
- Raise `MIN_SCORE` if the Slack channel feels too busy.
- Remove RSS feeds that don't pull their weight.
