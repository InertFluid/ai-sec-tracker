# AI / Agent Security Tracker

Automated daily digest of new AI developments, CVEs, advisories, research
papers, framework releases, and blog posts relevant to AI and agent security,
plus a weekly roll-up with suggested research threads. Runs on GitHub
Actions (free) and posts to a Discord channel.

It is built to support the guard0 research team's rapid-response rotation:
the **Top AI Developments** section flags major launches (models, agents,
frameworks, incidents) on day one, each with a suggested guard0 security
angle, so the team can be first with a credible take.

## Two lanes

| Lane | What it catches | How items are selected |
|---|---|---|
| **Developments** | Model launches, lab announcements, trending discussion, new lab repos and models | Source authority + popularity (HN points, Bluesky/X likes, HF likes, GitHub stars). *Not* security keywords, so "Introducing System One Models and Jev" isn't dropped for never saying "prompt injection". The LLM then keeps only notable items, merges duplicate coverage, and suggests a guard0 angle. |
| **Security** | CVEs, advisories, papers, research blogs, AI-security vendor research | Keyword score ≥ `MIN_SCORE` (AI-security sources are trusted and bypass it), then the LLM drops coincidental matches and marketing. |

## Pipeline

Each run executes:

1. **Fetch** — every source in `sources/` is queried for items published in
   the last `LOOKBACK_DAYS` (default 2). Each endpoint records whether it
   worked (see *Source health*).
2. **Dedupe** — URLs are normalized (tracking params, `www`, trailing slash)
   so the same story from a lab blog, HN, and Bluesky collapses into one
   item that notes where else it appeared. IDs already in `state.json` are dropped.
3. **Score** — security items are keyword-scored via `core.score_finding`;
   CVEs get a severity-based floor. Developments get a floor plus their
   popularity boost.
4. **LLM filter (optional)** — if `GROQ_API_KEY` is set, both lanes go to
   Groq for a relevance recheck, 1-line summary, and research angle.
5. **Post** — the top `DEVELOPMENTS_MAX` developments first, then security
   sections, sent to Discord in chunked messages under the 2000-char limit.
6. **Persist** — `state.json` stores seen IDs, sitemap baselines, and
   posted-item history *only on successful delivery*; source health is saved
   every run. The workflow exits non-zero if the Discord post fails.

## Sources

| Source | Lane | Fetcher |
|---|---|---|
| Hacker News (Algolia API, ≥ `HN_MIN_POINTS` + AI term) | Developments | `sources/hn_source.py` |
| AI lab blogs — OpenAI, Google DeepMind, Google AI, Meta AI, Qwen, Microsoft Research, NVIDIA | Developments | `sources/rss_source.py` |
| Labs with no RSS — Anthropic, Mistral, xAI (new sitemap URLs) | Developments | `sources/sitemap_source.py` |
| Tech press — The Register, TechCrunch, The Verge, Ars Technica, heise, 404 Media | Developments | `sources/rss_source.py` |
| Newsletters — Import AI, Latent Space, Interconnects | Developments | `sources/rss_source.py` |
| Bluesky — AI researchers, builders, commentators, labs + AI posts from security accounts | Developments | `sources/bluesky_source.py` |
| X / Twitter — labs, AI leaders, AI-security researchers (**optional**, needs `X_BEARER_TOKEN`) | Developments | `sources/x_source.py` |
| Reddit top-of-day — r/LocalLLaMA, r/MachineLearning, r/netsec | Both | `sources/reddit_source.py` |
| Hugging Face trending new models | Developments | `sources/huggingface_source.py` |
| New repos in AI lab GitHub orgs | Developments | `sources/github_source.py` |
| arXiv (`cs.CR`, `cs.AI`, `cs.LG`, `cs.CL`) | Security | `sources/arxiv_source.py` |
| NVD CVE API 2.0 | Security | `sources/nvd_source.py` |
| GitHub Security Advisories + tracked-repo releases | Security | `sources/github_source.py` |
| AI-security research — Embrace The Red, Adversa, OWASP GenAI, Promptfoo, METR, Anthropic Frontier Red Team, Cisco AI | Security (trusted) | `sources/rss_source.py` |
| AI-security vendors with no RSS — Lakera, Pillar, Zenity, Noma, Mindgard, PromptArmor, Repello, Lasso, SPLX, Straiker, UK AISI | Security (trusted) | `sources/sitemap_source.py` |
| Security research/news — Trail of Bits, Project Zero, PortSwigger, Unit 42, Wiz, Snyk, GitHub Security Lab, MSRC/Google/AWS security blogs, Talos, BleepingComputer, The Hacker News, Dark Reading, tl;dr sec, … | Security | `sources/rss_source.py` |

Notes:

- **Sitemap watches** detect *new URLs*, not `<lastmod>` (which many sites
  bump on every edit). The first run for a site records a baseline silently.
  If a sitemap suddenly shows more than `SITEMAP_MAX_NEW` new URLs, it's
  treated as a site restructure and re-baselined instead of flooding Discord.
- **Meta AI and the Anthropic red-team blog** come from the community
  [Olshansk/rss-feeds](https://github.com/Olshansk/rss-feeds) scrapes, because
  those sites have no feed and block direct fetches.
- **X / Twitter** is the fastest channel but reading via the API needs a paid
  plan. Without `X_BEARER_TOKEN` the source is skipped; HN, Bluesky, and the
  newsletters usually pick up big X threads within hours.
- **Reddit's** JSON API now needs OAuth, so the public top-of-day RSS is used
  (rank, not vote count, is the popularity signal). Reddit rate-limits
  aggressively; the health check will say if Actions gets blocked.

## Setup

1. **Create a new GitHub repo** and drop this folder into it. Public is fine — no secrets live in the code, and public repos get unlimited free Actions minutes.
2. **Create a Discord webhook** → in your server, open channel settings (gear icon) → *Integrations* → *Webhooks* → *New Webhook* → name it → *Copy Webhook URL*.
3. **Add secrets** to the repo (Settings → Secrets and variables → Actions):
   - `DISCORD_WEBHOOK_URL` (required)
   - `GROQ_API_KEY` (strongly recommended — the LLM filter is what keeps the developments lane down to notable items and adds research angles. Get a free key at [console.groq.com](https://console.groq.com))
   - `NVD_API_KEY` (optional — [request one here](https://nvd.nist.gov/developers/request-an-api-key), raises your rate limit and speeds up NVD pagination)
   - `X_BEARER_TOKEN` (optional — enables the X/Twitter source; requires a paid X API plan)
   - `GITHUB_TOKEN` is provided automatically by Actions.
4. **Enable workflow write permissions**: Settings → Actions → General → Workflow permissions → *Read and write*. This lets the workflow commit `state.json` back.
5. **Test it**: Actions tab → *AI Security Digest* → *Run workflow*. The weekly roll-up is *AI Security Weekly Roll-up* (Mondays).

### Schedule

The digest targets Discord before ~07:00 IST. GitHub starts scheduled
workflows late under load (1–5 hours observed on this repo, and some days
not at all), so `digest.yml` has two crons: a primary at 01:47 IST and a
backup at 04:13 IST. Scheduled runs use `--skip-if-posted-within 10`, so
whichever runs second exits without posting. Manual runs always post. The
weekly roll-up runs Mondays 04:27 IST.

## Customization

All knobs live in `config.py`:

- `KEYWORDS` / `MIN_SCORE` — security-lane scoring.
- `TRACKED_REPOS` — watched for releases and advisory matches.
- `SECURITY_FEEDS`, `AI_SECURITY_FEEDS`, `DEVELOPMENT_FEEDS` — RSS feeds per lane.
- `SITEMAP_WATCHES` — sites without feeds (`include` / `exclude` regexes).
- `HN_MIN_POINTS`, `REDDIT_SUBS`, `HF_*`, `LAB_GITHUB_ORGS`, `LAB_REPO_MIN_STARS` — developments sources.
- `BSKY_AI_ACCOUNTS` (every post on-topic), `BSKY_GENERAL_ACCOUNTS` (AI posts only), `BSKY_MIN_LIKES`, `BSKY_MEDIAN_MULT`.
- `X_ACCOUNTS`, `X_MIN_LIKES`.
- `AI_TERMS` — what counts as "about AI" for HN, general press, and general accounts.
- `DEVELOPMENTS_MAX` — how many developments to show per digest.
- `NVD_RELEVANT_TERMS` — substrings to consider a CVE relevant.
- `LOOKBACK_DAYS` — how far back each run looks.
- `HEALTH_FAIL_STREAK`, `STALE_DAYS` — source-health alerting.

## Local run

```bash
pip install -r requirements.txt
export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
export GROQ_API_KEY=gsk_...   # optional
python main.py
```

To preview without posting or touching `state.json`:

```bash
python main.py --dry-run           # daily digest + per-source health
python main.py --weekly --dry-run  # weekly roll-up
python main.py --check-health      # exit 1 if any source is failing
python main.py --skip-if-posted-within 10  # no-op if a digest went out in the last 10h
```

On macOS with the python.org installer, run `Install Certificates.command`
(or `export SSL_CERT_FILE=$(python3 -m certifi)`) first, or every HTTPS
fetch fails with `CERTIFICATE_VERIFY_FAILED`.

## LLM filter

When `GROQ_API_KEY` is set, `llm_filter.py` runs between scoring and posting:

- **Security lane:** drops coincidental keyword matches (e.g. a CVE that
  mentions "ray" but is about an unrelated product) and vendor marketing;
  rewrites abstracts / advisory text into one sentence naming the affected
  product; adds a research angle when there's a clear one.
- **Developments lane:** keeps only notable developments, merges duplicate
  coverage of the same story, writes a one-line summary, and suggests the
  guard0 angle (what to test, measure, or write about).
- **Weekly roll-up:** proposes 3–5 research threads from the week's items.
- **Releases bypass the LLM** — their raw changelog bullets are more
  informative than any rewrite.
- **Best-effort** — if the API key is missing or a call fails, the affected
  batch passes through unchanged. The digest always goes out, and failures
  show up under `llm:groq` in source health.

Model defaults to `openai/gpt-oss-120b` (Groq decommissioned
`llama-3.3-70b-versatile` on 2026-08-16, which silently disabled the filter).
If Groq reports a model as retired, the filter falls back to
`openai/gpt-oss-20b` automatically. Override with the `GROQ_MODEL` env var.

## Source health

Every fetcher records per-endpoint health (HTTP errors, feeds that return no
entries, sitemaps that stop matching). `state.json` tracks a consecutive-failure
streak per source:

- A source failing `HEALTH_FAIL_STREAK` (3) runs in a row is listed at the
  bottom of the Discord digest and turns the Actions run red via
  `python main.py --check-health`, with an annotation per failing source.
- Feeds whose newest entry is older than `STALE_DAYS` are flagged as stale
  (warning only) in the weekly roll-up and the run summary.
- The Actions step summary has a table of every unhealthy source.

This exists because arXiv returned 0 papers and several feeds (HiddenLayer,
Protect AI, NCC Group) returned nothing for weeks without anyone noticing.

## Weekly roll-up

`.github/workflows/weekly.yml` runs `python main.py --weekly` on Mondays. It
reads the last 7 days of posted items from `state.json` and posts the biggest
developments, top security items, LLM-suggested research threads, and any
failing or stale sources. It does not modify state.

## State

`state.json` is committed back to the repo at the end of each run. It stores:

- `seen_ids` — items already processed, so you never get duplicates (capped
  at 6000; only updated after a successful post).
- `sitemaps` — known-URL baselines per sitemap watch (hashes).
- `history` — the last 8 days of posted items, for the weekly roll-up.
- `health` — per-source failure streaks and last status.

## Extending

- **New source?** Add `sources/yoursource.py` exposing `fetch() -> list[Finding]`, call `record_health()` for each endpoint, set `lane="developments"` and a `boost` if it's news rather than security, and register it in `main.py`.
- **New delivery channel?** Mirror `discord_notifier.py` — e.g. `email_notifier.py` using SMTP or SES — and call it from `main.py`.
- **Per-category thresholds?** Modify `core.score_finding` or the filter in `main.run_daily`.

## Tuning signal vs noise

After a week of digests, review items flagged as low-value and:
- Lower weights on noisy keywords (e.g. bare `llm` is deliberately weak).
- Raise `MIN_SCORE` if the security sections feel too busy.
- Raise `HN_MIN_POINTS` / `BSKY_MEDIAN_MULT` / `X_MIN_LIKES` or lower `DEVELOPMENTS_MAX` if the developments lane is noisy.
- Remove feeds that don't pull their weight (the weekly stale list helps).
