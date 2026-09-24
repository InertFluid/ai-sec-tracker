"""Configuration: keywords, sources, lanes, and scoring weights.

The digest has two lanes:

* **security** — CVEs, advisories, papers, research blogs. Items must clear
  the keyword score threshold (``MIN_SCORE``) unless they come from a trusted
  AI-security source.
* **developments** — model launches, lab announcements, trending discussion.
  Items are ranked by source authority + popularity, *not* security keywords,
  so a launch like "Introducing System One Models and Jev" is not dropped just
  because it never says "prompt injection".
"""

# Keywords used to score relevance. Higher weights = stronger signal.
# Scored case-insensitively against title + summary.
KEYWORDS = {
    # High-signal AI security terms
    "prompt injection": 5,
    "indirect prompt injection": 6,
    "jailbreak": 4,
    "llm security": 5,
    "agent security": 6,
    "ai agent": 3,
    "tool poisoning": 6,
    "mcp": 4,  # Model Context Protocol — noisy but important
    "model context protocol": 6,
    "rag poisoning": 5,
    "data exfiltration": 3,
    "adversarial": 2,
    "llm": 2,
    "guardrail": 3,
    "red team": 2,
    "alignment": 1,
    "agentic": 3,
    "autonomous agent": 3,
    "coding agent": 3,
    "model weights": 2,
    "backdoor": 2,
    "supply chain": 2,
    # Frameworks / products
    "langchain": 4,
    "llamaindex": 4,
    "autogen": 4,
    "crewai": 4,
    "semantic kernel": 4,
    "openai": 2,
    "anthropic": 2,
    "claude": 2,
    "gemini": 2,
    "copilot": 2,
    "gpt-4": 1,
    # Attack classes
    "rce": 3,
    "remote code execution": 3,
    "ssrf": 2,
    "privilege escalation": 2,
    "sandbox escape": 4,
}

# Minimum score for a finding to be included in the digest.
MIN_SCORE = 3

# How many days back to look on first run / for NVD queries.
LOOKBACK_DAYS = 2

# ---------------------------------------------------------------------------
# Security lane
# ---------------------------------------------------------------------------

# arXiv categories + query
ARXIV_CATEGORIES = ["cs.CR", "cs.AI", "cs.LG", "cs.CL"]
ARXIV_QUERY_TERMS = [
    "prompt injection",
    "LLM security",
    "agent security",
    "jailbreak",
    "AI agent attack",
    "tool poisoning",
    "model context protocol",
    "agent hijacking",
    "LLM backdoor",
    "red teaming",
]

# General security blogs/news. Items must clear the keyword threshold.
SECURITY_FEEDS = [
    ("Simon Willison", "https://simonwillison.net/atom/everything/"),
    ("Trail of Bits", "https://blog.trailofbits.com/feed/"),
    ("Google Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("PortSwigger Research", "https://portswigger.net/research/rss"),
    ("Hugging Face Blog", "https://huggingface.co/blog/feed.xml"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Palo Alto Networks", "https://www.paloaltonetworks.com/blog/feed/"),
    ("Wiz", "https://www.wiz.io/feed/rss.xml"),
    ("Snyk", "https://snyk.io/blog/feed/"),
    ("Legit Security", "https://www.legitsecurity.com/blog/rss.xml"),
    ("GitHub Security Lab", "https://securitylab.github.com/advisories/feed.xml"),
    ("GitHub Blog Security", "https://github.blog/security/feed/"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Google Security Blog", "https://security.googleblog.com/feeds/posts/default"),
    ("AWS Security", "https://aws.amazon.com/blogs/security/feed/"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Cloudflare AI", "https://blog.cloudflare.com/tag/ai/rss/"),
    ("CrowdStrike", "https://www.crowdstrike.com/en-us/blog/feed"),
    ("Schneier on Security", "https://www.schneier.com/feed/atom/"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://thehackernews.com/feeds/posts/default"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("tl;dr sec", "https://tldrsec.com/feed.xml"),
]

# AI-security-focused sources. Everything they publish is on-topic, so items
# bypass the keyword threshold (the LLM filter still drops marketing fluff).
AI_SECURITY_FEEDS = [
    ("Embrace The Red", "https://embracethered.com/blog/index.xml"),
    ("Adversa AI", "https://adversa.ai/feed/"),
    ("OWASP GenAI", "https://genai.owasp.org/feed/"),
    ("Promptfoo", "https://www.promptfoo.dev/blog/rss.xml"),
    ("Cisco AI", "https://blogs.cisco.com/ai/feed"),
    ("METR", "https://metr.org/feed.xml"),
    # Community-maintained scrape (Olshansk/rss-feeds); red.anthropic.com has no feed.
    ("Anthropic Frontier Red Team", "https://raw.githubusercontent.com/Olshansk/rss-feeds/main/feeds/feed_anthropic_red.xml"),
]

# ---------------------------------------------------------------------------
# Developments lane
# ---------------------------------------------------------------------------

# (name, url, kind). kind controls ranking + filtering:
#   lab           — official AI lab/vendor announcements; always considered
#   press         — AI section of a tech outlet; capped per run
#   press-general — whole-site feed; only AI-related items kept
#   newsletter    — curated AI newsletters
DEVELOPMENT_FEEDS = [
    ("OpenAI", "https://openai.com/news/rss.xml", "lab"),
    ("Google DeepMind", "https://deepmind.google/blog/rss.xml", "lab"),
    ("Google AI", "https://blog.google/technology/ai/rss/", "lab"),
    ("Microsoft Research", "https://www.microsoft.com/en-us/research/feed/", "press-general"),
    ("NVIDIA", "https://blogs.nvidia.com/feed/", "press-general"),
    # Community-maintained scrape; ai.meta.com blocks direct fetches.
    ("Meta AI", "https://raw.githubusercontent.com/Olshansk/rss-feeds/main/feeds/feed_meta_ai.xml", "lab"),
    ("Qwen", "https://qwenlm.github.io/blog/index.xml", "lab"),
    ("The Register AI", "https://www.theregister.com/software/ai_ml/headlines.atom", "press"),
    ("TechCrunch AI", "https://techcrunch.com/category/artificial-intelligence/feed/", "press"),
    ("The Verge AI", "https://www.theverge.com/rss/ai-artificial-intelligence/index.xml", "press"),
    ("Ars Technica AI", "https://arstechnica.com/ai/feed/", "press"),
    ("heise", "https://www.heise.de/rss/heise-atom.xml", "press-general"),
    ("404 Media", "https://www.404media.co/rss/", "press-general"),
    ("Import AI", "https://jack-clark.net/feed/", "newsletter"),  # substack URL 403s from Actions
    ("Latent Space", "https://www.latent.space/feed", "newsletter"),
    ("Interconnects", "https://www.interconnects.ai/feed", "newsletter"),
]

# Sites with no RSS feed. New URLs in their sitemap become findings. The
# first run records a baseline silently, so only genuinely new pages surface.
#   lane: "developments" (lab announcements) or "ai-security" (trusted research)
SITEMAP_WATCHES = [
    {"name": "Anthropic", "sitemap": "https://www.anthropic.com/sitemap.xml",
     "include": r"^https://www\.anthropic\.com/(news|research|engineering)/[^/]+$", "lane": "developments"},
    {"name": "Mistral AI", "sitemap": "https://mistral.ai/sitemap.xml",
     "include": r"^https://mistral\.ai/news/[^/]+/?$", "lane": "developments"},
    {"name": "xAI", "sitemap": "https://x.ai/sitemap.xml",
     "include": r"^https://x\.ai/news/[^/]+/?$", "lane": "developments"},
    {"name": "UK AISI", "sitemap": "https://www.aisi.gov.uk/sitemap.xml",
     "include": r"/(blog|research)/[^/]+$", "lane": "ai-security"},
    {"name": "Lakera", "sitemap": "https://www.lakera.ai/sitemap.xml",
     "include": r"/blog/[^/]+$", "lane": "ai-security"},
    {"name": "Pillar Security", "sitemap": "https://www.pillar.security/sitemap.xml",
     "include": r"/blog/[^/]+$", "lane": "ai-security"},
    {"name": "Zenity", "sitemap": "https://zenity.io/sitemap.xml",
     "include": r"/(blog|research)/[^/]+$", "lane": "ai-security"},
    {"name": "Noma Security", "sitemap": "https://noma.security/sitemap.xml",
     "include": r"/blog/[^/]+/?$", "lane": "ai-security"},
    {"name": "Mindgard", "sitemap": "https://www.mindgard.ai/sitemap.xml",
     "include": r"/blog/[^/]+$", "lane": "ai-security"},
    {"name": "PromptArmor", "sitemap": "https://www.promptarmor.com/sitemap.xml",
     "include": r"/resources/[^/]+$", "lane": "ai-security"},
    {"name": "Repello AI", "sitemap": "https://repello.ai/sitemap.xml",
     "include": r"/blog/[^/]+$", "exclude": r"/blog/(page|category|tag|author)/", "lane": "ai-security"},
    {"name": "Lasso Security", "sitemap": "https://www.lasso.security/sitemap.xml",
     "include": r"/blog/[^/]+$", "lane": "ai-security"},
    {"name": "SPLX", "sitemap": "https://splx.ai/sitemap.xml",
     "include": r"/blog/[^/]+$", "lane": "ai-security"},
    {"name": "Straiker", "sitemap": "https://www.straiker.ai/sitemap.xml",
     "include": r"/blog/[^/]+$", "lane": "ai-security"},
]
# If a sitemap suddenly yields more new URLs than this, assume the site was
# restructured and re-baseline instead of flooding the digest.
SITEMAP_MAX_NEW = 15

# Hacker News (Algolia API). Stories need this many points AND an AI term.
HN_MIN_POINTS = 150

# Reddit top-of-day RSS (the JSON API now requires OAuth). (subreddit, top_n, lane)
REDDIT_SUBS = [
    ("LocalLLaMA", 5, "developments"),
    ("MachineLearning", 3, "developments"),
    ("netsec", 5, "security"),
]

# Hugging Face trending models: new (<= max age) and liked enough.
HF_TRENDING_LIMIT = 30
HF_MAX_AGE_DAYS = 10
HF_MIN_LIKES = 150

# New repos from AI lab GitHub orgs (e.g. a model's reference code dropping).
LAB_GITHUB_ORGS = [
    "openai", "anthropics", "google-deepmind", "google-gemini", "meta-llama",
    "facebookresearch", "mistralai", "deepseek-ai", "QwenLM", "xai-org",
    "huggingface", "modelcontextprotocol", "allenai", "moonshotai", "zai-org",
]
LAB_REPO_MIN_STARS = 50
LAB_REPO_LOOKBACK_DAYS = 5  # longer than LOOKBACK_DAYS: stars take a few days

# Bluesky (public API, no auth). A post surfaces when its likes clear
# max(BSKY_MIN_LIKES, BSKY_MEDIAN_MULT x the account's recent median), so
# prolific posters need a genuinely standout post.
BSKY_AI_ACCOUNTS = [
    # AI researchers, builders, commentators, and labs — every post is on-topic.
    "simonwillison.net", "emollick.bsky.social", "natolambert.bsky.social",
    "minimaxir.bsky.social", "timkellogg.me", "hardmaru.bsky.social",
    "melaniemitchell.bsky.social", "mmitchell.bsky.social", "garymarcus.bsky.social",
    "hamel.bsky.social", "yoavgo.bsky.social", "willknight.bsky.social",
    "ai2.bsky.social", "unsloth.ai", "pytorch.org",
]
BSKY_GENERAL_ACCOUNTS = [
    # Broader tech/security accounts — only AI-related posts are kept.
    "swiftonsecurity.com", "caseynewton.bsky.social", "danielmiessler.bsky.social",
    "thezdi.bsky.social", "owasp.org", "wiz.io",
]
BSKY_MIN_LIKES = 15
BSKY_MEDIAN_MULT = 3

# X / Twitter. Only runs when X_BEARER_TOKEN is set (the API is paid).
X_ACCOUNTS = [
    # Labs
    "OpenAI", "OpenAIDevs", "AnthropicAI", "claudeai", "GoogleDeepMind", "AIatMeta",
    "MistralAI", "xai", "deepseek_ai", "Alibaba_Qwen", "Kimi_Moonshot", "huggingface",
    # AI leaders, researchers, and trackers
    "sama", "karpathy", "ylecun", "JeffDean", "demishassabis", "OfficialLoganK",
    "AndrewYNg", "ClementDelangue", "DrJimFan", "_akhaliq", "rasbt", "polynoamial",
    "tszzl", "swyx", "simonw", "natolambert", "emollick", "btibor91", "testingcatalog",
    "lmarena_ai", "ArtificialAnlys", "EpochAIResearch", "METR_Evals", "AISecurityInst",
    # AI security researchers
    "wunderwuzzi23", "elder_plinius", "rez0__", "KGreshake", "goodside",
    "random_walker", "llm_sec", "danielmiessler", "Jhaddix",
]
X_MIN_LIKES = 250

# Words that make an item "about AI" for the developments lane filters.
# Matched as whole words, case-insensitive.
AI_TERMS = [
    "ai", "agi", "llm", "llms", "gpt", "chatgpt", "openai", "anthropic", "claude",
    "gemini", "deepmind", "grok", "xai", "mistral", "llama", "qwen", "deepseek",
    "kimi", "copilot", "codex", "hugging face", "huggingface", "agent", "agents",
    "agentic", "machine learning", "neural", "transformer", "diffusion", "model",
    "models", "inference", "fine-tuning", "fine-tune", "open-weight", "open weights",
    "chatbot", "mcp", "prompt", "prompts", "embedding", "embeddings", "rag",
    "reasoning", "benchmark", "sora", "midjourney", "vibe coding",
]

# How many developments to show per digest, and how many to send to the LLM.
DEVELOPMENTS_MAX = 15
DEVELOPMENTS_LLM_MAX = 50
SECURITY_LLM_MAX = 80

# ---------------------------------------------------------------------------
# NVD / health
# ---------------------------------------------------------------------------

# NVD CPE vendor/product substrings to flag as AI/ML relevant.
# Applied to the CVE's configurations.
NVD_RELEVANT_TERMS = [
    "langchain", "llama", "autogen", "semantic_kernel", "ollama",
    "vllm", "transformers", "huggingface", "openai", "anthropic",
    "crewai", "pytorch", "tensorflow", "gradio", "streamlit",
    "mlflow", "ray", "triton", "nemo", "rebuff", "pinecone",
    "chromadb", "weaviate", "qdrant", "pgvector", "langflow",
    "litellm", "open_webui", "n8n", "flowise", "dify",
]

# A source that fails this many runs in a row is reported as failing and
# turns the workflow red.
HEALTH_FAIL_STREAK = 3
# A feed whose newest entry is older than this is flagged as stale (warning only).
STALE_DAYS = 90
