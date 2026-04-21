"""Configuration: keywords, tracked repos, RSS feeds, and scoring weights."""

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
    # Frameworks / products
    "langchain": 4,
    "llamaindex": 4,
    "autogen": 4,
    "crewai": 4,
    "semantic kernel": 4,
    "openai": 2,
    "anthropic": 2,
    "claude": 2,
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

# arXiv categories + query
ARXIV_CATEGORIES = ["cs.CR", "cs.AI", "cs.LG"]
ARXIV_QUERY_TERMS = [
    "prompt injection",
    "LLM security",
    "agent security",
    "jailbreak",
    "AI agent attack",
    "tool poisoning",
]

# GitHub repos to monitor for releases + security advisories.
# Format: "owner/repo"
TRACKED_REPOS = [
    "langchain-ai/langchain",
    "langchain-ai/langgraph",
    "run-llama/llama_index",
    "microsoft/autogen",
    "crewAIInc/crewAI",
    "microsoft/semantic-kernel",
    "modelcontextprotocol/servers",
    "anthropics/anthropic-sdk-python",
    "openai/openai-python",
    "vllm-project/vllm",
    "ollama/ollama",
    "huggingface/transformers",
    "protectai/rebuff",
    "NVIDIA/NeMo-Guardrails",
    "mitre-atlas/atlas-data",  # MITRE ATLAS adversarial threat landscape for AI
]

# RSS feeds for security research blogs.
RSS_FEEDS = [
    ("Embrace The Red", "https://embracethered.com/blog/index.xml"),
    ("Simon Willison", "https://simonwillison.net/atom/everything/"),
    ("HiddenLayer", "https://hiddenlayer.com/innovation-hub/feed/"),
    ("Protect AI", "https://protectai.com/blog/rss.xml"),
    ("NCC Group Research", "https://research.nccgroup.com/feed/"),
    ("Trail of Bits", "https://blog.trailofbits.com/feed/"),
    ("Google Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("PortSwigger Research", "https://portswigger.net/research/rss"),
    ("Hugging Face Blog", "https://huggingface.co/blog/feed.xml"),
    ("Adversa AI", "https://adversa.ai/feed/"),
]

# NVD CPE vendor/product substrings to flag as AI/ML relevant.
# Applied to the CVE's configurations.
NVD_RELEVANT_TERMS = [
    "langchain", "llama", "autogen", "semantic_kernel", "ollama",
    "vllm", "transformers", "huggingface", "openai", "anthropic",
    "crewai", "pytorch", "tensorflow", "gradio", "streamlit",
    "mlflow", "ray", "triton", "nemo", "rebuff", "pinecone",
    "chromadb", "weaviate", "qdrant", "pgvector",
]

# How many days back to look on first run / for NVD queries.
LOOKBACK_DAYS = 2
