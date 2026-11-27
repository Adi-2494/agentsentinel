"""AgentSentinel v2 — single-owner GitHub App delivery layer (wraps the v1 engine).

See docs/v2/ARCHITECTURE.md. V1 = webhook receiver -> run the unchanged Merge Gate -> log.
LLM backend is the owner's subscription or free local Ollama (core.config); never a paid API.
"""
