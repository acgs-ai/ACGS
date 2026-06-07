"""delve — a self-deepening research engine.

Takes a question, fans out parallel research, builds a persistent
citation-backed knowledge graph, adversarially verifies claims, and
loops-until-dry via a completeness critic.

The orchestration core is backend-agnostic: LLM and search providers are
injected via a factory (see ``delve.backends``), so the whole engine runs
offline with deterministic fakes and swaps to real providers behind extras.
"""

__version__ = "0.1.0"
