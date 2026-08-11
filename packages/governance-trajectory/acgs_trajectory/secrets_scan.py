"""Secret-boundary detection with graded policy tiers (Phase 1 gate V5; H4).

Detection runs at the ingestion edge, BEFORE anything is written to the shared
raw archive (ADR 0002 D7). On a quarantine-worthy hit the record is quarantined
— the authoritative raw is NEVER modified or redacted (that would break
provenance). Findings never carry the secret value itself, only a type,
location, and tier.

Tiers (H4 — refine fail-closed without over-quarantining structural non-secrets):

    confirmed_secret        high-precision named pattern (AWS/GitHub/PEM/JWT/...)
    secret_pattern_match    shape match, lower precision (assigned/bearer/entropy)
    example_placeholder     an EXACT known public example credential (allowlist)

Quarantine-worthy: {confirmed_secret, secret_pattern_match}. `example_placeholder`
is surfaced as a note (allowed) so audits distinguish public examples from real
leaks — the direction stays fail-closed.

SECURITY MODEL: transcript content is UNTRUSTED / subject-controlled. Therefore
NO content-controlled downgrade is honored — there is no `pragma`/annotation
exemption at the ingestion edge (that concept belongs to first-party source
scanning only). `example_placeholder` uses an exact allowlist of public example
values, which cannot be used to hide a real secret (a real secret is, by
definition, not equal to a published example). Structural non-secret tokens
(UUIDs, git SHAs, bounded provider ids) are whitelisted only after confirming the
token does not embed a named credential.

Self-contained (no external dependency).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# ---- tiers ------------------------------------------------------------------

CONFIRMED_SECRET = "confirmed_secret"
SECRET_PATTERN_MATCH = "secret_pattern_match"
EXAMPLE_PLACEHOLDER = "example_placeholder"

QUARANTINE_TIERS = frozenset({CONFIRMED_SECRET, SECRET_PATTERN_MATCH})

_HIGH_PRECISION_KINDS = frozenset(
    {"aws_access_key_id", "github_pat", "github_fine_grained_pat", "openai_key",
     "slack_token", "google_api_key", "private_key_block", "jwt"}
)

# EXACT known-public example credentials. Exact-match only (never substring):
# a real secret cannot be hidden by equalling a published example.
_KNOWN_EXAMPLES = frozenset({
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
})

# ---- patterns ---------------------------------------------------------------

_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# Provider id tokens (Anthropic/OpenAI). BOUNDED body length so a long secret
# cannot be smuggled behind a known prefix; the body is additionally re-checked
# for embedded named credentials before the token is trusted.
_ID_PREFIX = re.compile(r"^(?:toolu|msg|req|call|chatcmpl|run|thread|asst|fc)_([A-Za-z0-9]{1,32})$")

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("bearer_token", re.compile(r"(?i)\b(?:authorization|bearer)\b[\"'\s:=]+[A-Za-z0-9._\-]{20,}")),
    (
        "assigned_secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|client[_-]?secret)\b"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9/\+_\-\.]{16,})[\"']?"
        ),
    ),
]

_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9/\+_\-]{32,}")


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    tier: str
    start: int
    end: int
    context: str  # short redacted locator, e.g. "line 12"

    @property
    def quarantine_worthy(self) -> bool:
        return self.tier in QUARANTINE_TIERS

    def as_reason(self) -> str:
        return f"secret:{self.tier}:{self.kind}@{self.context}"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _body_embeds_named_secret(body: str) -> bool:
    """True if a prefix-stripped id body itself contains a named credential."""
    return any(pat.search(body) for _kind, pat in _PATTERNS)


def _is_structural_non_secret(token: str) -> bool:
    """Whitelist genuinely non-secret structural tokens (fail-closed on doubt)."""
    if _UUID.fullmatch(token):
        return True
    if _GIT_SHA.fullmatch(token):  # 40-hex git object id
        return True
    m = _ID_PREFIX.fullmatch(token)
    if m:
        # a provider id ONLY if the bounded body embeds no named credential
        return not _body_embeds_named_secret(m.group(1))
    return False


def _classify(kind: str, value: str) -> str:
    """Assign a tier from content only. NO content-controlled downgrade."""
    if value in _KNOWN_EXAMPLES:
        return EXAMPLE_PLACEHOLDER
    if kind in _HIGH_PRECISION_KINDS:
        return CONFIRMED_SECRET
    return SECRET_PATTERN_MATCH


def scan_text(text: str, *, entropy_threshold: float = 4.3) -> list[SecretFinding]:
    """Return tiered secret findings for ``text``. Values are never included."""
    findings: list[SecretFinding] = []
    covered: list[tuple[int, int]] = []

    for kind, pat in _PATTERNS:
        for m in pat.finditer(text):
            sample = m.group(0)
            if _is_structural_non_secret(sample.strip("\"'")):
                continue
            findings.append(SecretFinding(kind, _classify(kind, sample), m.start(), m.end(), _locate(text, m.start())))
            covered.append((m.start(), m.end()))

    for m in _ENTROPY_CANDIDATE.finditer(text):
        if any(a <= m.start() < b for a, b in covered):
            continue
        token = m.group(0)
        if _is_structural_non_secret(token):
            continue
        if _shannon_entropy(token) >= entropy_threshold:
            findings.append(
                SecretFinding("high_entropy_string", _classify("high_entropy_string", token),
                              m.start(), m.end(), _locate(text, m.start()))
            )

    return findings


def quarantine_findings(findings: list[SecretFinding]) -> list[SecretFinding]:
    return [f for f in findings if f.quarantine_worthy]


def allowed_findings(findings: list[SecretFinding]) -> list[SecretFinding]:
    return [f for f in findings if not f.quarantine_worthy]


def _locate(text: str, offset: int) -> str:
    return f"line {text.count(chr(10), 0, offset) + 1}"


def has_secrets(text: str, **kw) -> bool:
    """True only if a QUARANTINE-worthy secret is present (public examples excluded)."""
    return bool(quarantine_findings(scan_text(text, **kw)))
