"""Pure-Python detection rules used by the NeMo Guardrails actions.

Input rules flag untrusted text (user prompts, attached documents, RAG chunks,
relayed agent messages) that carries prompt-injection, prompt-extraction,
identity-spoofing or tool-abuse patterns. Output rules redact JWT-shaped
credentials and detect system-prompt leakage in model responses.

Kept free of NeMo imports so the same logic can be unit-tested and reused by
the RAG ingestion filter and the before/after comparison.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

# header.payload.signature where header and payload are base64url JSON ("eyJ" == '{"').
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
REDACTION = "[REDACTED]"
BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass(frozen=True)
class Finding:
    rule: str
    reason: str
    evidence: str

    def as_dict(self) -> dict:
        return {"rule": self.rule, "reason": self.reason, "evidence": self.evidence}


I = re.IGNORECASE
INPUT_RULES: list[tuple[str, str, re.Pattern]] = [
    ("LLM01-hidden-comment", "instruction hidden in an HTML comment",
     re.compile(r"<!--(?=[^>]*?\b(?:assistant|ai|instruction|ignore|token|credential|call|tool|append|mention)\b)[\s\S]*?-->", I)),
    ("LLM01-markdown-exfil", "markdown image/link URL with a templated variable (exfiltration beacon)",
     re.compile(r"!?\[[^\]]*\]\([^)]*\{[A-Za-z_][A-Za-z0-9_]*\}[^)]*\)")),
    ("LLM01-secret-reference", "references an internal credential variable",
     re.compile(r"\b[A-Z][A-Z0-9_]*_(?:TOKEN|SECRET|API_KEY|PASSWORD|PRIVATE_KEY)\b")),
    ("LLM01-instruction-override", "attempts to override prior instructions",
     re.compile(r"\b(?:ignore|disregard|forget|override)\b.{0,30}\b(?:previous|prior|above|earlier|all)\b.{0,20}"
                r"\b(?:instructions?|rules|prompts?|directives|guidelines)\b|\b(?:unrestricted|developer|jailbreak|god)\s+mode\b", I)),
    ("LLM07-prompt-extraction", "asks the model to disclose its system prompt or configuration",
     re.compile(r"\b(?:repeat|print|reveal|show|output|display|dump|translate|describe|recite)\b.{0,60}"
                r"(?:system\s+prompt|\b(?:initial|original|hidden|full|internal|your)\s+(?:instructions|prompt|configuration|rules)\b"
                r"|text above|everything above)|starting with the words", I)),
    ("LLM07-role-play-override", "role-play persona designed to drop safety rules",
     re.compile(r"\b(?:no rules|without (?:any )?(?:rules|restrictions|filters)|stay in character)\b", I)),
    ("LLM01-fake-delimiter", "forged conversation delimiter / fake system turn (suffix injection)",
     re.compile(r"^\s*#{2,}\s*(?:system|end of (?:user )?message|assistant)\b|<\|im_(?:start|end)\|>"
                r"|\[/?(?:SYSTEM|INST)\]|\bdiagnostic mode\b", I | re.M)),
    ("LLM09-spoofed-authority", "in-band orchestrator/system authority claim (identity spoofing)",
     re.compile(r"BEGIN ORCHESTRATOR ENVELOPE|trust_level\s*:\s*system|signature\s*:\s*verified|\bbreak-glass\b"
                r"|\bskip confirmation\b", I)),
    ("LLM06-tool-call-injection", "embedded instruction to invoke a tool or export data",
     re.compile(r"\b(?:call|invoke|execute|run)\b.{0,20}\b(?:mcp\s+)?tool\b|tools/call|\b[a-z]+\.export_[a-z_]+\b"
                r"|\"destination\"\s*:\s*\"https?://", I)),
    ("LLM01-concealment", "tells the model to hide its actions from the user",
     re.compile(r"\b(?:do not|don'?t|never)\s+(?:mention|tell|reveal|disclose)\b.{0,30}\b(?:user|anyone|this)\b", I)),
    ("LLM06-privilege-claim", "in-band privilege escalation claim (console marker / 'trust me' admin)",
     re.compile(r"\[(?:support|admin|staff)[-_ ]console\]|\btrust me\b.{0,40}\b(?:admin|root)\b"
                r"|\b(?:admin|root)\b.{0,40}\btrust me\b", I)),
]


def _snippet(text: str, limit: int = 70) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def _decoded_blobs(text: str) -> list[tuple[str, str]]:
    blobs = []
    for blob in BASE64_BLOB.findall(text):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > 0.95:
            blobs.append((blob, decoded))
    return blobs


def scan_input(text: str, _depth: int = 0) -> list[Finding]:
    """Return every input rule that matches; base64 blobs are decoded and re-scanned once."""
    findings = [Finding(rule, reason, _snippet(match.group(0)))
                for rule, reason, pattern in INPUT_RULES if (match := pattern.search(text))]
    if _depth == 0:
        for blob, decoded in _decoded_blobs(text):
            inner = scan_input(decoded, _depth=1)
            if inner:
                findings.append(Finding("LLM01-encoded-instruction",
                                        f"base64 payload decodes to an injected instruction ({inner[0].rule})",
                                        _snippet(f"{blob[:16]}... -> {decoded}")))
    return findings


def redact_credentials(text: str) -> tuple[str, int]:
    """Replace JWT-shaped strings with [REDACTED]; returns (text, number_of_redactions)."""
    return JWT_PATTERN.subn(REDACTION, text)


# Set by the guarded application to fragments of its own system prompt (canary tokens, secrets, rule text).
PROTECTED_FRAGMENTS: list[str] = []
LEAK_THRESHOLD = 1


def system_prompt_leak(text: str, fragments: list[str] | None = None) -> list[str]:
    return [f for f in (PROTECTED_FRAGMENTS if fragments is None else fragments) if f in text]
