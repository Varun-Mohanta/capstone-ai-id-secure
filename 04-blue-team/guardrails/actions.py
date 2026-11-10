"""Custom NeMo Guardrails actions (auto-loaded from the config directory)."""

import sys
from pathlib import Path

from nemoguardrails.actions import action
from nemoguardrails.actions.actions import ActionResult

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import detectors  # noqa: E402


@action(name="check_input_guardrail")
async def check_input_guardrail(text: str = ""):
    findings = detectors.scan_input(text or "")
    reason = "; ".join(f"{f.rule}: {f.reason}" for f in findings)
    return ActionResult(return_value=bool(findings), context_updates={
        "input_findings": [f.as_dict() for f in findings], "block_reason": reason})


@action(name="redact_credentials_output")
async def redact_credentials_output(text: str = ""):
    redacted, count = detectors.redact_credentials(text or "")
    return ActionResult(return_value=redacted, context_updates={"redaction_count": count})


@action(name="check_prompt_leak")
async def check_prompt_leak(text: str = ""):
    leaked = detectors.system_prompt_leak(text or "")
    blocked = len(leaked) >= detectors.LEAK_THRESHOLD
    return ActionResult(return_value=blocked, context_updates={
        "leak_fragments": leaked, "leak_reason": f"system prompt canaries in output: {leaked}" if blocked else ""})
