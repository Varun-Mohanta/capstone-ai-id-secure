"""Guardrail test 1 - run every Project 3 attack payload through NeMo Guardrails.

Each payload from 03-red-team (imported verbatim, not copied) is sent to the
NeMo Guardrails-protected NovaAssist. The terminal shows BLOCKED / PASSED for
each payload with the input-rail rule(s) that fired, then a per-attack summary.
Offline only: the protected model is the scripted, deliberately vulnerable
Project 3 model.

Run: .venv/bin/python 04-blue-team/guardrail_input_test.py [--fast] [--save]
"""

from __future__ import annotations

import sys

from bluelog import ChatLog, base_parser, run
from guarded_app import GuardedNovaAssist, project3_payloads


def preview(text: str, limit: int = 88) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


def main() -> None:
    args = base_parser(__doc__.splitlines()[0]).parse_args()
    log = ChatLog("guardrail-input-test", args)
    log.banner("PROJECT 4 - Input guardrail (NeMo Guardrails) vs all Project 3 attack payloads")
    app = GuardedNovaAssist()
    log.say("NEMO", f"LLMRails loaded from 04-blue-team/guardrails | main model: {app.llm.model_name}")
    log.say("NEMO", "input rails : securenova input guardrail (check_input_guardrail)")
    log.say("NEMO", "output rails: securenova redact credentials, securenova block prompt leak")

    rows, per_attack = [], {}
    for payload in project3_payloads():
        log.section(f"{payload['finding']} {payload['attack']} - {payload['id']} ({payload['technique']})")
        log.say("ATTACKER", preview(payload["text"]))
        result = app.chat(payload["text"])
        status = "BLOCKED" if result.blocked_by else "PASSED"
        if result.blocked_by:
            log.say("GUARDRAIL", f"[{status}] {payload['id']} by {result.blocked_by} rail")
            for finding in result.findings:
                log.say("GUARDRAIL", f"   reason: {finding['rule']} - {finding['reason']}")
                log.say("GUARDRAIL", f"   match : {finding['evidence']}")
        else:
            log.say("GUARDRAIL", f"[{status}] {payload['id']} - {result.reason}")
        log.say("ASSISTANT", result.final_response)
        rows.append([payload["finding"], payload["id"], payload["technique"], status,
                     result.findings[0]["rule"] if result.findings else "-"])
        stats = per_attack.setdefault(payload["finding"], [payload["attack"], 0, 0])
        stats[1] += 1
        stats[2] += status == "BLOCKED"

    log.section("Result per payload")
    log.table(["Finding", "Payload", "Technique", "Status", "First rule fired"], rows)
    log.section("Result per Project 3 attack")
    log.table(["Finding", "Attack", "Payloads", "Blocked", "Block rate"],
              [[f, a, str(n), str(b), f"{100 * b / n:.0f} %"] for f, (a, n, b) in per_attack.items()])
    blocked = sum(r[3] == "BLOCKED" for r in rows)
    log.say("VERDICT", f"{blocked}/{len(rows)} Project 3 payloads BLOCKED by the input guardrail "
                       f"({100 * blocked / len(rows):.1f} %)")
    log.close()
    sys.exit(0 if blocked >= 3 else 1)


if __name__ == "__main__":
    run(main)
