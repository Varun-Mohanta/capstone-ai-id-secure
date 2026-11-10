"""Signed agent bus - Ed25519 identity binding between orchestrator and ops-agent.

Every outgoing agent message is signed with the sender's Ed25519 private key
(04-blue-team/keys/, created by ed25519_keygen.py). ops-agent (Agent B)
verifies the signature against the sender's pinned public key BEFORE parsing
or acting on the message, then checks recipient, expiry, replay and finally
authorises the tool against the scopes registered for the *verified* sender.

Scenarios:
  1. legitimate signed orchestrator instruction        -> accepted, executed
  2. same kind of message with ONE character tampered  -> rejected (InvalidSignature)
  3. Project 3 forged ORCHESTRATOR ENVELOPE (unsigned) -> rejected (unsigned)
  4. forgery signed with research-agent's own key but
     claiming sender=orchestrator-01                   -> rejected (InvalidSignature)
  5. research-agent honestly signs a privileged request -> authenticated, denied (scope)
  6. replay of message 1                               -> rejected (replayed msg_id)

Run: .venv/bin/python 04-blue-team/signed_agent_bus.py [--fast] [--save]
"""

from __future__ import annotations

import copy
import json
import re
import sys

from bluelog import ChatLog, base_parser, run  # isort: skip  (adds 03-red-team to sys.path)
import agent_identity as ai
import sim2_agent_identity_spoofing as sim2

AGENT_B = "ops-agent"
REGISTERED_SCOPES = {"orchestrator-01": ["read:ai-data", "write:admin"], "research-agent": ["read:ai-data"]}
TOOL_SCOPES = {"grant_role": "write:admin", "reset_mfa": "write:admin", "refund_override": "write:admin"}


class OpsAgent:
    """Agent B with signature verification in front of every tool call."""

    def __init__(self, log: ChatLog) -> None:
        self.log = log
        self.verifier = ai.SignedMessageVerifier(AGENT_B, {i: ai.load_public_key(i) for i in REGISTERED_SCOPES})

    def handle(self, message: object) -> str:
        try:
            envelope = self.verifier.verify(message)
        except ai.VerificationError as exc:
            self.log.say("ERROR ops-agent", f"REJECTED before processing: {exc}")
            return "REJECTED"
        sender, body = envelope["sender"], envelope["body"]
        self.log.say("VERIFIER ops-agent", f"signature OK | sender={sender} (pinned key "
                     f"{ai.fingerprint(self.verifier.trusted_keys[sender])[:22]}...) msg_id={envelope['msg_id'][:8]}")
        tool, args = re.search(r"(\w+)\((.*?)\)", body).groups()
        required = TOOL_SCOPES.get(tool)
        if required and required not in REGISTERED_SCOPES[sender]:
            self.log.say("ERROR ops-agent", f"DENIED: verified sender {sender} lacks {required} for {tool}")
            return "DENIED"
        self.log.say("ACCEPT ops-agent", f"authorised ({required}) - executing {tool}({args})")
        self.log.say("AUDIT", f"actor={sender} (Ed25519-verified) action={tool} args={args} result=SUCCESS")
        return "EXECUTED"


def show(log: ChatLog, speaker: str, message: dict) -> None:
    log.json(speaker, message)


def one_char_tamper(message: dict, old: str, new: str) -> tuple[dict, int]:
    tampered = copy.deepcopy(message)
    body = tampered["envelope"]["body"]
    index = body.index(old)
    assert len(old) == len(new) and sum(a != b for a, b in zip(old, new)) == 1
    tampered["envelope"]["body"] = body[:index] + new + body[index + len(old):]
    position = index + next(i for i, (a, b) in enumerate(zip(old, new)) if a != b)
    return tampered, position


def main() -> None:
    args = base_parser(__doc__.splitlines()[0]).parse_args()
    log = ChatLog("signed-agent-bus", args)
    log.banner("PROJECT 4 - Ed25519 agent identity binding: sign every message, verify before processing")
    missing = [i for i in REGISTERED_SCOPES if not ai.private_key_path(i).exists()]
    if missing:
        log.say("ERROR", f"missing key pairs for {missing}; run: python 04-blue-team/ed25519_keygen.py")
        sys.exit(2)
    orchestrator_key = ai.load_private_key("orchestrator-01")
    research_key = ai.load_private_key("research-agent")
    agent_b = OpsAgent(log)
    log.say("SYSTEM", "ops-agent trust registry (pinned Ed25519 public keys):")
    for identity, scopes in REGISTERED_SCOPES.items():
        log.say("SYSTEM", f"  {identity:<16} {ai.fingerprint(ai.load_public_key(identity))} scopes={scopes}")
    results = []

    log.section("1. Legitimate orchestrator instruction (signed)")
    msg1 = ai.sign_message(orchestrator_key, "orchestrator-01", AGENT_B,
                           'refund_override(order="ORD-1001", amount=10.00)')
    log.say("SIGNER orchestrator", "signed with orchestrator-01 private key:")
    show(log, "SIGNER orchestrator", msg1)
    results.append(["1", "Legitimate signed instruction", "EXECUTED", agent_b.handle(msg1)])

    log.section("2. Man-in-the-middle changes ONE character of a signed message")
    msg2 = ai.sign_message(orchestrator_key, "orchestrator-01", AGENT_B,
                           'refund_override(order="ORD-1002", amount=10.00)')
    tampered, pos = one_char_tamper(msg2, "amount=10.00", "amount=90.00")
    log.say("SIGNER orchestrator", f"original body : {msg2['envelope']['body']}")
    log.say("ATTACKER", f"tampered body : {tampered['envelope']['body']}")
    log.say("ATTACKER", f"                {' ' * pos}^ 1 character changed at body[{pos}]: "
                        f"'{msg2['envelope']['body'][pos]}' -> '{tampered['envelope']['body'][pos]}' "
                        "(signature left unchanged)")
    show(log, "ATTACKER", tampered)
    results.append(["2", "Signed message, 1 char tampered", "REJECTED", agent_b.handle(tampered)])

    log.section("3. Replay of the Project 3 forged ORCHESTRATOR ENVELOPE (unsigned)")
    log.say("AGENT-A (research)", sim2.FORGED_MESSAGE)
    results.append(["3", "Project 3 forged envelope (unsigned)", "REJECTED", agent_b.handle(sim2.FORGED_MESSAGE)])

    log.section("4. Forgery signed with research-agent's key, claiming sender=orchestrator-01")
    forged = ai.sign_message(research_key, "orchestrator-01", AGENT_B, sim2.VICTIM_TARGET)
    log.say("ATTACKER", f"envelope.sender=orchestrator-01 body={sim2.VICTIM_TARGET} (signed by research-agent key)")
    results.append(["4", "Spoofed sender, attacker's own key", "REJECTED", agent_b.handle(forged)])

    log.section("5. research-agent signs a privileged request as itself")
    honest = ai.sign_message(research_key, "research-agent", AGENT_B, sim2.VICTIM_TARGET)
    results.append(["5", "Authentic low-privilege sender", "DENIED", agent_b.handle(honest)])

    log.section("6. Replay of message 1 (valid signature, same msg_id)")
    results.append(["6", "Replay of a valid signed message", "REJECTED", agent_b.handle(json.loads(json.dumps(msg1)))])

    log.section("Summary")
    rows = [r + ["PASS" if r[2] == r[3] else "FAIL"] for r in results]
    log.table(["#", "Scenario", "Expected", "Actual", "Check"], rows)
    passed = sum(r[4] == "PASS" for r in rows)
    log.say("VERDICT", f"{passed}/{len(rows)} scenarios behaved as expected | tampered message rejected: "
                       f"{rows[1][3] == 'REJECTED'} | Project 3 spoofing (F2) blocked: {rows[2][3] == 'REJECTED'}")
    log.close()
    sys.exit(0 if passed == len(rows) else 1)


if __name__ == "__main__":
    run(main)
