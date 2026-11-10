"""Anomaly detection for AI identities: volume spikes, scope changes, expired-token reuse.

Rules (evaluated per identity, in event-time order):
  R1 LLM_API_VOLUME_SPIKE  - more than 20 LLM API calls in any 60-second sliding window
  R2 SCOPE_CHANGE          - granted scope differs between two consecutive requests of the same identity
  R3 EXPIRED_TOKEN_REUSE   - a request presents a token whose `exp` is already in the past

Input: JSON Lines events, one per request:
  {"ts": "2026-11-09T20:30:00.000Z", "identity": "agent|novaassist-01", "event": "llm_api_call",
   "scope": "read:ai-data", "token_fp": "a1b2...", "token_exp": "2026-11-09T20:35:00Z", "source": "..."}

Default mode replays the Project 3 attacks (F1-F5) as an event stream so every
rule can be shown firing with timestamp, identity and event type. Use
--events FILE to scan a real log instead. Alerts are also written as JSON Lines
to 04-blue-team/evidence/alerts-<run>.jsonl when --save is given.

Run: .venv/bin/python 04-blue-team/anomaly_detector.py [--fast] [--save] [--events FILE]
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bluelog import EVIDENCE_DIR, ChatLog, base_parser, run

VOLUME_LIMIT = 20
VOLUME_WINDOW = timedelta(seconds=60)


@dataclass
class Alert:
    ts: str
    identity: str
    event_type: str
    rule: str
    severity: str
    detail: str
    attack: str


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AnomalyDetector:
    def __init__(self) -> None:
        self.windows: dict[str, deque[datetime]] = defaultdict(deque)
        self.spiking: set[str] = set()
        self.last_scope: dict[str, frozenset[str]] = {}

    def process(self, event: dict) -> list[Alert]:
        ts, identity = parse_ts(event["ts"]), event["identity"]
        attack = event.get("attack", "-")
        alerts = []

        if event["event"] == "llm_api_call":
            window = self.windows[identity]
            window.append(ts)
            while window and ts - window[0] > VOLUME_WINDOW:
                window.popleft()
            if len(window) > VOLUME_LIMIT and identity not in self.spiking:
                self.spiking.add(identity)
                alerts.append(Alert(event["ts"], identity, event["event"], "LLM_API_VOLUME_SPIKE", "HIGH",
                                    f"{len(window)} LLM API calls in {(ts - window[0]).total_seconds():.1f}s "
                                    f"(limit {VOLUME_LIMIT}/60s)", attack))
            elif len(window) <= VOLUME_LIMIT:
                self.spiking.discard(identity)

        scope = frozenset(event.get("scope", "").split())
        previous = self.last_scope.get(identity)
        if previous is not None and scope != previous:
            added, removed = sorted(scope - previous), sorted(previous - scope)
            escalation = any("admin" in s or s.startswith("write:") for s in added)
            alerts.append(Alert(event["ts"], identity, event["event"], "SCOPE_CHANGE",
                                "CRITICAL" if escalation else "MEDIUM",
                                f"scope '{' '.join(sorted(previous))}' -> '{' '.join(sorted(scope))}'"
                                f" (added={added or '-'} removed={removed or '-'})", attack))
        self.last_scope[identity] = scope

        if event.get("token_exp") and ts > parse_ts(event["token_exp"]):
            late = (ts - parse_ts(event["token_exp"])).total_seconds()
            alerts.append(Alert(event["ts"], identity, event["event"], "EXPIRED_TOKEN_REUSE", "HIGH",
                                f"token fp={event.get('token_fp', '?')} used {late:.0f}s after exp "
                                f"{event['token_exp']}", attack))
        return alerts


def fp(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:12]


def project3_replay(start: datetime) -> list[dict]:
    """Event stream produced by replaying the Project 3 attacks against the hardened stack."""
    events: list[dict] = []

    def add(offset: float, identity: str, event: str, scope: str, token: str, ttl_from: float,
            source: str, attack: str) -> None:
        events.append({"ts": iso(start + timedelta(seconds=offset)), "identity": identity, "event": event,
                       "scope": scope, "token_fp": fp(token), "token_exp": iso(start + timedelta(seconds=ttl_from + 300)),
                       "source": source, "attack": attack})

    # Baseline: normal customer traffic (should raise nothing).
    for i in range(6):
        add(i * 9, "auth0|alice", "llm_api_call", "openid read:ai-data", "alice-at-1", 0, "chat", "baseline")

    # F3/F1: automated extraction / injection probing - 25 payload variants fired in ~37 s.
    for i in range(25):
        add(60 + i * 1.5, "auth0|eve", "llm_api_call", "openid read:ai-data", "eve-at-1", 60,
            f"sim3/sim1 payload variant {i + 1}", "F3/F1 prompt extraction + injection probing")

    # F2: Agent A relays the forged orchestrator envelope; research-agent suddenly requests write:admin.
    add(110, "agent|research-agent", "agent_request", "read:ai-data", "ra-m2m-1", 100, "read ticket #8841", "baseline")
    add(112, "agent|research-agent", "agent_request", "read:ai-data write:admin", "ra-m2m-1", 100,
        "grant_role via forged ORCHESTRATOR ENVELOPE", "F2 agent identity spoofing")

    # F4: eve's session asks for admin after the leaked console passphrase.
    add(130, "auth0|eve", "api_request", "openid read:ai-data write:admin", "eve-at-1", 60,
        "[support-console] NOVA-ADMIN-2291 list_all_customers", "F4 role escalation user->admin")

    # F5: poisoned RAG chunk makes the agent call crm.export_customers with admin scope.
    add(150, "agent|novaassist-01", "agent_request", "read:ai-data", "nova-m2m-1", 140, "rag retrieve", "baseline")
    add(151, "agent|novaassist-01", "mcp_tool_call", "read:ai-data write:admin", "nova-m2m-1", 140,
        "tools/call crm.export_customers (kb-105)", "F5 RAG poisoning + MCP abuse")

    # F1: the credential exfiltrated in Project 3 is replayed by the attacker after it expired (TTL 300 s).
    add(700, "agent|novaassist-01", "api_request", "read:ai-data write:admin", "nova-m2m-1", 140,
        "attacker replays exfiltrated AGENT_SERVICE_TOKEN from 198.51.100.23", "F1 stolen credential replay")
    return sorted(events, key=lambda e: e["ts"])


def main() -> None:
    parser = base_parser(__doc__.splitlines()[0])
    parser.add_argument("--events", type=Path, help="scan a JSON Lines event file instead of the Project 3 replay")
    args = parser.parse_args()
    log = ChatLog("anomaly-detector", args)
    log.banner("PROJECT 4 - Anomaly detection: LLM call spike | scope change | expired token reuse")
    log.say("DETECTOR", f"R1 LLM_API_VOLUME_SPIKE  > {VOLUME_LIMIT} llm_api_call per identity in 60 s")
    log.say("DETECTOR", "R2 SCOPE_CHANGE          scope differs between consecutive requests of one identity")
    log.say("DETECTOR", "R3 EXPIRED_TOKEN_REUSE   request presents a token after its exp")

    if args.events:
        events = [json.loads(line) for line in args.events.read_text().splitlines() if line.strip()]
        log.say("SYSTEM", f"Loaded {len(events)} events from {args.events}")
    else:
        events = project3_replay(datetime.now(timezone.utc).replace(microsecond=0))
        log.say("SYSTEM", f"Replaying Project 3 attacks as {len(events)} timestamped events")

    detector, alerts = AnomalyDetector(), []
    for event in events:
        if event.get("attack", "baseline") != "baseline" or args.events:
            log.say("EVENT", f"{event['ts']} {event['identity']:<22} {event['event']:<14} "
                             f"scope='{event.get('scope', '')}' src={event.get('source', '')}")
        for alert in detector.process(event):
            alerts.append(alert)
            log.say("ALERT", f"[{alert.severity}] {alert.rule} ts={alert.ts} identity={alert.identity} "
                             f"event_type={alert.event_type}")
            log.say("ALERT", f"   {alert.detail} | attack={alert.attack}")

    log.section("Alerts")
    log.table(["Timestamp (UTC)", "Identity", "Event type", "Rule", "Severity", "Project 3 attack"],
              [[a.ts, a.identity, a.event_type, a.rule, a.severity, a.attack] for a in alerts])
    fired = {a.rule for a in alerts}
    rules = ["LLM_API_VOLUME_SPIKE", "SCOPE_CHANGE", "EXPIRED_TOKEN_REUSE"]
    log.section("Rule coverage")
    log.table(["Rule", "Fired"], [[r, "YES" if r in fired else "NO"] for r in rules])
    if not args.events:
        attacks = sorted({e["attack"] for e in events if e["attack"] != "baseline"})
        log.table(["Project 3 attack replayed", "Alerted"],
                  [[a, "YES" if any(x.attack == a for x in alerts) else "NO"] for a in attacks])
        baseline_alerts = [a for a in alerts if a.attack == "baseline"]
        log.say("VERDICT", f"{len(alerts)} alerts | rules fired {len(fired)}/3 | baseline false alerts: "
                           f"{len(baseline_alerts)}")
    if args.save:
        EVIDENCE_DIR.mkdir(exist_ok=True)
        path = EVIDENCE_DIR / f"alerts-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.jsonl"
        path.write_text("".join(json.dumps(asdict(a)) + "\n" for a in alerts))
        log.say("SYSTEM", f"Alerts written to {path}")
    log.close()
    sys.exit(0 if args.events or fired == set(rules) else 1)


if __name__ == "__main__":
    run(main)
