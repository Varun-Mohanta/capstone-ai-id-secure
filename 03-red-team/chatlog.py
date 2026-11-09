"""Shared chat-log renderer for the Project 3 red-team simulations.

Everything is offline: no network calls, no real models and no real secrets.
Each line is streamed with a UTC timestamp so the output reads like a live
chat/agent log, and can optionally be saved as plain-text evidence.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

RESET = "\033[0m"
DEFAULT_COLOR = "\033[97m"
# Matched by prefix against the upper-cased speaker label.
SPEAKER_COLORS = {
    "SYSTEM": "\033[90m",
    "USER": "\033[36m",
    "ATTACKER": "\033[91m",
    "ASSISTANT": "\033[32m",
    "AGENT-A": "\033[34m",
    "AGENT-B": "\033[35m",
    "ORCHESTRATOR": "\033[94m",
    "TOOL": "\033[33m",
    "MCP": "\033[33m",
    "INGEST": "\033[90m",
    "RETRIEVER": "\033[96m",
    "CLIENT": "\033[90m",
    "AUDIT": "\033[93m",
    "DETECTOR": "\033[95m",
    "VERDICT": "\033[1;97m",
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def fake_jwt(claims: dict) -> str:
    """Build a JWT-shaped string with an obviously invalid signature."""
    header = {"alg": "RS256", "typ": "JWT", "kid": "FAKE-KEY-DO-NOT-USE"}
    segments = [b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)]
    segments.append(b64url(b"FAKE-SIGNATURE-NOT-VALID"))
    return ".".join(segments)


def parse_args(description: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--delay", type=float, default=0.25, help="seconds between streamed lines (default: 0.25)")
    parser.add_argument("--fast", action="store_true", help="print instantly (no streaming delay)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("--save", action="store_true", help="also save a plain-text transcript to 03-red-team/evidence/")
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


class ChatLog:
    def __init__(self, name: str, args: argparse.Namespace) -> None:
        self.delay = 0.0 if args.fast else max(args.delay, 0.0)
        self.color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        self.file = None
        self.path: Path | None = None
        if args.save:
            EVIDENCE_DIR.mkdir(exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            self.path = EVIDENCE_DIR / f"{name}-{stamp}.log"
            self.file = self.path.open("w", encoding="utf-8")

    def _emit(self, plain: str, code: str) -> None:
        print(f"{code}{plain}{RESET}" if self.color else plain, flush=True)
        if self.file:
            self.file.write(plain + "\n")
            self.file.flush()
        if self.delay:
            time.sleep(self.delay)

    def say(self, speaker: str, text: object = "") -> None:
        """Stream a (possibly multi-line) message, one timestamped line at a time."""
        code = next((c for k, c in SPEAKER_COLORS.items() if speaker.upper().startswith(k)), DEFAULT_COLOR)
        if self.delay:
            time.sleep(self.delay)  # short "typing" pause between messages
        for line in str(text).splitlines() or [""]:
            self._emit(f"[{utc_now()}] {speaker:<18} | {line}", code)

    def json(self, speaker: str, payload: object) -> None:
        self.say(speaker, json.dumps(payload, indent=2))

    def banner(self, title: str) -> None:
        bar = "=" * 92
        for line in (bar, f"  {title}", bar):
            self._emit(line, "\033[1;97m")

    def section(self, title: str) -> None:
        self._emit("", "")
        self._emit(f"--- {title} " + "-" * max(0, 87 - len(title)), "\033[1;93m")

    def table(self, headers: list[str], rows: list[list[str]]) -> None:
        widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)]
        fmt = " | ".join(f"{{:<{w}}}" for w in widths)
        self._emit(fmt.format(*headers), "\033[1;97m")
        self._emit("-+-".join("-" * w for w in widths), "\033[90m")
        for row in rows:
            self._emit(fmt.format(*row), DEFAULT_COLOR)

    def close(self) -> None:
        if self.file:
            self.file.close()
            print(f"\nTranscript saved to {self.path}")


def run(main) -> None:
    try:
        main()
    except KeyboardInterrupt:
        print("\nSimulation interrupted.")
    except BrokenPipeError:
        # Output was piped into something like `head` that closed early.
        sys.stdout = open(os.devnull, "w")
