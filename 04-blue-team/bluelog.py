"""Shared terminal/evidence logger for the Project 4 blue-team programs.

Reuses the Project 3 ChatLog renderer (timestamped, colour-coded, streamed
lines) so red-team and blue-team transcripts look identical side by side, but
saves transcripts to 04-blue-team/evidence/ and adds blue-team speakers.
It also puts 03-red-team/ on sys.path so the original attack payloads can be
imported verbatim instead of being copied.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

BLUE_TEAM_DIR = Path(__file__).resolve().parent
RED_TEAM_DIR = BLUE_TEAM_DIR.parent / "03-red-team"
EVIDENCE_DIR = BLUE_TEAM_DIR / "evidence"
sys.path.insert(0, str(RED_TEAM_DIR))

import chatlog  # noqa: E402

chatlog.EVIDENCE_DIR = EVIDENCE_DIR
chatlog.SPEAKER_COLORS.update({
    "GUARDRAIL": "\033[1;95m",
    "NEMO": "\033[95m",
    "SIGNER": "\033[34m",
    "VERIFIER": "\033[96m",
    "AUTH0": "\033[94m",
    "ALERT": "\033[1;91m",
    "EVENT": "\033[90m",
    "GATEWAY": "\033[33m",
    "PASS": "\033[1;92m",
    "FAIL": "\033[1;91m",
    "ERROR": "\033[1;91m",
    "ACCEPT": "\033[1;92m",
})

from chatlog import JWT_PATTERN, ChatLog, fake_jwt, run, utc_now  # noqa: E402,F401


def base_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--delay", type=float, default=0.05, help="seconds between streamed lines (default: 0.05)")
    parser.add_argument("--fast", action="store_true", help="print instantly (no streaming delay)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("--save", action="store_true", help="also save a plain-text transcript to 04-blue-team/evidence/")
    return parser
