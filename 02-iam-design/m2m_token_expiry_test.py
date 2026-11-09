#!/usr/bin/env python3
"""
Credential Rotation evidence: short-lived Auth0 M2M token expiry test.

1. Obtains an M2M access token from Auth0 (client_credentials grant).
   The Auth0 API must be configured with "Token Expiration" = 60 seconds.
2. Calls the /chat endpoint with the fresh token  -> expect 200 OK.
3. Waits until the token has expired (>= 60 s after issue, past `exp`).
4. Replays the SAME token against /chat           -> expect 401 Unauthorized.

All output is timestamped (UTC, ms precision) and written to both the terminal
and an evidence log file under ./evidence/.

Configuration (environment variables, or a .env file next to this script):
    AUTH0_DOMAIN         e.g. securenova.eu.auth0.com
    AUTH0_CLIENT_ID      M2M application client ID
    AUTH0_CLIENT_SECRET  M2M application client secret
    AUTH0_AUDIENCE       API identifier, e.g. https://api.securenova.ai
    CHAT_API_URL         e.g. http://localhost:8000/chat
    CHAT_PROMPT          optional, message body sent to /chat
    EXPECTED_TTL         optional, expected token TTL in seconds (default 60)
    EXPIRY_GRACE         optional, seconds to wait past `exp` (default 5)

Usage:
    python m2m_token_expiry_test.py
Exit code 0 = PASS (200 then 401), 1 = FAIL, 2 = configuration/setup error.
"""

import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = SCRIPT_DIR / "evidence"


class EvidenceLogger:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._fh = path.open("w", encoding="utf-8")

    def log(self, msg: str = "", level: str = "INFO") -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        for line in (msg.splitlines() or [""]):
            out = f"[{ts}] [{level:<5}] {line}"
            print(out, flush=True)
            self._fh.write(out + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def get_config() -> dict:
    load_dotenv(SCRIPT_DIR / ".env")
    required = ["AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET",
                "AUTH0_AUDIENCE", "CHAT_API_URL"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        sys.exit(f"Missing required configuration: {', '.join(missing)} "
                 f"(set env vars or create {SCRIPT_DIR / '.env'})")
    domain = os.environ["AUTH0_DOMAIN"].removeprefix("https://").rstrip("/")
    return {
        "domain": domain,
        "client_id": os.environ["AUTH0_CLIENT_ID"],
        "client_secret": os.environ["AUTH0_CLIENT_SECRET"],
        "audience": os.environ["AUTH0_AUDIENCE"],
        "chat_url": os.environ["CHAT_API_URL"],
        "prompt": os.environ.get("CHAT_PROMPT", "Hello from the SecureNova M2M agent"),
        "expected_ttl": int(os.environ.get("EXPECTED_TTL", "60")),
        "grace": int(os.environ.get("EXPIRY_GRACE", "5")),
    }


def b64url_json(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    """Decode header/payload for display only. The API is responsible for verification."""
    header_b64, payload_b64, _ = token.split(".")
    return b64url_json(header_b64), b64url_json(payload_b64)


def fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def request_token(cfg: dict, log: EvidenceLogger) -> dict:
    url = f"https://{cfg['domain']}/oauth/token"
    log.log(f"POST {url} (grant_type=client_credentials, audience={cfg['audience']})")
    resp = requests.post(url, json={
        "grant_type": "client_credentials",
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "audience": cfg["audience"],
    }, timeout=15)
    log.log(f"Auth0 token endpoint responded: HTTP {resp.status_code}")
    if resp.status_code != 200:
        log.log(f"Token request failed: {resp.text}", "ERROR")
        raise SystemExit(2)
    return resp.json()


def call_chat(cfg: dict, token: str, log: EvidenceLogger, label: str) -> requests.Response:
    log.log(f"[{label}] POST {cfg['chat_url']}  Authorization: Bearer <sha256:{fingerprint(token)}>")
    resp = requests.post(cfg["chat_url"],
                         headers={"Authorization": f"Bearer {token}"},
                         json={"message": cfg["prompt"]},
                         timeout=15)
    log.log(f"[{label}] Response: HTTP {resp.status_code} {resp.reason}")
    www_auth = resp.headers.get("WWW-Authenticate")
    if www_auth:
        log.log(f"[{label}] WWW-Authenticate: {www_auth}")
    log.log(f"[{label}] Body: {resp.text[:500]}")
    return resp


def main() -> int:
    cfg = get_config()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log = EvidenceLogger(EVIDENCE_DIR / f"m2m-token-expiry-{run_id}.log")

    try:
        log.log("=" * 72)
        log.log("SecureNova - Credential Rotation: M2M token expiry & replay test")
        log.log(f"Run ID: {run_id}   Host: {os.uname().nodename}")
        log.log(f"Auth0 tenant: {cfg['domain']}   Client ID: {cfg['client_id']}")
        log.log(f"Chat endpoint: {cfg['chat_url']}")
        log.log("=" * 72)

        # Step 1 - obtain token
        log.log("STEP 1: Obtain short-lived M2M access token")
        token_resp = request_token(cfg, log)
        token = token_resp["access_token"]
        header, claims = decode_jwt_unverified(token)
        ttl = claims["exp"] - claims["iat"]
        log.log(f"token_type={token_resp.get('token_type')} expires_in={token_resp.get('expires_in')}s")
        log.log(f"Token fingerprint (sha256, first 16 hex): {fingerprint(token)}")
        log.log(f"Token preview: {token[:20]}...{token[-10:]}")
        log.log(f"JWT header: alg={header.get('alg')} typ={header.get('typ')} kid={header.get('kid')}")
        log.log(f"Claims: iss={claims.get('iss')} sub={claims.get('sub')} aud={claims.get('aud')}")
        log.log(f"Claims: scope={claims.get('scope')!r} gty={claims.get('gty')}")
        log.log(f"Claims: iat={claims['iat']} ({utc(claims['iat'])})")
        log.log(f"Claims: exp={claims['exp']} ({utc(claims['exp'])})  -> TTL = {ttl}s")
        if ttl != cfg["expected_ttl"]:
            log.log(f"Token TTL is {ttl}s, expected {cfg['expected_ttl']}s. Set 'Maximum Access "
                    f"Token Lifetime' on the Auth0 API to {cfg['expected_ttl']}.", "WARN")

        # Step 2 - call /chat with valid token
        log.log("-" * 72)
        log.log("STEP 2: Call /chat with the fresh token (expect 200 OK)")
        first = call_chat(cfg, token, log, "FRESH")
        fresh_ok = first.status_code == 200

        # Step 3 - wait for expiry: at least 60 s after issue AND past exp + grace
        log.log("-" * 72)
        wait_until = max(claims["iat"] + cfg["expected_ttl"], claims["exp"]) + cfg["grace"]
        wait_s = max(0, wait_until - time.time())
        log.log(f"STEP 3: Waiting {wait_s:.1f}s until {utc(int(wait_until))} "
                f"(exp + {cfg['grace']}s grace for clock skew)")
        while (remaining := wait_until - time.time()) > 0:
            if int(remaining) % 10 == 0 or remaining < 5:
                log.log(f"  ...{remaining:.0f}s remaining")
            time.sleep(min(1, remaining))
        now = int(time.time())
        log.log(f"Token age: {now - claims['iat']}s; expired {now - claims['exp']}s ago")

        # Step 4 - replay expired token
        log.log("-" * 72)
        log.log("STEP 4: Replay the SAME (now expired) token against /chat (expect 401)")
        log.log(f"Replaying token fingerprint: {fingerprint(token)}")
        replay = call_chat(cfg, token, log, "REPLAY")
        replay_rejected = replay.status_code == 401

        # Summary
        log.log("=" * 72)
        log.log(f"Fresh token  -> HTTP {first.status_code} "
                f"[{'PASS' if fresh_ok else 'FAIL'}: expected 200]")
        log.log(f"Expired token-> HTTP {replay.status_code} "
                f"[{'PASS' if replay_rejected else 'FAIL'}: expected 401]")
        passed = fresh_ok and replay_rejected
        log.log(f"RESULT: {'PASS - expired M2M token was rejected on replay' if passed else 'FAIL'}",
                "INFO" if passed else "ERROR")
        log.log(f"Evidence written to {log.path}")
        log.log("=" * 72)
        return 0 if passed else 1
    except requests.RequestException as exc:
        log.log(f"Network error: {exc}", "ERROR")
        return 2
    finally:
        log.close()


if __name__ == "__main__":
    sys.exit(main())
