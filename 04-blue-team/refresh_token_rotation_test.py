#!/usr/bin/env python3
"""
Auth0 hardening evidence: access-token TTL = 300 s and refresh token rotation.

1. Authorization Code + PKCE login (Regular Web Application, scope includes
   offline_access) -> access token + refresh token RT1.
2. Decodes the access token and checks exp - iat == 300 s (API Token Expiration).
3. Exchanges RT1 for new tokens -> Auth0 returns a NEW refresh token RT2
   (proves rotation is enabled: RT2 != RT1).
4. Replays the OLD refresh token RT1 -> expects 403 invalid_grant.
5. Tries RT2 -> Auth0 reuse detection should have revoked the whole token
   family, so this is expected to fail too (reported as INFO).

Refresh tokens are never printed or logged: only a SHA-256 fingerprint.
Every line is UTC-timestamped and written to ./evidence/refresh-rotation-<run>.log.

Configuration (environment variables, 04-blue-team/.env, or 02-iam-design/.env):
    AUTH0_DOMAIN              e.g. securenova.eu.auth0.com
    AUTH0_AUDIENCE            API identifier, e.g. https://api.securenova.ai
    AUTH0_WEB_CLIENT_ID       Regular Web Application client ID
    AUTH0_WEB_CLIENT_SECRET   Regular Web Application client secret
    AUTH0_CALLBACK_URL        optional, default http://localhost:3000/callback (must be an Allowed Callback URL)
    AUTH0_SCOPE               optional, default "openid profile email offline_access read:ai-data"
    EXPECTED_ACCESS_TTL       optional, default 300
    REFRESH_REUSE_WAIT        optional, seconds to wait before replaying RT1 (> Auth0 reuse interval), default 2
    AUTH0_REFRESH_TOKEN       optional, start from an existing refresh token (skips the browser login)

Usage:
    python refresh_token_rotation_test.py            # paste the redirected URL after logging in
    python refresh_token_rotation_test.py --listen   # capture the callback on AUTH0_CALLBACK_URL automatically
Exit code 0 = PASS, 1 = FAIL, 2 = configuration/setup error.
"""

import argparse
import base64
import hashlib
import os
import secrets
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "02-iam-design"))
from m2m_token_expiry_test import EvidenceLogger, decode_jwt_unverified, fingerprint, load_dotenv, utc  # noqa: E402

load_dotenv(SCRIPT_DIR / ".env")
load_dotenv(SCRIPT_DIR.parent / "02-iam-design" / ".env")


def get_config() -> dict:
    required = ["AUTH0_DOMAIN", "AUTH0_AUDIENCE", "AUTH0_WEB_CLIENT_ID", "AUTH0_WEB_CLIENT_SECRET"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        print(f"Missing configuration: {', '.join(missing)} (see .env.example)", file=sys.stderr)
        raise SystemExit(2)
    return {
        "domain": os.environ["AUTH0_DOMAIN"].removeprefix("https://").rstrip("/"),
        "audience": os.environ["AUTH0_AUDIENCE"],
        "client_id": os.environ["AUTH0_WEB_CLIENT_ID"],
        "client_secret": os.environ["AUTH0_WEB_CLIENT_SECRET"],
        "callback": os.environ.get("AUTH0_CALLBACK_URL", "http://localhost:3000/callback"),
        "scope": os.environ.get("AUTH0_SCOPE", "openid profile email offline_access read:ai-data"),
        "expected_ttl": int(os.environ.get("EXPECTED_ACCESS_TTL", "300")),
        "reuse_wait": float(os.environ.get("REFRESH_REUSE_WAIT", "2")),
        "refresh_token": os.environ.get("AUTH0_REFRESH_TOKEN", ""),
    }


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def wait_for_callback(callback: str, timeout: int = 300) -> str:
    """Serve the callback URL once and return the full redirected URL (contains ?code=&state=)."""
    parsed = urllib.parse.urlparse(callback)
    captured: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if urllib.parse.urlparse(self.path).path != parsed.path:
                self.send_error(404)
                return
            captured["url"] = f"{callback}?{urllib.parse.urlparse(self.path).query}"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Login captured - return to the terminal.")

        def log_message(self, *args):
            pass

    server = HTTPServer((parsed.hostname or "localhost", parsed.port or 80), Handler)
    server.timeout = timeout
    server.handle_request()
    server.server_close()
    if "url" not in captured:
        raise SystemExit("Timed out waiting for the Auth0 callback")
    return captured["url"]


def browser_login(cfg: dict, log: EvidenceLogger, listen: bool) -> str:
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    params = {"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": cfg["callback"],
              "scope": cfg["scope"], "audience": cfg["audience"], "state": state,
              "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "login"}
    url = f"https://{cfg['domain']}/authorize?{urllib.parse.urlencode(params)}"
    log.log("Step 1 - Authorization Code + PKCE login (S256). Open this URL in a browser and sign in:")
    print(f"\n{url}\n", flush=True)
    if listen:
        log.log(f"Waiting for the redirect on {cfg['callback']} ...")
        redirected = wait_for_callback(cfg["callback"])
    else:
        redirected = input("After login, paste the FULL URL from the browser address bar "
                           "(it starts with your callback URL, the page itself may fail to load):\n> ").strip()
    query = urllib.parse.parse_qs(urllib.parse.urlparse(redirected).query)
    if query.get("error"):
        log.log(f"Login failed: {query['error'][0]} - {query.get('error_description', [''])[0]}", "ERROR")
        raise SystemExit(2)
    if query.get("state", [""])[0] != state:
        log.log("State mismatch - possible CSRF, aborting", "ERROR")
        raise SystemExit(2)
    code = query.get("code", [""])[0]
    if not code:
        log.log("No authorization code in the pasted URL", "ERROR")
        raise SystemExit(2)
    log.log(f"Authorization code received (state verified), fingerprint {fingerprint(code)}")
    tokens = token_request(cfg, log, "authorization_code", {
        "code": code, "code_verifier": verifier, "redirect_uri": cfg["callback"]})
    if tokens.status_code != 200:
        log.log(f"Code exchange failed: HTTP {tokens.status_code} {tokens.text}", "ERROR")
        raise SystemExit(2)
    body = tokens.json()
    check_access_token(cfg, log, body["access_token"])
    if "refresh_token" not in body:
        log.log("No refresh token returned. Enable 'Allow Offline Access' on the API and request offline_access.",
                "ERROR")
        raise SystemExit(2)
    return body["refresh_token"]


def token_request(cfg: dict, log: EvidenceLogger, grant: str, extra: dict) -> requests.Response:
    log.log(f"POST https://{cfg['domain']}/oauth/token (grant_type={grant})")
    resp = requests.post(f"https://{cfg['domain']}/oauth/token", data={
        "grant_type": grant, "client_id": cfg["client_id"], "client_secret": cfg["client_secret"], **extra},
        timeout=15)
    log.log(f"Auth0 responded: HTTP {resp.status_code}")
    return resp


TTL_OK = {"value": None}


def check_access_token(cfg: dict, log: EvidenceLogger, token: str) -> None:
    header, claims = decode_jwt_unverified(token)
    ttl = claims["exp"] - claims["iat"]
    log.log(f"Access token: alg={header.get('alg')} iss={claims.get('iss')} aud={claims.get('aud')}")
    log.log(f"Access token: scope='{claims.get('scope')}' iat={utc(claims['iat'])} exp={utc(claims['exp'])}")
    ok = ttl == cfg["expected_ttl"]
    TTL_OK["value"] = ok if TTL_OK["value"] is None else TTL_OK["value"] and ok
    log.log(f"Access token TTL = exp - iat = {ttl} s (expected {cfg['expected_ttl']} s) -> {'PASS' if ok else 'FAIL'}",
            "PASS" if ok else "FAIL")


def refresh(cfg: dict, log: EvidenceLogger, refresh_token: str, label: str) -> requests.Response:
    log.log(f"[{label}] using refresh token fp={fingerprint(refresh_token)}")
    return token_request(cfg, log, "refresh_token", {"refresh_token": refresh_token})


def main() -> int:
    parser = argparse.ArgumentParser(description="Auth0 TTL + refresh token rotation evidence")
    parser.add_argument("--listen", action="store_true", help="capture the callback with a local HTTP server")
    args = parser.parse_args()
    cfg = get_config()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log = EvidenceLogger(SCRIPT_DIR / "evidence" / f"refresh-rotation-{run_id}.log")
    log.log("=== Auth0 hardening: access token TTL + refresh token rotation ===")
    log.log(f"Tenant={cfg['domain']} client={cfg['client_id']} audience={cfg['audience']}")

    rt1 = cfg["refresh_token"] or browser_login(cfg, log, args.listen)
    log.log(f"RT1 obtained, fingerprint {fingerprint(rt1)}")

    log.log("Step 2 - Rotate: exchange RT1 for new tokens")
    first = refresh(cfg, log, rt1, "RT1 first use")
    if first.status_code != 200:
        log.log(f"Refresh failed: {first.text}", "ERROR")
        return 2
    body = first.json()
    check_access_token(cfg, log, body["access_token"])
    rt2 = body.get("refresh_token")
    rotated = bool(rt2) and rt2 != rt1
    log.log(f"New refresh token RT2 fp={fingerprint(rt2) if rt2 else 'NONE'} -> rotation "
            f"{'ENABLED (RT2 != RT1)' if rotated else 'NOT ENABLED'}", "PASS" if rotated else "FAIL")
    if not rotated:
        log.log("Enable Applications > (web app) > Settings > Refresh Token Rotation > Rotation.", "ERROR")
        log.close()
        return 1

    log.log(f"Step 3 - Waiting {cfg['reuse_wait']:.0f} s (longer than the rotation reuse interval) ...")
    time.sleep(cfg["reuse_wait"])
    log.log("Step 4 - REPLAY the OLD refresh token RT1 (already rotated)")
    replay = refresh(cfg, log, rt1, "RT1 replay")
    error = replay.json() if replay.headers.get("content-type", "").startswith("application/json") else {}
    log.log(f"Response body: error={error.get('error')} error_description={error.get('error_description')!r}")
    replay_rejected = replay.status_code in (400, 401, 403) and error.get("error") == "invalid_grant"
    log.log(f"Old refresh token replay -> HTTP {replay.status_code} {error.get('error')} -> "
            f"{'PASS (rejected)' if replay_rejected else 'FAIL (accepted!)'}", "PASS" if replay_rejected else "FAIL")

    log.log("Step 5 - Reuse detection: try RT2 after RT1 was replayed (family should be revoked)")
    family = refresh(cfg, log, rt2, "RT2 after reuse")
    revoked = family.status_code != 200
    family_error = family.json().get("error") if "json" in family.headers.get("content-type", "") else family.text[:80]
    log.log(f"RT2 -> HTTP {family.status_code} {family_error if revoked else 'issued new tokens'} -> "
            f"{'token family revoked (breach detection)' if revoked else 'family still valid'}", "INFO")

    passed = bool(TTL_OK["value"]) and rotated and replay_rejected
    log.log(f"RESULT: TTL={cfg['expected_ttl']}s {'OK' if TTL_OK['value'] else 'WRONG'} | rotation "
            f"{'ON' if rotated else 'OFF'} | old RT replay {'REJECTED' if replay_rejected else 'ACCEPTED'} -> "
            f"{'PASS' if passed else 'FAIL'}", "PASS" if passed else "FAIL")
    log.log(f"Evidence saved to {log.path}")
    log.close()
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
