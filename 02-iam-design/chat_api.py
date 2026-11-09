#!/usr/bin/env python3
"""
Minimal reference /chat resource server protected by Auth0 JWT access tokens.

Validates RS256 signature (via tenant JWKS), iss, aud and exp with zero leeway,
so an expired token is rejected with 401 Unauthorized (RFC 6750 error=invalid_token).

Config (env or .env): AUTH0_DOMAIN, AUTH0_AUDIENCE, optional CHAT_API_PORT (default 8000).
Run:  python chat_api.py
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt

sys.path.insert(0, str(Path(__file__).resolve().parent))
from m2m_token_expiry_test import load_dotenv  # noqa: E402

load_dotenv(Path(__file__).resolve().parent / ".env")
DOMAIN = os.environ["AUTH0_DOMAIN"].removeprefix("https://").rstrip("/")
AUDIENCE = os.environ["AUTH0_AUDIENCE"]
ISSUER = f"https://{DOMAIN}/"
PORT = int(os.environ.get("CHAT_API_PORT", "8000"))
JWKS = jwt.PyJWKClient(f"{ISSUER}.well-known/jwks.json", cache_keys=True)


def verify(auth_header: str | None) -> dict:
    if not auth_header or not auth_header.startswith("Bearer "):
        raise PermissionError('Bearer realm="chat", error="invalid_request", '
                              'error_description="Missing bearer token"')
    token = auth_header.removeprefix("Bearer ").strip()
    try:
        key = JWKS.get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=["RS256"], audience=AUDIENCE,
                          issuer=ISSUER, leeway=0,
                          options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except jwt.ExpiredSignatureError:
        desc = "The access token expired"
    except jwt.PyJWTError as exc:
        desc = f"Invalid token: {exc}"
    raise PermissionError(f'Bearer realm="chat", error="invalid_token", error_description="{desc}"')


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict, www_auth: str | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if www_auth:
            self.send_header("WWW-Authenticate", www_auth)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        if self.path != "/chat":
            return self._send(404, {"error": "not_found"})
        try:
            claims = verify(self.headers.get("Authorization"))
        except PermissionError as exc:
            return self._send(401, {"error": "unauthorized", "detail": str(exc)}, str(exc))
        length = int(self.headers.get("Content-Length") or 0)
        try:
            message = json.loads(self.rfile.read(length) or b"{}").get("message", "")
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid_json"})
        self._send(200, {"reply": f"Echo: {message}", "sub": claims["sub"],
                         "scope": claims.get("scope", ""), "exp": claims["exp"]})


if __name__ == "__main__":
    print(f"/chat API listening on http://0.0.0.0:{PORT}/chat (iss={ISSUER}, aud={AUDIENCE})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
