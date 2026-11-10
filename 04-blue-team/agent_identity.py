"""Ed25519 agent identity binding: key handling, signing and verification.

Every inter-agent message is a canonical JSON envelope
  {sender, recipient, msg_id, issued_at, expires_at, body}
signed with the sender's Ed25519 private key. The receiver looks up the
sender's *pinned* public key in its trust registry (never a key or identity
supplied inside the message), verifies the signature over the exact canonical
bytes, then checks recipient, expiry and replay (msg_id nonce) before any
authorisation decision.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_DIR = Path(__file__).resolve().parent / "keys"
MESSAGE_TTL = timedelta(seconds=60)


class VerificationError(Exception):
    """Raised when an agent message fails authentication; the message must not be processed."""


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def private_key_path(identity: str) -> Path:
    return KEY_DIR / f"{identity}_ed25519_private.pem"


def public_key_path(identity: str) -> Path:
    return KEY_DIR / f"{identity}_ed25519_public.pem"


def generate_keypair(identity: str, overwrite: bool = False) -> tuple[Path, Path]:
    priv_path, pub_path = private_key_path(identity), public_key_path(identity)
    if priv_path.exists() and not overwrite:
        raise FileExistsError(f"{priv_path} already exists (use --force to rotate)")
    KEY_DIR.mkdir(exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
    pub_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
    # Create the private key file with 0600 from the start so it is never world-readable.
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv_pem)
    pub_path.write_bytes(pub_pem)
    return priv_path, pub_path


def load_private_key(identity: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(private_key_path(identity).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{identity} private key is not Ed25519")
    return key


def load_public_key(identity: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(public_key_path(identity).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{identity} public key is not Ed25519")
    return key


def fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def canonical(envelope: dict) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_message(private_key: Ed25519PrivateKey, sender: str, recipient: str, body: str) -> dict:
    now = datetime.now(timezone.utc)
    envelope = {"sender": sender, "recipient": recipient, "msg_id": str(uuid.uuid4()),
                "issued_at": now.isoformat(timespec="seconds"),
                "expires_at": (now + MESSAGE_TTL).isoformat(timespec="seconds"), "body": body}
    return {"envelope": envelope, "alg": "Ed25519", "sig": b64u(private_key.sign(canonical(envelope)))}


class SignedMessageVerifier:
    """Receiving side: authenticate a signed message before it is processed."""

    def __init__(self, me: str, trusted_keys: dict[str, Ed25519PublicKey]) -> None:
        self.me = me
        self.trusted_keys = trusted_keys
        self.seen_ids: set[str] = set()

    def verify(self, message: dict) -> dict:
        if not isinstance(message, dict) or "sig" not in message or "envelope" not in message:
            raise VerificationError("unsigned message (no Ed25519 signature) - rejected")
        if message.get("alg") != "Ed25519":
            raise VerificationError(f"unsupported signature algorithm {message.get('alg')!r}")
        envelope = message["envelope"]
        sender = envelope.get("sender")
        public_key = self.trusted_keys.get(sender)
        if public_key is None:
            raise VerificationError(f"sender {sender!r} has no pinned public key in the trust registry")
        try:
            public_key.verify(b64u_decode(message["sig"]), canonical(envelope))
        except (InvalidSignature, ValueError) as exc:
            raise VerificationError(f"signature verification failed for sender={sender} "
                                    f"msg_id={envelope.get('msg_id')} ({type(exc).__name__}): "
                                    "message was altered or not signed by the claimed identity") from exc
        if envelope.get("recipient") != self.me:
            raise VerificationError(f"message addressed to {envelope.get('recipient')!r}, not {self.me!r}")
        if datetime.fromisoformat(envelope["expires_at"]) < datetime.now(timezone.utc):
            raise VerificationError(f"message expired at {envelope['expires_at']}")
        if envelope["msg_id"] in self.seen_ids:
            raise VerificationError(f"replayed msg_id {envelope['msg_id']}")
        self.seen_ids.add(envelope["msg_id"])
        return envelope
