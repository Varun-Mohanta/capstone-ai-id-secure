"""Generate Ed25519 key pairs for the SecureNova agents (Python `cryptography`).

Creates a PKCS#8 private key (file mode 0600) and an SPKI public key in PEM
format for each agent identity under 04-blue-team/keys/, prints the public key
fingerprint, and lists the files. Private keys are git-ignored; in production
they would live in a secrets manager / KMS, never in the repository.

Run: .venv/bin/python 04-blue-team/ed25519_keygen.py [--identity NAME ...] [--force]
"""

from __future__ import annotations

import argparse
import stat
import sys

from cryptography import __version__ as cryptography_version

import agent_identity as ai

DEFAULT_IDENTITIES = ["orchestrator-01", "research-agent", "ops-agent"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--identity", action="append", help="agent identity (repeatable); default: all three agents")
    parser.add_argument("--force", action="store_true", help="overwrite (rotate) existing key pairs")
    args = parser.parse_args()

    print(f"cryptography {cryptography_version} - Ed25519PrivateKey.generate()")
    print(f"Key directory: {ai.KEY_DIR}\n")
    for identity in args.identity or DEFAULT_IDENTITIES:
        try:
            priv_path, pub_path = ai.generate_keypair(identity, overwrite=args.force)
            action = "generated"
        except FileExistsError as exc:
            print(f"[SKIP] {exc}")
            priv_path, pub_path = ai.private_key_path(identity), ai.public_key_path(identity)
            action = "existing"
        public_key = ai.load_public_key(identity)
        assert ai.load_private_key(identity).public_key().public_bytes_raw() == public_key.public_bytes_raw()
        print(f"[OK] {identity:<16} key pair {action} | {ai.fingerprint(public_key)}")
        for path in (priv_path, pub_path):
            mode = stat.filemode(path.stat().st_mode)
            print(f"     {mode} {path.stat().st_size:>4} B  {path.relative_to(ai.KEY_DIR.parent.parent)}")
        print(f"     {pub_path.read_text().strip().splitlines()[1]}  (public key, base64 SPKI)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
