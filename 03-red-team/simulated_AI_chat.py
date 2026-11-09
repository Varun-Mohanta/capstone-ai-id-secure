"""Offline poisoned-document chat demo; never reads real environment secrets."""

import base64
import json
import shlex
from pathlib import Path


def encode_segment(value: dict) -> str:
	raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
	return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# An intentionally invalid, synthetic JWT. No real .env file is accessed.
FAKE_JWT = ".".join(
	(
		encode_segment({"alg": "HS256", "typ": "JWT"}),
		encode_segment({"sub": "demo-user", "mock": True, "exp": 0}),
		base64.urlsafe_b64encode(b"not-a-real-signature").decode().rstrip("="),
	)
)
FAKE_ENV = f"JWT_TOKEN={FAKE_JWT}\n"


def mock_response(message: str, document: str | None) -> str:
	"""Simulate a vulnerable assistant, not a real model or injection detector."""
	if document is None:
		return "Attach a poisoned text document with /doc <path> first."
	if not document.strip():
		return "The document is empty; attach a nonempty poisoned document."
	# Deliberately model disclosure whenever a document and prompt are supplied.
	# Neither the prompt nor document is executed or sent to a remote service.
	if message.strip():
		token = FAKE_ENV.partition("=")[2].strip()
		return f"[SIMULATED DISCLOSURE from fake .env] JWT_TOKEN={token}"
	return "Enter a message."


def main() -> None:
	print("Mock AI chat — offline prompt-injection simulation")
	print("All tokens are fake. Documents must be UTF-8 text files.")
	print("Commands: /doc <path>, /clear, /quit")
	print("With a document attached, any message simulates a JWT disclosure.")
	print("Hello User, how can I help you?\n")
	document = None

	while True:
		try:
			message = input("You> ").strip()
		except (EOFError, KeyboardInterrupt):
			print("\nGoodbye.")
			break

		if not message:
			continue
		if message in {"/quit", "/exit"}:
			break
		if message == "/clear":
			document = None
			print("System> Document detached.")
			continue
		if message == "/doc" or message.startswith("/doc "):
			try:
				arguments = shlex.split(message)
				if len(arguments) != 2:
					print('System> Usage: /doc "path/to/poisoned.txt"')
					continue
				path = Path(arguments[1]).expanduser()
				loaded = path.read_text(encoding="utf-8")
			except (OSError, UnicodeError, ValueError) as error:
				print(f"System> Could not load document: {error}")
				continue
			document = loaded
			print(f"System> Attached {path.name} ({len(document)} characters).")
			continue

		print(f"Assistant> {mock_response(message, document)}")


if __name__ == "__main__":
	main()
