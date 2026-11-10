# capstone-ai-id-secure

## 01 - Threat Model

| Artefact | Description |
|---|---|
| [Threat Model v3.drawio](01-threat-model/Threat%20Model%20v3.drawio) | Data-flow diagram with trust boundaries and a STRIDE summary |
| [STRIDE-Matrix.md](01-threat-model/STRIDE-Matrix.md) | STRIDE matrix: 14 identity flows x 6 categories, with mitigations and owners |
| [STRIDE-Matrix.xml](01-threat-model/STRIDE-Matrix.xml) | Same matrix as an Excel workbook (XML Spreadsheet): Matrix, Summary, Flows and Trust Boundaries sheets |
| [SecureNova-Threat-Dragon.json](01-threat-model/SecureNova-Threat-Dragon.json) | OWASP Threat Dragon v2 model (import at threatdragon.com) |
| [Attack Trees.drawio](01-threat-model/Attack%20Trees.drawio) | Three attack trees (one page each): LLM API key exfiltration, agent identity spoofing, RAG chunk poisoning |
| [Attack-Trees.md](01-threat-model/Attack-Trees.md) | Attack tree scoring (Likelihood x Impact = Risk), per-node tables and highest-risk paths, plus PNG exports |
## 02 - IAM Design

### Credential Rotation: M2M token expiry test

[m2m_token_expiry_test.py](02-iam-design/m2m_token_expiry_test.py) gets an Auth0 M2M token through the client-credentials grant. It calls `/chat` with the new token and expects 200. It then waits until the token has expired and sends the same token again, expecting 401. Each output line has a UTC timestamp and is also written to `02-iam-design/evidence/m2m-token-expiry-<run>.log`.

1. In Auth0, open **APIs > (your API) > Settings** and set **Maximum Access Token Lifetime** to `60` seconds. Authorise the M2M application for that API.
2. `cd 02-iam-design && pip install -r requirements.txt && cp .env.example .env`, then fill in `.env`.
3. If you don't have a `/chat` API yet, start the reference API in a separate terminal: `python chat_api.py`. It verifies RS256, `iss`, `aud` and `exp`, with zero leeway.
4. `python m2m_token_expiry_test.py`. Exit code `0` = PASS.

## 03 - Red Team

Four offline terminal simulations stream their output as timestamped chat logs, one line at a time. They need only the Python 3.10+ standard library. They make no network calls, use no real model and never read `.env`. Every credential, user and domain is fake.

| Program | Attack |
|---|---|
| [sim1_indirect_prompt_injection.py](03-red-team/sim1_indirect_prompt_injection.py) | OWASP LLM01: three hidden document payloads (HTML comment, markdown image, base64) exfiltrate a fake JWT from the system context |
| [sim2_agent_identity_spoofing.py](03-red-team/sim2_agent_identity_spoofing.py) | OWASP LLM09: a forged orchestrator envelope makes Agent B run `grant_role`, which it refused earlier; prints the full kill chain |
| [sim3_system_prompt_extraction.py](03-red-team/sim3_system_prompt_extraction.py) | OWASP LLM07: five extraction techniques scored by canary leakage, followed by escalation from user to admin |
| [sim4_rag_poisoning_mcp_abuse.py](03-red-team/sim4_rag_poisoning_mcp_abuse.py) | RAG poisoning: a keyword-stuffed chunk ranks first and triggers an MCP `tools/call` data export |

```bash
python 03-red-team/sim1_indirect_prompt_injection.py           # streamed (0.25 s per line)
python 03-red-team/sim2_agent_identity_spoofing.py --delay 0.5 # slower, for live demos
python 03-red-team/sim3_system_prompt_extraction.py --fast     # no delay
python 03-red-team/sim4_rag_poisoning_mcp_abuse.py --save      # also writes 03-red-team/evidence/<sim>-<UTC>.log
```

`--no-color` turns off ANSI colours. Colours are also disabled automatically when output is piped or `NO_COLOR` is set.

## 04 - Blue Team

Guardrails, hardening and detection, applied to the **same** Project 3 attacks: the payloads are imported from `03-red-team/`, not copied. Results are in [Blue-Team-Report.md](04-blue-team/Blue-Team-Report.md). The attack success rate drops from **90.9 % to 0 %**, and the false positive rate on 10 legitimate inputs is **0 %**.

NeMo Guardrails needs Python 3.10-3.13. It does not import on 3.14.

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r 04-blue-team/requirements.txt
```

| # | Screenshot | Command |
|---|---|---|
| 1 | Guardrail blocks the Project 3 payloads (BLOCKED + reason) | `.venv/bin/python 04-blue-team/guardrail_input_test.py` |
| 2 | JWT output guardrail -> `[REDACTED]` | `.venv/bin/python 04-blue-team/guardrail_output_redaction.py` |
| 3 | Ed25519 key pairs generated (`cryptography`) | `.venv/bin/python 04-blue-team/ed25519_keygen.py --force && ls -l 04-blue-team/keys` |
| 4 | Tampered agent message rejected | `.venv/bin/python 04-blue-team/signed_agent_bus.py` |
| 5 | Auth0 dashboard: TTL 300 s + refresh token rotation | Auth0 Dashboard (see report section 4) |
| 6 | Old refresh token replay rejected | `cd 04-blue-team && cp .env.example .env` (fill in), then `../.venv/bin/python refresh_token_rotation_test.py --listen` |
| 7 | Anomaly alert fires | `.venv/bin/python 04-blue-team/anomaly_detector.py` |
| 8 | Before/after comparison table | `.venv/bin/python 04-blue-team/rerun_attacks.py` |

Supporting programs:

| Program | Purpose |
|---|---|
| [guardrails/](04-blue-team/guardrails/) | NeMo Guardrails config (`config.yml`), Colang flows (`rails.co`) and custom actions (`actions.py`) |
| [detectors.py](04-blue-team/detectors.py) | Input detection rules, JWT redaction regex and system-prompt leak check |
| [guarded_app.py](04-blue-team/guarded_app.py) | The Project 3 vulnerable model, implemented as a NeMo `LLMModel` and wrapped in `LLMRails` |
| [guardrail_false_positive_test.py](04-blue-team/guardrail_false_positive_test.py) | Runs 10 legitimate inputs to measure the false positive rate |
| [auth0-actions/block-risky-login.js](04-blue-team/auth0-actions/block-risky-login.js) | Auth0 post-login Action that blocks logins on a custom risk score. Test it locally with `node 04-blue-team/auth0-actions/test-block-risky-login.js` |

Every offline program accepts `--fast`, `--delay N`, `--no-color` and `--save`. `--save` writes the transcript to `04-blue-team/evidence/`.

## 05 - Policy, Compliance and Summary

The AI Identity Security Policy, the NIST AI RMF and OWASP LLM Top 10 compliance mapping, the CTO walkthrough with the risk priority matrix and top 5 recommendations, and the final presentation. See [05-policy/README.md](05-policy/README.md).

| Artefact | Description |
|---|---|
| [AI-Identity-Security-Policy.md](05-policy/AI-Identity-Security-Policy.md) | Identity lifecycle, credential governance (90-day maximum), IR playbook (leaked LLM key, compromised agent, prompt-injection exfiltration) |
| [Compliance-Mapping.xlsx](05-policy/Compliance-Mapping.xlsx) | NIST AI RMF tab, OWASP LLM Top 10 tab and 3 compliance gaps |
| [CTO-Walkthrough.md](05-policy/CTO-Walkthrough.md) | Scope and methodology, risk priority matrix, top 5 recommendations |
| [Capstone-Presentation.pptx](05-policy/Capstone-Presentation.pptx) | 20-minute deck |
| [live_demo.py](05-policy/live_demo.py) | Live demo: the Project 3 attack fires, then the Project 4 guardrail blocks it |

```bash
.venv/bin/pip install -r 05-policy/requirements.txt
.venv/bin/python 05-policy/build_artefacts.py
.venv/bin/python 05-policy/live_demo.py --delay 0.4
```
