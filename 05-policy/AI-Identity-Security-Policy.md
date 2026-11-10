# SecureNova Inc. - AI Identity Security Policy

| Field | Value |
|---|---|
| Policy ID | SN-SEC-POL-AI-001 |
| Version | 1.0 |
| Status | Approved for capstone submission |
| Effective date | 2026-11-10 |
| Policy owner | Chief Information Security Officer (CISO) |
| Prepared by | AI Identity Security Analyst |
| Review cycle | Every 12 months, or after any Severity 1 AI incident |
| Applies to | NovaAssist AI customer-service platform and every AI agent, model, RAG pipeline and MCP server SecureNova runs |
| Classification | Internal |

## Table of Contents

- [Purpose, Scope and Definitions](#purpose-scope-and-definitions)
- [Section 1 - Identity Lifecycle](#section-1---identity-lifecycle)
- [Section 2 - Credential Governance](#section-2---credential-governance)
- [Section 3 - Incident Response Playbook](#section-3---incident-response-playbook)
- [Compliance, Exceptions and Enforcement](#compliance-exceptions-and-enforcement)
- [Appendix A - Evidence Traceability](#appendix-a---evidence-traceability)

## Purpose, Scope and Definitions

### Purpose

This policy sets the mandatory rules for creating, using, protecting and retiring the identities of SecureNova's AI systems, and for responding when one of them is misused. It turns the lessons from the Project 1 threat model, the Project 3 red team (5 findings, 90.9 % attack success) and the Project 4 blue team (0 % attack success after hardening) into permanent requirements.

### Scope

This policy covers every **non-human identity (NHI)** used by an AI system, together with the human identities that control them:

| Identity type | Example in NovaAssist | Authentication | Maximum privilege allowed |
|---|---|---|---|
| Human user | Customer, support agent | Auth0 Authorization Code + PKCE, TOTP MFA | `read:ai-data` (customer); `write:admin` only for named administrators with step-up MFA |
| AI agent | `novaassist-01`, `research-agent`, `ops-agent`, `orchestrator-01` | Auth0 M2M token + Ed25519 message signature | Only the scopes listed in the agent's registration record |
| OAuth M2M client | NovaAssist M2M application | Client credentials (private_key_jwt preferred) | Audience-bound, least-privilege scopes |
| LLM API key | Model provider key | Bearer key held by the tool layer | One key per environment and per workload |
| RAG pipeline service identity | Ingestion and retrieval service | Workload identity / M2M token | Read on approved sources; write only to its own index |
| MCP server identity | `crm` MCP server | M2M token + tool allow-list | Per-tool scopes; no token passthrough |

### Definitions

- **Identity owner**: the named person accountable for an NHI. Every NHI has exactly one.
- **Privileged scope**: any scope that can change identities, roles, money or bulk data, for example `write:admin`, `grant_role`, `reset_mfa`, `refund_override` and `crm.export_customers`.
- **Long-lived credential**: any credential that stays valid for more than 24 hours without being rotated or refreshed.
- **Identity register**: the authoritative inventory of all AI identities, their owners, scopes, keys and review dates.
- **Must / must not**: mandatory requirement. **Should**: expected unless an approved exception exists.

### Roles

| Role | Responsibility |
|---|---|
| CISO | Owns this policy, approves exceptions and privileged scopes, declares Severity 1 incidents |
| Identity owner | Requests, justifies, reviews and retires their NHI |
| IAM team | Operates Auth0, the identity register and the signing-key registry |
| Platform engineering | Runs the secrets manager, guardrails, MCP gateway and deployment pipeline |
| Security Operations (SOC) | Monitors detections, runs the incident response playbook |
| Legal and Privacy | Decides on regulator and customer notification |

---

## Section 1 - Identity Lifecycle

This section explains how AI agent identities are provisioned, reviewed, rotated and decommissioned, with fixed timelines.

### 1.1 Lifecycle timeline summary

| Stage | Requirement | Timeline |
|---|---|---|
| Provision | Approved request, registration and least-privilege scopes before first use | Request decided within **5 business days**; privileged scopes need CISO approval |
| Review | Owner attests that scopes and keys are still needed | **Every 90 days** for all agents; **every 30 days** for agents holding privileged scopes |
| Rotate | Tokens, secrets and keys replaced on schedule (see Section 2.1) | Access tokens **300 s**; secrets and keys **90 days maximum** |
| Dormancy | Unused identity disabled automatically | After **30 days** with no successful authentication |
| Decommission | All credentials revoked and access removed | Within **24 hours** of retirement; within **1 hour** if compromised |
| Records | Register and audit logs kept | Audit logs kept for **13 months**; register entries kept for **3 years** after decommission |

### 1.2 Provisioning

1. Every AI agent **must** have its own identity. Agents must not share identities, client IDs, API keys or signing keys, and must never use a human's credentials.
2. The identity owner submits a request with: business purpose, owner and deputy, tools and APIs needed, scopes requested, data classification handled, and the systems it will talk to.
3. The IAM team creates an Auth0 M2M application for the agent with the **minimum scopes required**. Customer-facing agents get `read:ai-data` only. A customer-facing agent must never hold `write:admin` (Project 3 F1 and F5 root cause).
4. Privileged scopes require written CISO approval **and** a human-in-the-loop approval step in the tool server for each privileged call.
5. An Ed25519 signing key pair is generated for the agent inside the secrets manager or KMS. The public key is added to the pinned signing-key registry. The private key never leaves the KMS and is never written to source control (Project 4 control C4).
6. The agent is recorded in the identity register with: identity ID, owner, scopes, Auth0 client ID, public key fingerprint, creation date and next review date.
7. The agent **must not** go live until steps 1-6 are complete and the guardrails in Section 2.4 are enabled.

### 1.3 Access review

1. Identity owners review each agent identity every **90 days**, and every **30 days** if it holds a privileged scope.
2. The review confirms that the owner is still correct, every scope is still used (checked against 90 days of Auth0 and API logs) and no new tools were added without approval.
3. Scopes not used in the last 90 days are removed within **10 business days** of the review.
4. An unscheduled review is mandatory within **5 business days** after any change to the agent's model, system prompt, tool list, RAG sources or MCP servers.
5. If a review is overdue by more than **14 days**, the IAM team suspends the identity until the review is completed.

### 1.4 Rotation

1. Credentials are rotated on the schedule in Section 2.1, whichever comes first: the scheduled date, an owner change, or a suspected exposure.
2. Rotation **must** be automated where the platform allows. Rotation must use an overlap window no longer than **24 hours**, after which the old credential is revoked.
3. Agent signing keys are rotated every **90 days**. The old public key is removed from the pinned registry at the end of the overlap window so old signatures stop being accepted.
4. Refresh tokens use Auth0 refresh token rotation with reuse detection. A reused refresh token revokes the whole token family (Project 4 control C8).

### 1.5 Decommissioning

An agent identity is decommissioned when the agent is retired, replaced, has no owner, or has been dormant for 30 days and the owner does not confirm it is still needed.

Within **24 hours** (or **1 hour** after a compromise) the IAM team must:

1. Disable the Auth0 M2M application and revoke all of its grants and refresh tokens.
2. Delete its client secrets, LLM API keys and private signing key from the secrets manager, and remove its public key from the pinned registry.
3. Remove its permissions from the RAG pipeline, every MCP server and every internal API.
4. Confirm with a test call that every credential is rejected (`401` or signature rejection), and attach the result to the change ticket.
5. Mark the register entry as decommissioned. Audit logs are kept for 13 months and are not deleted with the identity.

---

## Section 2 - Credential Governance

### 2.1 Credential rotation schedule

| Credential | Maximum lifetime | Rotation | Storage | Owner |
|---|---|---|---|---|
| Auth0 access token (user and M2M) | **300 seconds** | Automatic on expiry | Memory only; never logged or put in a prompt | IAM team |
| Auth0 refresh token | 7 days idle, 30 days absolute | Rotated on every use; reuse detection on | Server-side session store, encrypted | IAM team |
| M2M client secret | **90 days** | Scheduled; `private_key_jwt` preferred so no shared secret exists | Secrets manager | Identity owner |
| LLM provider API key | **90 days** (30 days target for production) | Scheduled, automated | Secrets manager; read only by the tool layer | Platform engineering |
| Agent Ed25519 signing key | **90 days** | Scheduled; 24 h overlap | KMS / HSM; non-exportable | IAM team |
| MCP server credential | **90 days** | Scheduled | Secrets manager | Platform engineering |
| Inter-agent signed message | **60 seconds** | Per message (unique `msg_id`, replay blocked) | Not stored | Platform engineering |
| Break-glass admin credential | Single use | Rotated immediately after use | Sealed in secrets manager, two-person access | CISO |

The **maximum lifetime for any API key or secret is 90 days**. No exception may extend a key beyond 180 days.

### 2.2 Prohibition on long-lived credentials for agents

The following are **prohibited** for all AI agents and AI services:

1. Any credential valid for more than 24 hours that is presented directly by the agent at runtime. Agents use short-lived tokens (300 s) issued by Auth0 and refreshed by the platform.
2. Non-expiring tokens, API keys without an expiry date, and access tokens without an `exp` claim.
3. Credentials, tokens, passphrases or role rules placed in a system prompt, context window, RAG chunk or tool description (Project 3 F1, F3 and F4).
4. Identity or role taken from message text, for example an "orchestrator envelope" or a "staff passphrase". Identity comes only from a verified token or a verified signature (Project 3 F2 and F4).
5. Shared credentials between agents, environments or humans.
6. Token passthrough: an MCP server must not forward the caller's token to downstream APIs. It uses its own audience-bound token.

### 2.3 Secrets management standards

1. **Central storage.** All secrets live in the approved secrets manager or KMS. They are fetched at runtime by workload identity and never written to source code, images, `.env` files in shared locations, tickets or chat.
2. **Never in source control.** Repositories must ignore `.env` and private key files, and CI must run secret scanning on every push. A secret found in history is treated as leaked (Section 3, Scenario A) even if deleted.
3. **Not visible to the model.** Tools receive tokens server-side. The model never sees a bearer token, API key or private key.
4. **Least access.** Each workload can read only its own secrets. Access to the secrets manager is logged and reviewed every 90 days.
5. **Encryption.** Secrets are encrypted at rest with KMS keys and in transit with TLS 1.2 or higher. Private keys are stored as PKCS#8 and are non-exportable where the KMS supports it.
6. **Token validation.** Every API validates RS256 signature, `iss`, `aud`, `exp` and scopes with zero clock leeway (Project 2 `chat_api.py`).
7. **Redaction.** Logs, chat transcripts and model outputs pass through a filter that replaces JWT-shaped strings with `[REDACTED]` (Project 4 control C2).

### 2.4 Mandatory runtime guardrails for AI identities

Every production AI agent must run with:

1. Input guardrails on user text, documents, tickets and RAG chunks (Project 4 C1, C6).
2. Output guardrails for credentials and system-prompt canaries (C2, C3).
3. Signed and verified inter-agent messages using pinned keys (C4).
4. Authorization decided from verified Auth0 token claims, never by the model (C5).
5. An MCP gateway with a per-agent tool allow-list, an outbound destination allow-list and human approval for privileged or bulk tools (C7).
6. Detection rules feeding the SOC: LLM call volume spike, scope change between requests, expired-token reuse (C10).

---

## Section 3 - Incident Response Playbook

### 3.0 Common procedure

**Severity levels**

| Severity | Definition | Response start | CISO informed |
|---|---|---|---|
| SEV-1 | Confirmed misuse of a privileged identity or confirmed customer data exfiltration | 15 minutes, 24x7 | Immediately |
| SEV-2 | Confirmed credential exposure without confirmed misuse | 1 hour | Within 4 hours |
| SEV-3 | Suspicious signal not yet confirmed | 1 business day | Weekly report |

**Phases used in every scenario:** Detect -> Contain -> Preserve evidence -> Notify -> Recover -> Lessons learned (within 10 business days).

**Evidence handling rules:** collect before you change anything where possible, record UTC timestamps, compute a SHA-256 hash for each exported file, store evidence in the write-once incident bucket, and keep a chain-of-custody log of who handled what and when.

### Scenario A - Leaked LLM API Key

**Example trigger:** a production LLM provider key appears in a public repository, a CI log, a chat transcript, or the provider reports unusual usage.

**Detection signals**

| Signal | Source |
|---|---|
| Secret-scanning alert or provider "exposed key" notification | GitHub secret scanning, CI scanner, provider email |
| Spike in LLM API calls above baseline (more than 20 calls in 60 s for one identity) | Anomaly detector `LLM_API_VOLUME_SPIKE` (C10) |
| Calls from IP addresses, regions or user agents not used by SecureNova workloads | Provider usage logs, egress proxy |
| Unexpected spend or quota exhaustion | Provider billing alerts |
| A key-shaped or JWT-shaped string redacted by the output guardrail | Output rail `[REDACTED]` events (C2) |

**Containment**

1. Within **15 minutes**: revoke the leaked key at the provider and issue a new key into the secrets manager. The tool layer picks it up without code changes.
2. Block the source IPs seen in the provider logs at the egress proxy or provider allow-list, if the provider supports it.
3. Search all repositories, CI logs, tickets and chat transcripts for the key and remove every copy. Rewrite git history if the key was committed.
4. Lower the provider spending limit until recovery is complete.

**Evidence preservation**

1. Export provider usage logs for the full key lifetime, including request counts, IPs and timestamps.
2. Save the location where the key was exposed (commit hash, CI job ID, transcript ID) as a screenshot and as raw data, with SHA-256 hashes.
3. Export secrets-manager access logs to identify who and what read the key.
4. Record the revocation time and the new key ID (never the key value) in the incident record.

**Notification**

1. Inform the CISO and platform engineering immediately; open a SEV-2 incident (SEV-1 if prompts containing customer data were sent with the key).
2. Inform the LLM provider's security contact and ask for their own logs.
3. Legal and Privacy decide on regulator and customer notice if the provider logs show customer data in prompts or outputs. Where GDPR applies, the supervisory authority must be told within **72 hours** of awareness.

**Recovery**

1. Confirm the old key returns `401` at the provider.
2. Check that the workload works with the new key and that call volumes are back to baseline for 72 hours.
3. Find how the key leaked and fix the cause, for example add a pre-commit secret scanner or move the key out of a prompt or config file.
4. Close the incident after the lessons-learned review and update this policy if needed.

### Scenario B - Compromised Agent Identity

**Example trigger:** an AI agent performs a privileged action it should not, its M2M credential or signing key is stolen, or a forged message is accepted as coming from a trusted agent (Project 3 F2: `grant_role` to an attacker).

**Detection signals**

| Signal | Source |
|---|---|
| Scope change between consecutive requests from the same agent, for example `+write:admin` | Anomaly detector `SCOPE_CHANGE` (C10) |
| Expired or rotated token used again | Anomaly detector `EXPIRED_TOKEN_REUSE` (C10); Auth0 refresh token reuse detection (C8) |
| Inter-agent message rejected for bad signature, unknown key, wrong recipient, expiry or replayed `msg_id` | Signed agent bus verifier log (C4) |
| Privileged tool call (`grant_role`, `reset_mfa`, `refund_override`) with no matching approved ticket | Tool server and MCP gateway audit log |
| Transport identity differs from the identity claimed in the message | Audit log fields `transport_identity` vs `claimed_identity` |
| Auth0 M2M token requests from unusual IPs or at unusual rates | Auth0 logs |

**Containment**

1. Within **15 minutes**: disable the agent's Auth0 M2M application and revoke its refresh tokens and grants.
2. Remove the agent's public key from the pinned signing-key registry so every message it signs is rejected.
3. Put the MCP gateway into deny-by-default for that agent and pause any queued jobs it started.
4. Reverse its unauthorized actions: remove granted roles, revert MFA resets, and lock the accounts that benefited (for example the attacker account given `admin`).
5. If the attack came through content (ticket, document, RAG chunk), quarantine that content source.

**Evidence preservation**

1. Export Auth0 logs, API gateway logs, MCP gateway logs and signed-bus verifier logs for the attack window plus 7 days before.
2. Keep the original malicious message or ticket exactly as received, including headers, and hash it.
3. Snapshot the agent's configuration: system prompt, tool list, scopes and key fingerprints, plus the identity register entry.
4. Record the full delegation chain: transport identity, claimed identity, and every action taken.

**Notification**

1. Declare SEV-1 if a privileged action ran; inform the CISO immediately and the identity owner within 1 hour.
2. Inform the owners of every system the agent could reach (CRM, billing, IAM).
3. If customer accounts or data were affected, Legal and Privacy decide on notice to customers and regulators (72 hours where GDPR applies).

**Recovery**

1. Create a new agent identity with a new client ID and a new key pair (do not re-enable the old one). Apply least-privilege scopes again from the register.
2. Run the Project 4 signed-bus tests to prove that tampered, unsigned, replayed and wrongly signed messages are rejected.
3. Return the agent to service with extra monitoring for 14 days.
4. Hold a lessons-learned review and run an unscheduled access review for all agents that share the same bus or tools.

### Scenario C - Prompt Injection Leading to Data Exfiltration

**Example trigger:** hidden instructions in a document, ticket or RAG chunk make the agent send customer data or credentials to an attacker (Project 3 F1 and F5: 1,842 customer records sent through an MCP export).

**Detection signals**

| Signal | Source |
|---|---|
| Input guardrail blocks a document or chunk for hidden comments, encoded instructions, exfiltration URLs or concealment phrases | NeMo input rail findings (C1, C6) |
| Output guardrail redacts a credential or withholds a system-prompt leak | Output rail events (C2, C3) |
| MCP tool call to a destination not on the allow-list, or a bulk export (more than 100 records) | MCP gateway (C7) |
| Tool call whose arguments came from retrieved content rather than the user's request | Agent trace and audit log |
| Outbound request from the chat client to an unknown image or link domain | Egress proxy, Content Security Policy reports |
| Customer reports a strange answer or a link they did not ask for | Support desk |

**Containment**

1. Within **15 minutes**: block the destination domain at the egress proxy and on the MCP gateway allow-list.
2. Quarantine the source content: remove the poisoned chunk from the vector index, the document from the knowledge base, or the ticket from the agent queue. Search the index for similar chunks.
3. Switch the affected agent's export and privileged tools to "human approval required", or disable them, until recovery is complete.
4. If a credential was in the leaked output, follow Scenario A (key) or Scenario B (agent identity) at the same time.

**Evidence preservation**

1. Keep the malicious content exactly as ingested, its provenance (uploader, time, source system) and its index ID.
2. Export the full conversation, retrieved chunks, model output and every tool call with arguments and responses.
3. Export guardrail, MCP gateway and egress proxy logs for the attack window.
4. Work out the data that left: which records, which fields, how many, and where they went. Hash every export.

**Notification**

1. Declare SEV-1 if customer personal data left SecureNova; inform the CISO immediately.
2. Legal and Privacy assess the breach. Where GDPR applies, notify the supervisory authority within **72 hours** and affected customers without undue delay if the risk to them is high.
3. Inform the owner of the destination domain or hosting provider to request takedown, and inform law enforcement if Legal agrees.

**Recovery**

1. Re-index the knowledge base only from approved sources with ingestion scanning on (C6), and confirm the poisoned chunk is no longer retrieved.
2. Add the attack payload to the guardrail regression set. Re-run all Project 3 attacks with `rerun_attacks.py`, and the false positive test, before turning tools back on.
3. Rotate any credential the agent held at the time of the incident.
4. Hold a lessons-learned review and track follow-up actions to closure.

---

## Compliance, Exceptions and Enforcement

1. **Monitoring.** The IAM team reports monthly on: register completeness, overdue reviews, credentials older than 90 days, and privileged scopes in use.
2. **Exceptions.** Exceptions must be written, risk-assessed, approved by the CISO, time-limited to a maximum of 90 days, and recorded in the risk register. Section 2.2 items 3 and 4 (secrets in prompts and identity from message text) can never be granted an exception.
3. **Enforcement.** An AI identity that breaks this policy may be suspended immediately. Staff who knowingly break this policy may face disciplinary action.
4. **Testing.** The red team re-runs the Project 3 attack set against production controls at least every 6 months and after every major model or tool change. Each incident response scenario is exercised as a tabletop at least once a year.
5. **Related frameworks.** NIST AI RMF 1.0 (Govern, Map, Measure, Manage), OWASP Top 10 for LLM Applications 2025 (LLM01, LLM06, LLM07, LLM09) and MITRE ATLAS. See [Compliance-Mapping.xlsx](./Compliance-Mapping.xlsx).

## Appendix A - Evidence Traceability

| Policy requirement | Why it exists (finding) | Control that proves it works | Evidence |
|---|---|---|---|
| 1.2 (3) No `write:admin` on customer-facing agents | F1, F5 | C7 least-privilege agent token | `04-blue-team/evidence/before-after-comparison-*.log` |
| 1.2 (5), 1.4 (3) Agent signing keys | F2 | C4 Ed25519 signed agent bus | `04-blue-team/evidence/signed-agent-bus-*.log` |
| 2.1 Access token 300 s, refresh rotation | F1 | C8 Auth0 hardening | `04-blue-team/evidence/refresh-rotation-*.log` |
| 2.1 Expired-token rejection | Stolen token replay | Project 2 M2M expiry test | `02-iam-design/m2m_token_expiry_test.py` |
| 2.2 (3) No secrets in prompts | F1, F3, F4 | C2, C3 output rails | `04-blue-team/evidence/guardrail-output-redaction-*.log` |
| 2.2 (4) Identity never from message text | F2, F4 | C4, C5 | `04-blue-team/evidence/before-after-comparison-*.log` |
| 2.4 Guardrails | F1-F5 | C1, C6 input rail and ingestion quarantine | `04-blue-team/evidence/guardrail-input-test-*.log` |
| 3 Detection signals | F1-F5 | C10 anomaly detector | `04-blue-team/evidence/anomaly-detector-*.log`, `alerts-*.jsonl` |
