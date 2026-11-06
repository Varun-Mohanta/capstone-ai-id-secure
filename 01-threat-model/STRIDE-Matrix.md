# STRIDE Matrix — SecureNova AI Customer Service Platform

Project 1 · Task 2. Every identity flow in the data-flow diagram is checked against all six STRIDE categories. Each cell holds either a threat or a justified **N/A**.

| Artefact | Purpose |
|---|---|
| [Threat Model v3.drawio](./Threat%20Model%20v3.drawio) | DFD with trust boundaries and a STRIDE summary |
| [SecureNova-Threat-Dragon.json](./SecureNova-Threat-Dragon.json) | OWASP Threat Dragon v2 model (same DFD, with all threats attached to each flow) |
| This file | The full flow-by-flow STRIDE matrix |

To open the Threat Dragon model, go to [Threat Dragon](https://www.threatdragon.com/) (or the desktop app), choose **Open an existing threat model → Import**, and select `SecureNova-Threat-Dragon.json`.

---

## 1. Method

- **Scope:** all 14 data flows in Threat Model v3 (F01–F14). These cover every identity type: human user, AI agent, OAuth M2M client, LLM API key, RAG service identity, and MCP server identity.
- **Approach:** STRIDE-per-flow. Each flow is checked against Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, and Elevation of privilege, giving 14 × 6 = **84 assessments**.
- **Severity (qualitative):**
  - **High:** credential or token compromise, privilege escalation, cross-user data exposure, or loss of attribution for privileged actions.
  - **Medium:** limited data exposure, integrity loss without direct privilege gain, or availability or cost impact.
  - **Low:** minor or hard-to-exploit impact.
  - Numeric Likelihood × Impact scoring is done in the attack trees and the risk register (Tasks 3–4).
- **Status:** `Open` means the mitigation is defined but has not yet been verified. It gets verified in Projects 2–4. `N/A` means the category does not apply, with the reason given.
- **Threat ID format:** `T-<flow>-<category>`, for example `T-F08-E`.

## 2. Trust boundaries

| ID | Boundary | Components inside | Why it is a boundary |
|---|---|---|---|
| TB1 | User / Frontend | User, User Interface (browser) | Untrusted client device and user input |
| TB2 | Identity Provider | Auth0 Tenant | Third-party SaaS that issues every token |
| TB3 | Application Backend | Chatbot Backend, Secrets Manager, Chat Session DB (contains TB4) | SecureNova-controlled server zone |
| TB4 | Agent Runtime | AI Chatbot Harness | Non-deterministic LLM-driven code that holds workload credentials |
| TB5 | Internal API | Internal REST APIs | Business systems of record that need scoped tokens |
| TB6 | RAG Pipeline | RAG Service, Embedding Service, Vector Store | Holds and serves untrusted ingested content |
| TB7 | MCP Server | MCP Server | Tool-execution identity that acts on internal APIs |
| TB8 | External Provider | LLM Provider | Third-party model API, reached with the LLM API key |

The three boundaries the task asks about map like this:
- **User layer → Agent layer:** TB1 → TB3/TB4, via F04 and F05.
- **Agent layer → Internal API layer:** TB4 → TB5, via F08, and TB4 → TB7 → TB5, via F13 and F14.

## 3. Identity flows in scope

| Flow | Source → Destination | Data / credential | Identity used | Boundary crossed |
|---|---|---|---|---|
| F01 | User → User Interface | User interaction, credentials typed at login | Human user | None (inside TB1) |
| F02 | User Interface ↔ Auth0 | OIDC authorize with PKCE / code callback | Human user, Web App client ID | TB1 → TB2 |
| F03 | Auth0 ↔ Chatbot Backend | Auth code + verifier exchange; ID and access tokens | Web App client (confidential) | TB2 → TB3 |
| F04 | User Interface → Chatbot Backend | Chat request with session cookie; response | Human user session | TB1 → TB3 |
| F05 | Chatbot Backend → AI Chatbot Harness | Request + validated user context; response | User context + agent identity (`agent_id`) | TB3 → TB4 |
| F06 | Chatbot Backend ↔ Chat Session DB | Read/write session and chat history | Backend service DB identity | None (inside TB3) |
| F07 | Secrets Manager → AI Chatbot Harness | M2M client credential + LLM API key | Agent workload identity | TB3 → TB4 |
| F08 | AI Chatbot Harness → Internal REST APIs | M2M access token + least-privilege scope | OAuth M2M client (AI agent) | TB4 → TB5 |
| F09 | AI Chatbot Harness → LLM Provider | Prompt over TLS with key in auth header; model response | LLM API key | TB4 → TB8 |
| F10 | AI Chatbot Harness → RAG Service | Query with agent identity; retrieved text | Agent identity → RAG service identity | TB4 → TB6 |
| F11 | RAG Service → Embedding Service | Embedding request and response | RAG service identity | None (inside TB6) |
| F12 | RAG Service ↔ Vector Store | Scoped search; retrieved chunks | RAG service identity | None (inside TB6) |
| F13 | AI Chatbot Harness → MCP Server | Tool request with agent identity; result | Agent identity → MCP server identity | TB4 → TB7 |
| F14 | MCP Server → Internal REST APIs | Tool call with MCP identity; tool result | MCP server identity (M2M) | TB7 → TB5 |

---

## 4. STRIDE matrix (flow by flow)

### F01 — User → User Interface (human user, inside TB1)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F01-S | S | A phishing or look-alike chat UI harvests the user's password and TOTP code, and the attacker then signs in as that user. | Collect credentials only on Auth0 Universal Login, never in the app UI. Enforce TOTP MFA, brute-force protection, and Suspicious IP Throttling. Use a custom domain and train users. | Medium | IAM | Open |
| T-F01-T | T | XSS or a malicious browser extension changes chat input, or submits injected prompts in the user's name. | Strict CSP with no inline script, Subresource Integrity (SRI), output encoding, and Trusted Types. | Medium | Frontend | Open |
| T-F01-R | R | A user denies typing a harmful prompt that triggered an agent action. | Attribution is captured server-side on F04 (user `sub`, session ID, prompt hash, timestamp). | Low | SecOps | Open |
| T-F01-I | I | Tokens kept in `localStorage`, or chat content left on a shared device, can be read by XSS or the next user. | Backend-for-frontend pattern: tokens stay server-side, cookies are HttpOnly, idle auto-logout applies, and nothing sensitive goes in browser storage. | Medium | Frontend | Open |
| T-F01-D | D | **N/A.** This interaction stays on the user's own device, with no shared resource to exhaust. Service-level DoS is covered on F02 and F04. | — | — | — | N/A |
| T-F01-E | E | **N/A.** No privilege boundary is crossed: the user acts only with their own rights. Privilege checks happen at F04, F05, and F08. | — | — | — | N/A |

### F02 — User Interface ↔ Auth0 (OIDC authorize + PKCE / callback, TB1 → TB2)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F02-S | S | Login CSRF or callback injection: an attacker's authorization code is injected into the victim's browser, or an open redirect sends the code to an attacker-controlled URL. | Exact-match Allowed Callback URLs, `state` and `nonce` checks, HTTPS only, and no wildcard redirect URIs. | High | IAM | Open |
| T-F02-T | T | Authorization request tampering: `code_challenge` is removed (PKCE downgrade), the `redirect_uri` is changed, or `write:admin` is added to `scope`. | Require PKCE with S256. Scopes are granted by Auth0 RBAC, not by what the client requests, and `write:admin` is issued only to the admin role. | High | IAM | Open |
| T-F02-R | R | A user disputes a login or MFA event (for example, "that wasn't me"). | Stream Auth0 tenant logs (login success/failure, MFA enrol/challenge) to the SIEM with retention. | Low | SecOps | Open |
| T-F02-I | I | The authorization code leaks through `Referer`, browser history, or proxy logs. | Single-use, short-lived codes. PKCE makes a leaked code useless without the verifier. Set `Referrer-Policy: no-referrer` and use `response_mode=form_post`. | Medium | IAM | Open |
| T-F02-D | D | Credential stuffing or login floods lock out legitimate users and exhaust Auth0 rate limits. | Brute-force protection (10 attempts, 15-minute block), Suspicious IP Throttling, and Bot Detection. | Medium | IAM | Open |
| T-F02-E | E | MFA is bypassed, or a self-signup/account-linking path grants elevated roles. | Enforce MFA for all users through policy or an Action. Restrict public signup so new users get only the `user` role. Admin roles are assigned only by tenant admins. | High | IAM | Open |

### F03 — Auth0 ↔ Chatbot Backend (code exchange; ID/access tokens, TB2 → TB3)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F03-S | S | The backend accepts a forged token (`alg=none`, HS256/RS256 key confusion) or a token issued for another tenant or audience. | Verify RS256 signatures against the Auth0 JWKS, pin the algorithm, and check `iss`, `aud`, `exp`, `nbf`, and the ID-token `nonce`. | High | Backend | Open |
| T-F03-T | T | JWT claims (`scope`, `agent_id`, roles) are edited to gain access. | Use claims only after the signature is verified. Reject unsigned tokens and tokens with unknown `kid` values. | High | Backend | Open |
| T-F03-R | R | There is no way to prove which token was issued to which session or client. | Correlate Auth0 `seacft` (code exchange) logs with backend logs using `sub`, `client_id`, `jti`, and session ID. | Low | SecOps | Open |
| T-F03-I | I | The client secret or tokens are written to application logs, or the ID token over-shares PII. | Keep the client secret in Secrets Manager, scrub `Authorization` headers and tokens from logs, use minimal claims, and require TLS 1.2+. | Medium | Backend | Open |
| T-F03-D | D | An Auth0 outage, rate limiting, or a failed JWKS fetch blocks every login and token validation. | Cache JWKS with refresh-on-unknown-`kid`, retry with exponential backoff, and fail closed with a clear error. | Low | SRE | Open |
| T-F03-E | E | The backend accepts an ID token as an API access token, or long-lived tokens extend the attack window. | APIs accept only access tokens with the correct `aud`. Set access-token TTL to 300 s and turn on refresh-token rotation with reuse detection. | High | IAM | Open |

### F04 — User Interface → Chatbot Backend (chat request + session cookie, TB1 → TB3)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F04-S | S | Session hijacking with a stolen cookie, or CSRF sends chat requests as the victim. | Cookies set to `HttpOnly; Secure; SameSite=Strict`, anti-CSRF token, session rotation at login, and short idle/absolute timeouts. | High | Backend | Open |
| T-F04-T | T | The client injects `role`/`user_id` fields into the request body, or embeds a direct prompt injection. | Take identity only from the server-side session and ignore client-supplied identity fields. Validate the request schema and run input guardrails. | High | Backend | Open |
| T-F04-R | R | A user denies sending the prompt that led to an agent action. | Write a tamper-evident audit log of `sub`, session ID, request ID, prompt hash, and timestamp. | Medium | SecOps | Open |
| T-F04-I | I | IDOR on a conversation ID exposes another user's chat, or verbose errors or model output leak secrets. | Check conversation ownership, return generic errors, and run an output guardrail that redacts JWT-shaped strings. | High | Backend | Open |
| T-F04-D | D | Prompt flooding or oversized prompts burn the LLM budget ("denial of wallet"). | Per-user rate limits, a maximum input-token count, a WAF, and request body size limits. | Medium | SRE | Open |
| T-F04-E | E | A user-level session reaches admin functions through hidden endpoints, or by asking the agent to act as admin. | Server-side RBAC (`read:ai-data` vs `write:admin`) returns 403. The agent never gets more privilege than the calling user. | High | Backend / IAM | Open |

### F05 — Chatbot Backend → AI Chatbot Harness (validated user context, TB3 → TB4)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F05-S | S | An attacker skips the backend and calls the harness directly with a forged user context. | Network policy so only the backend can reach the harness. Mutual TLS, or an Ed25519-signed context envelope verified by the harness. | High | Platform | Open |
| T-F05-T | T | User context (`sub`, roles) is changed in transit, or user text mixed into the prompt overrides the system instructions. | Send user context as signed structured metadata, kept separate from the prompt. Make the system prompt immutable and use input guardrails. | High | AI Eng | Open |
| T-F05-R | R | Agent actions cannot be traced back to the originating user (confused-deputy audit gap). | Pass request ID, user `sub`, and `agent_id` to every downstream call and log them at each hop. | High | SecOps | Open |
| T-F05-I | I | The system prompt, or credentials embedded in it, is extracted and returned to the user (LLM07). | No secrets in the system prompt, an output guardrail, and canary strings to detect leakage. | High | AI Eng | Open |
| T-F05-D | D | Agent reasoning or tool-call loops use up compute and tokens. | Maximum agent steps, a per-request timeout, and a token budget per conversation. | Medium | AI Eng | Open |
| T-F05-E | E | The agent acts with its own M2M privileges instead of the user's, so users gain indirect access (confused deputy). | Authorize downstream actions against the intersection of user scope and agent scope, using token exchange / on-behalf-of with an `act` claim. | High | IAM | Open |

### F06 — Chatbot Backend ↔ Chat Session DB (inside TB3)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F06-S | S | Another service connects with shared database credentials and poses as the backend. | Per-service DB identity (IAM authentication), network ACLs, and no shared DB accounts. | Medium | Platform | Open |
| T-F06-T | T | Stored chat history is edited to plant a persistent prompt injection (memory poisoning). | Only the backend has write access, all queries are parameterized, history is treated as untrusted when re-prompting, and records carry an integrity hash. | Medium | Backend | Open |
| T-F06-R | R | Chat history is deleted or changed without a trace. | DB audit logging and an append-only audit table. | Low | SecOps | Open |
| T-F06-I | I | A DB breach or backup leak exposes transcripts that contain PII or tokens. | Encryption at rest, redact tokens before writing, retention limits, and per-user row-level access. | High | Platform | Open |
| T-F06-D | D | Very large transcripts or abusive volume exhaust storage. | Message size caps, per-user quotas, and retention and purge jobs. | Low | SRE | Open |
| T-F06-E | E | SQL injection through chat content gives DB admin rights. | Parameterized queries and a least-privilege DB role (DML only, no DDL). | Medium | Backend | Open |

### F07 — Secrets Manager → AI Chatbot Harness (M2M credential + LLM API key, TB3 → TB4)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F07-S | S | Another workload impersonates the harness to read its secrets. | Workload identity (cloud IAM role / SPIFFE), with each secret's access policy bound to the harness identity only. | High | Platform | Open |
| T-F07-T | T | A secret is replaced with an attacker-controlled value, for example to route LLM traffic to the attacker's account. | Restrict write access, version secrets, and alert on every secret change. | Medium | Platform | Open |
| T-F07-R | R | No record of who read or rotated a secret. | Send Secrets Manager access logs to the SIEM. | Medium | SecOps | Open |
| T-F07-I | I | The LLM API key or M2M secret is loaded into env vars or prompt context and exfiltrated through prompt injection (Attack Tree 1). | Never put secrets in model context; they stay only inside the HTTP client. Use short-lived M2M tokens, rotate keys at least every 90 days, and redact output. | High | Platform / AI Eng | Open |
| T-F07-D | D | If Secrets Manager is unavailable, the agent cannot authenticate. | In-memory cache with a TTL, a highly available secrets service, and alerting. | Low | SRE | Open |
| T-F07-E | E | The harness has wildcard read access to every secret, so one compromise exposes all credentials. | Least-privilege policy per secret path, reviewed quarterly. | High | Platform | Open |

### F08 — AI Chatbot Harness → Internal REST APIs (M2M token + scope, TB4 → TB5)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F08-S | S | A stolen M2M token or client secret lets an attacker pose as the agent (Attack Tree 2). | TTL of 60–300 s, `private_key_jwt` or mTLS sender-constrained tokens, a source-IP allow-list, and an alert on token reuse after expiry. | High | IAM | Open |
| T-F08-T | T | A prompt-injected agent changes API parameters, for example the customer ID or amount. | Per-object authorization on the server against the propagated user context, plus strict parameter validation. | High | API owner | Open |
| T-F08-R | R | The API cannot tell whether the agent acted for user A or user B. | Log `client_id`, `agent_id`, user `sub` (`act` claim), scope, and request ID on every call. | High | SecOps | Open |
| T-F08-I | I | The API returns more data than needed, and that data then flows into the LLM. | Field-level filtering, data minimization, and scope-based response shaping. | Medium | API owner | Open |
| T-F08-D | D | A spike in agent call volume overwhelms internal APIs. | Per-client rate limits, plus an alert when there are more than 20 requests in 60 s. | Medium | SRE | Open |
| T-F08-E | E | The agent's M2M client has `write:admin`, or its scope changes between consecutive requests. | Grant the M2M client only the scopes it needs, enforce scope at the API, and alert on scope change. | High | IAM | Open |

### F09 — AI Chatbot Harness → LLM Provider (prompt + API key, TB4 → TB8)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F09-S | S | A DNS or proxy misconfiguration sends prompts to a fake LLM endpoint, or a stolen key lets someone pose as SecureNova to the provider. | TLS certificate validation, a fixed provider hostname, an egress allow-list, and provider-side key restrictions. | Medium | Platform | Open |
| T-F09-T | T | A man-in-the-middle changes model responses in transit. | TLS 1.2+, treat model output as untrusted, and validate every tool call it proposes. | Low | Platform | Open |
| T-F09-R | R | LLM usage and cost cannot be attributed to a user or agent. | Separate keys per environment, request IDs and user tags in provider metadata, and usage logs in the SIEM. | Medium | SecOps | Open |
| T-F09-I | I | Prompts send PII, tokens, or the system prompt to a third party, which may retain them. | Minimize and redact data before sending, and use a zero-retention agreement / DPA with the provider. | High | Platform / Privacy | Open |
| T-F09-D | D | Abuse exhausts the provider's rate limit or quota (denial of wallet). | Spend budgets and quotas, a circuit breaker, and a fallback model. | Medium | SRE | Open |
| T-F09-E | E | Model output tells the harness to call privileged tools or APIs (excessive agency, LLM06). | A tool allow-list per user role, a policy engine outside the LLM, and human approval for privileged actions. | High | AI Eng | Open |

### F10 — AI Chatbot Harness → RAG Service (query / retrieved text, TB4 → TB6)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F10-S | S | An unauthenticated caller queries the RAG service directly, or the harness claims a different user to get their documents. | RAG requires an agent workload token, and per-user ACL filters come only from the verified context. | Medium | RAG | Open |
| T-F10-T | T | Queries are crafted to pull poisoned chunks, or retrieved text is changed in transit. | TLS, provenance-tagged and hash-verified chunks, and content sanitization. | Medium | RAG | Open |
| T-F10-R | R | No record of which chunks shaped an answer or action. | Log chunk ID, source document, and version for every request. | Medium | SecOps | Open |
| T-F10-I | I | Semantic search leaks documents across users or tenants. | Enforce document-level ACLs at retrieval with metadata filters, never only in the prompt. | High | RAG | Open |
| T-F10-D | D | Expensive queries (large top-k, long text) slow the service down. | Cap top-k and query length, and set timeouts and rate limits. | Low | SRE | Open |
| T-F10-E | E | A retrieved chunk carries instructions the agent follows to escalate its actions (indirect prompt injection, Attack Tree 3). | Treat chunks as data (spotlighting/delimiters) and run input guardrails on retrieved text. Privileged actions need authorization outside the LLM. | High | AI Eng | Open |

### F11 — RAG Service → Embedding Service (inside TB6)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F11-S | S | A rogue embedding endpoint is substituted for the real one. | Fixed endpoint configuration, plus mTLS or API-key auth between services. | Low | RAG | Open |
| T-F11-T | T | Embedding vectors or the model version are manipulated to steer retrieval. | Pin the model version, use integrity-checked deployments, and use TLS. | Low | RAG | Open |
| T-F11-R | R | Nobody can tell which embedding model version indexed a chunk. | Record the embedding model ID and version with every indexed chunk. | Low | RAG | Open |
| T-F11-I | I | Document text is sent to a third-party embedding API. | Use a self-hosted or approved provider, and redact sensitive fields before embedding. | Medium | RAG / Privacy | Open |
| T-F11-D | D | An embedding service outage blocks both retrieval and ingestion. | Retries, a query-embedding cache, and a queue for ingestion. | Low | SRE | Open |
| T-F11-E | E | **N/A.** The embedding service is a stateless transform that only returns vectors. It makes no authorization decisions and has no privileged operations. | — | — | — | N/A |

### F12 — RAG Service ↔ Vector Store (inside TB6)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F12-S | S | An unauthorized writer poses as the ingestion pipeline and inserts chunks. | Separate identities for querying (read) and ingestion (write), with authentication enforced on the vector DB. | High | RAG | Open |
| T-F12-T | T | Chunk poisoning: malicious instructions are inserted or edited in the store (Attack Tree 3). | Ingestion review and content scanning, signed chunk hashes checked at retrieval, and provenance metadata. | High | RAG | Open |
| T-F12-R | R | No one can tell who inserted or changed a chunk. | Store author, source, and ingest time on each chunk, with audit logs on writes. | Medium | SecOps | Open |
| T-F12-I | I | The vector store is exposed, or embeddings are inverted to reconstruct the source text. | Private network, authentication, and encryption at rest. | Medium | Platform | Open |
| T-F12-D | D | The index is deleted or corrupted. | Snapshots and backups, restricted delete rights, and a tested restore. | Medium | SRE | Open |
| T-F12-E | E | The RAG query identity has write or admin rights on the store. | Give the query path a read-only role. Only the ingestion identity can write. | Medium | RAG | Open |

### F13 — AI Chatbot Harness → MCP Server (tool request with agent identity, TB4 → TB7)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F13-S | S | A rogue or look-alike MCP server or tool is registered (tool shadowing), or a caller poses as the agent to the MCP server. | MCP server allow-list with a pinned identity (mTLS/OAuth). The agent authenticates with a signed, audience-bound token. | High | Platform / AI Eng | Open |
| T-F13-T | T | A tool manifest or description is poisoned, or injected content changes tool arguments. | Pin and hash tool manifests, validate arguments against a JSON schema, and Ed25519-sign agent messages. | High | AI Eng | Open |
| T-F13-R | R | A tool invocation cannot be traced to the agent or user who triggered it. | Log tool name, argument hash, `agent_id`, user `sub`, request ID, and result. | High | SecOps | Open |
| T-F13-I | I | Tool results containing secrets go back into the LLM context, or the MCP server logs tokens. | Filter and redact tool results, and never pass tokens through. | Medium | AI Eng | Open |
| T-F13-D | D | Long-running or hanging tools block the agent. | Per-tool timeouts and concurrency caps. | Low | SRE | Open |
| T-F13-E | E | A poisoned chunk triggers a privileged MCP tool, such as a refund or delete. | Per-tool scopes, deny by default, and human-in-the-loop approval for destructive tools. | High | IAM / AI Eng | Open |

### F14 — MCP Server → Internal REST APIs (tool call with MCP identity, TB7 → TB5)

| ID | Cat | Threat | Mitigation | Sev | Owner | Status |
|---|---|---|---|---|---|---|
| T-F14-S | S | The MCP server uses a shared or static credential, which an attacker steals to pose as the MCP server. | A dedicated M2M client for the MCP server, with short-TTL, sender-constrained tokens. | High | IAM | Open |
| T-F14-T | T | The MCP server rewrites requests beyond what the agent asked for. | The API validates each request against the propagated user and agent context, and requests are signed. | Medium | API owner | Open |
| T-F14-R | R | API logs show only the MCP identity, so the user → agent → tool chain is lost. | Pass the actor chain (RFC 8693 `act` claim) and request ID, and log them at the API. | High | SecOps | Open |
| T-F14-I | I | The API returns more data than the MCP tool needs. | Data minimization and scope-limited fields. | Medium | API owner | Open |
| T-F14-D | D | A storm of tool calls overloads internal APIs. | Rate limits per MCP client, plus a circuit breaker. | Medium | SRE | Open |
| T-F14-E | E | Token passthrough: the MCP server forwards the agent's token, or uses its own broader rights (confused deputy). | No token passthrough. The MCP server gets an audience-specific token through token exchange, with scopes no wider than the caller's. | High | IAM | Open |

---

## 5. Summary

### Coverage

| Category | Threats | N/A | High | Medium | Low |
|---|---|---|---|---|---|
| Spoofing | 14 | 0 | 9 | 4 | 1 |
| Tampering | 14 | 0 | 7 | 5 | 2 |
| Repudiation | 14 | 0 | 4 | 5 | 5 |
| Information disclosure | 14 | 0 | 6 | 8 | 0 |
| Denial of service | 13 | 1 | 0 | 7 | 6 |
| Elevation of privilege | 12 | 2 | 10 | 2 | 0 |
| **Total** | **81** | **3** | **36** | **31** | **14** |

All 84 flow-category cells (14 flows × 6 categories) are assessed.

### Highest-concentration risk areas (input to attack trees and the risk register)

1. **Credential exposure to the model:** T-F07-I, T-F05-I, T-F09-I → Attack Tree 1 (LLM API key exfiltration via prompt injection).
2. **Agent identity and scope abuse:** T-F08-S, T-F08-E, T-F05-E, T-F14-E → Attack Tree 2 (agent identity spoofing to gain elevated API scope).
3. **Untrusted retrieved content driving actions:** T-F12-T, T-F10-E, T-F13-E → Attack Tree 3 (RAG chunk poisoning).
4. **Non-human identity audit gaps:** T-F05-R, T-F08-R, T-F13-R, T-F14-R. Propagating the `act` claim and request ID end to end addresses the "lack of audit trails for non-human identities" concern.
