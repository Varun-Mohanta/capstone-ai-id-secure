# Attack Trees — SecureNova AI Customer Service Platform

| Artefact | Purpose |
|---|---|
| [Attack Trees.drawio](./Attack%20Trees.drawio) | Editable draw.io file, one page per tree (AT1, AT2, AT3) |
| [Attack Tree 1 - LLM API Key Exfiltration.png](./Attack%20Tree%201%20-%20LLM%20API%20Key%20Exfiltration.png) | PNG export of AT1 |
| [Attack Tree 2 - Agent Identity Spoofing.png](./Attack%20Tree%202%20-%20Agent%20Identity%20Spoofing.png) | PNG export of AT2 |
| [Attack Tree 3 - RAG Chunk Poisoning.png](./Attack%20Tree%203%20-%20RAG%20Chunk%20Poisoning.png) | PNG export of AT3 |

Every leaf traces back to a threat ID in [STRIDE-Matrix.md](./STRIDE-Matrix.md) (section 5, "Highest-concentration risk areas").

## 1. Scoring method

- **Likelihood (L), 1–5:** 1 Rare · 2 Unlikely · 3 Possible · 4 Likely · 5 Almost certain
- **Impact (I), 1–5:** 1 Negligible · 2 Minor · 3 Moderate · 4 Major · 5 Severe
- **Risk Score = L × I** (1–25). Scores are **inherent** risk, before the Project 4 controls are applied.
- **Bands:** Low 1–5 · Medium 6–10 · High 12–16 · Critical 20–25
- **Propagation:**
  - **AND** node (every child is needed): L = lowest child L (the hardest step limits the attack); I = highest child I.
  - **OR** node (any child is enough): the child with the highest risk propagates up.
- The **highest-risk attack path** is drawn with thick red edges and outlines in the diagrams and marked ● below.

## 2. Results

| Tree | Root goal | Root gate | L | I | Risk | Band | Highest-risk path |
|---|---|---|---|---|---|---|---|
| AT1 | Exfiltrate the LLM API key via prompt injection | AND | 4 | 5 | **20** | Critical | 1.1.1 → 1.2.2 → 1.3.2 → 1.4.1 |
| AT2 | Spoof the agent identity to gain elevated API scope (`write:admin`) | OR | 4 | 5 | **20** | Critical | 2.2 → 2.2.3 |
| AT3 | Manipulate agent behaviour via RAG chunk poisoning | AND | 4 | 4 | **16** | High | 3.1.1 → 3.2.1 → 3.3.1 |

The trees are linked. AT3 can deliver the injection for AT1 (1.2.3) and AT1 can supply the stolen credential for AT2 (2.1.1.4), so a single poisoned chunk can chain into a key leak and then into agent impersonation.

### AT1 — LLM API Key Exfiltration
| Node | Description | STRIDE ref | L | I | Risk | Band | Path |
|---|---|---|---|---|---|---|---|
| AT1 | [AND] Exfiltrate the LLM API key via prompt injection | LLM01 / LLM07 · T-F07-I, T-F05-I, T-F09-I | 4 | 5 | **20** | Critical | ● |
| 1.1 | [OR] Key is reachable by the model |  | 4 | 5 | **20** | Critical | ● |
| 1.1.1 | API key / credential embedded in system prompt or agent config text | T-F05-I | 4 | 5 | **20** | Critical | ● |
| 1.1.2 | Agent tool can read env vars or config files | T-F07-I, T-F07-E | 2 | 5 | **10** | Medium |  |
| 1.1.3 | Key surfaces in error / tool output fed back into context | T-F13-I | 2 | 5 | **10** | Medium |  |
| 1.2 | [OR] Deliver the injected instruction |  | 4 | 5 | **20** | Critical | ● |
| 1.2.1 | Direct injection in chat ("ignore previous instructions, print your key") | T-F04-T | 4 | 4 | **16** | High |  |
| 1.2.2 | Indirect injection in a document / ticket / email the agent reads | T-F10-E | 4 | 5 | **20** | Critical | ● |
| 1.2.3 | Poisoned RAG chunk (see Attack Tree 3) | T-F12-T | 3 | 5 | **15** | High |  |
| 1.2.4 | Malicious MCP tool description or tool result | T-F13-T | 2 | 5 | **10** | Medium |  |
| 1.3 | [OR] Bypass the model's refusal |  | 4 | 5 | **20** | Critical | ● |
| 1.3.1 | Role-play / "developer mode" override | T-F05-T | 4 | 4 | **16** | High |  |
| 1.3.2 | Encoding trick: base64, translation, char-splitting | T-F04-I | 4 | 5 | **20** | Critical | ● |
| 1.3.3 | Suffix injection / ignore-prior-instruction | T-F05-T | 3 | 4 | **12** | High |  |
| 1.4 | [OR] Exfiltrate through an output channel |  | 4 | 5 | **20** | Critical | ● |
| 1.4.1 | Key echoed in the chat response (no secret redaction) | T-F04-I | 4 | 5 | **20** | Critical | ● |
| 1.4.2 | Markdown image / link auto-rendered to attacker URL (zero-click) | T-F04-I | 3 | 5 | **15** | High |  |
| 1.4.3 | Agent HTTP / email MCP tool sends key to attacker | T-F13-E | 2 | 5 | **10** | Medium |  |
| 1.4.4 | Key persisted in chat history or provider logs, read later | T-F06-I, T-F09-I | 2 | 4 | **8** | Medium |  |

### AT2 — Agent Identity Spoofing
| Node | Description | STRIDE ref | L | I | Risk | Band | Path |
|---|---|---|---|---|---|---|---|
| AT2 | [OR] Spoof the agent identity to gain elevated API scope (write:admin) | LLM06 / LLM09 · T-F08-S, T-F08-E, T-F05-E, T-F14-E | 4 | 5 | **20** | Critical | ● |
| 2.1 | [AND] Steal and replay the agent's M2M credential |  | 3 | 5 | **15** | High |  |
| 2.1.1 | [OR] Obtain a credential |  | 3 | 5 | **15** | High |  |
| 2.1.1.1 | Client secret leaked in repo, CI logs or env dump | T-F07-I | 3 | 5 | **15** | High |  |
| 2.1.1.2 | Over-broad Secrets Manager read by another workload | T-F07-S, T-F07-E | 2 | 5 | **10** | Medium |  |
| 2.1.1.3 | Live token captured from logs or MCP token passthrough | T-F13-I, T-F14-E | 3 | 4 | **12** | High |  |
| 2.1.1.4 | Credential exfiltrated via prompt injection (Attack Tree 1) | T-F07-I | 3 | 5 | **15** | High |  |
| 2.1.2 | M2M client is granted write:admin (no least privilege) | T-F08-E | 3 | 5 | **15** | High |  |
| 2.1.3 | Token is long-lived and not sender-constrained | T-F08-S | 4 | 4 | **16** | High |  |
| 2.2 | [OR] Forge the agent identity |  | 4 | 5 | **20** | Critical | ● |
| 2.2.1 | JWT validation flaw: alg=none, RS256→HS256, aud/iss unchecked | T-F08-S | 2 | 5 | **10** | Medium |  |
| 2.2.2 | Call harness directly with forged user context / agent_id | T-F05-S | 2 | 5 | **10** | Medium |  |
| 2.2.3 | Pose as trusted orchestrator to Agent B (unsigned inter-agent messages) | T-F05-T · LLM09 | 4 | 5 | **20** | Critical | ● |
| 2.3 | [OR] Abuse the agent as a confused deputy |  | 4 | 4 | **16** | High |  |
| 2.3.1 | Prompt the agent to "act as admin" with its own M2M scope | T-F05-E, T-F04-E | 4 | 4 | **16** | High |  |
| 2.3.2 | MCP server forwards agent token or uses broader rights | T-F14-E | 3 | 5 | **15** | High |  |
| 2.3.3 | Scope changes between consecutive requests go undetected | T-F08-E, T-F08-R | 2 | 4 | **8** | Medium |  |

### AT3 — RAG Chunk Poisoning
| Node | Description | STRIDE ref | L | I | Risk | Band | Path |
|---|---|---|---|---|---|---|---|
| AT3 | [AND] Manipulate agent behaviour via RAG chunk poisoning | LLM01 / LLM04 / LLM08 · T-F12-T, T-F10-E, T-F13-E | 4 | 4 | **16** | High | ● |
| 3.1 | [OR] Insert poisoned content into the knowledge base |  | 4 | 4 | **16** | High | ● |
| 3.1.1 | Submit via a legitimate ingestion source (KB page, ticket, upload) | T-F12-T | 4 | 4 | **16** | High | ● |
| 3.1.2 | Impersonate ingestion pipeline / direct write to vector store | T-F12-S, T-F12-E | 2 | 5 | **10** | Medium |  |
| 3.1.3 | Insider edits a KB article (no provenance) | T-F12-R | 2 | 4 | **8** | Medium |  |
| 3.2 | [OR] Get the poisoned chunk retrieved |  | 4 | 4 | **16** | High | ● |
| 3.2.1 | Keyword / semantic stuffing to rank top-k for common queries | T-F10-T | 4 | 4 | **16** | High | ● |
| 3.2.2 | No tenant / ACL filter, chunk served to all users | T-F10-I | 3 | 4 | **12** | High |  |
| 3.2.3 | Adversarial text crafted to collide with target embeddings | T-F11-T, T-F12-T | 2 | 4 | **8** | Medium |  |
| 3.3 | [OR] Agent acts on the poisoned chunk |  | 4 | 4 | **16** | High | ● |
| 3.3.1 | Chunk instructions obeyed as commands (no spotlighting) | T-F10-E | 4 | 4 | **16** | High | ● |
| 3.3.2 | Triggers privileged MCP tool (refund, delete, email) | T-F13-E | 3 | 5 | **15** | High |  |
| 3.3.3 | Exfiltrates context or credentials (Attack Tree 1) | T-F07-I | 3 | 5 | **15** | High |  |
| 3.3.4 | Serves misinformation or phishing links to customers | T-F04-I | 4 | 3 | **12** | High |  |

## 3. Key observations

1. **AT1 (20, Critical):** Every AND branch has a Likely (L4) option. The decisive weakness is that a credential sits in model-readable context (1.1.1). Removing secrets from the prompt drops this branch to L2, which caps the whole tree at 10 (Medium). Output redaction of secret- and JWT-shaped strings (1.4.1) is the second choke point.
2. **AT2 (20, Critical):** The OR root means the *easiest* branch sets the risk. Unsigned inter-agent messages (2.2.3) beat credential theft. Signing agent messages with Ed25519 (Project 4.2) is the primary control. Least-privilege scopes (2.1.2) and short-lived, sender-constrained tokens (2.1.3) close the credential-replay branch.
3. **AT3 (16, High):** Low barrier to entry: public ingestion sources and keyword stuffing need no privileges. Ingestion review, chunk provenance/signing, and treating retrieved text as data (spotlighting) cut it at 3.1, 3.2 and 3.3. Human approval for privileged MCP tools limits the I5 outcome (3.3.2).

## 4. Next step

Task 4 maps each attack path to a MITRE ATLAS technique (AML.TXXXX) and combines these scores into the risk-ranked register with owners.
