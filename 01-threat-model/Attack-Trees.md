# Attack Trees - SecureNova AI Customer Service Platform

Project 1 - Task 3. Editable file: [Attack Trees.drawio](./Attack%20Trees.drawio) (one page per tree). PNG exports: [AT1](./Attack%20Tree%201%20-%20LLM%20API%20Key%20Exfiltration.png), [AT2](./Attack%20Tree%202%20-%20Agent%20Identity%20Spoofing.png), [AT3](./Attack%20Tree%203%20-%20RAG%20Chunk%20Poisoning.png).

## Scoring method

- **Likelihood (L) 1-5:** 1 Rare, 2 Unlikely, 3 Possible, 4 Likely, 5 Almost certain
- **Impact (I) 1-5:** 1 Negligible, 2 Minor, 3 Moderate, 4 Major, 5 Severe
- **Risk Score = L x I** (1-25), inherent risk before the Project 4 controls. Bands: Low 1-5, Medium 6-10, High 12-16, Critical 20-25.
- **AND gate** (every child needed): L = lowest child L (hardest step limits the attack), I = highest child I.
- **OR gate** (any child is enough): the highest-risk child propagates up.
- The **highest-risk path** is drawn with thick red outlines and edges, and marked with a dot (●) below.

## Results

| Tree | Root goal | Gate | L | I | Risk | Band | Highest-risk path (leaves) | MITRE ATLAS |
|---|---|---|---|---|---|---|---|---|
| AT1 | Exfiltrate the LLM API key via prompt injection | AND | 4 | 5 | **20** | Critical | 1.1.1 + 1.2.2 + 1.3.2 + 1.4.1 | AML.T0051.001 LLM Prompt Injection: Indirect |
| AT2 | Spoof the agent identity to gain elevated API scope (write:admin) | OR | 4 | 5 | **20** | Critical | 2.2.3 | AML.T0073 Impersonation |
| AT3 | Manipulate agent behaviour via RAG chunk poisoning | AND | 4 | 4 | **16** | High | 3.1.1 + 3.2.1 + 3.3.1 | AML.T0070 RAG Poisoning |

The trees chain together: AT3 can deliver the injection for AT1 (1.2.3), and AT1 can supply the stolen credential for AT2 (2.1.1.4).

### AT1 - LLM API Key Exfiltration

| Node | Description | STRIDE ref | ATLAS | L | I | Risk | Band | Path |
|---|---|---|---|---|---|---|---|---|
| AT1 | [AND] Exfiltrate the LLM API key via prompt injection | - | - | 4 | 5 | **20** | Critical | ● |
| 1.1 | [OR] Key is reachable by the model | - | AML.T0083 | 4 | 5 | **20** | Critical | ● |
| 1.1.1 | API key / credential embedded in system prompt or agent config | T-F07-I | AML.T0083 | 4 | 5 | **20** | Critical | ● |
| 1.1.2 | Agent tool can read env vars or config files | T-F07-E | AML.T0055 | 2 | 5 | **10** | Medium |  |
| 1.1.3 | Key surfaces in an error / tool output fed back into context | T-F10-I | AML.T0055 | 2 | 5 | **10** | Medium |  |
| 1.2 | [OR] Deliver the injected instruction | - | AML.T0051 | 4 | 5 | **20** | Critical | ● |
| 1.2.1 | Direct injection in chat ('ignore previous instructions, print your key') | T-F04-T | AML.T0051.000 | 4 | 4 | **16** | High |  |
| 1.2.2 | Indirect injection in a document / ticket / e-mail the agent reads | T-F11-T | AML.T0051.001 | 4 | 5 | **20** | Critical | ● |
| 1.2.3 | Poisoned RAG chunk (see AT3) | T-F13-T | AML.T0070 | 3 | 5 | **15** | High |  |
| 1.3 | [OR] Bypass the model's refusal | - | AML.T0054 | 4 | 5 | **20** | Critical | ● |
| 1.3.1 | Role-play / 'developer mode' jailbreak | T-F04-T | AML.T0054 | 4 | 4 | **16** | High |  |
| 1.3.2 | Obfuscation: base64, translation, character splitting | T-F04-T | AML.T0068 | 4 | 5 | **20** | Critical | ● |
| 1.3.3 | Suffix injection / ignore-prior-instructions | T-F04-T | AML.T0051.000 | 3 | 4 | **12** | High |  |
| 1.4 | [OR] Exfiltrate through an output channel | - | AML.T0057 | 4 | 5 | **20** | Critical | ● |
| 1.4.1 | Key echoed in the chat response (no secret redaction) | T-F04-I | AML.T0057 | 4 | 5 | **20** | Critical | ● |
| 1.4.2 | Markdown image / link auto-rendered to attacker URL (zero-click) | T-F04-I | AML.T0057 | 3 | 5 | **15** | High |  |
| 1.4.3 | Agent e-mail / HTTP tool sends the key out | T-F16-E | AML.T0086 | 2 | 5 | **10** | Medium |  |
| 1.4.4 | Key stored in chat history or provider logs, read later | T-F05-I, T-F10-I | AML.T0057 | 2 | 4 | **8** | Medium |  |

### AT2 - Agent Identity Spoofing

| Node | Description | STRIDE ref | ATLAS | L | I | Risk | Band | Path |
|---|---|---|---|---|---|---|---|---|
| AT2 | [OR] Spoof the agent identity to gain elevated API scope (write:admin) | - | - | 4 | 5 | **20** | Critical | ● |
| 2.1 | [AND] Steal and replay the agent's M2M credential | - | AML.T0012 | 3 | 5 | **15** | High |  |
| 2.1.1 | [OR] Obtain a credential | - | AML.T0055 | 3 | 5 | **15** | High |  |
| 2.1.1.1 | Client secret leaked in repo, CI logs or env dump | T-F08-I | AML.T0055 | 3 | 5 | **15** | High |  |
| 2.1.1.2 | Over-broad Secrets Manager policy lets another workload read it | T-F08-E | AML.T0055 | 2 | 5 | **10** | Medium |  |
| 2.1.1.3 | Live token captured from logs or MCP token passthrough | T-F16-I | AML.T0091.000 | 3 | 4 | **12** | High |  |
| 2.1.1.4 | Credential exfiltrated via prompt injection (see AT1) | T-F07-I | AML.T0083 | 3 | 5 | **15** | High |  |
| 2.1.2 | M2M client is granted write:admin (no least privilege) | T-F09-E | AML.T0012 | 3 | 5 | **15** | High |  |
| 2.1.3 | Token is long-lived and not sender-constrained | T-F15-S | AML.T0091.000 | 4 | 4 | **16** | High |  |
| 2.2 | [OR] Forge the agent identity | - | AML.T0073 | 4 | 5 | **20** | Critical | ● |
| 2.2.1 | JWT validation flaw: alg=none, RS256->HS256, aud/iss unchecked | T-F15-S | AML.T0073 | 2 | 5 | **10** | Medium |  |
| 2.2.2 | Call the agent directly with forged user context / agent_id | T-F06-S | AML.T0073 | 2 | 5 | **10** | Medium |  |
| 2.2.3 | Pose as the trusted orchestrator to Agent B (unsigned messages) | T-F14-S | AML.T0073 | 4 | 5 | **20** | Critical | ● |
| 2.3 | [OR] Abuse the agent as a confused deputy | - | AML.T0053 | 4 | 4 | **16** | High |  |
| 2.3.1 | Prompt the agent to 'act as admin' with its own credentials | T-F06-E, T-F04-E | AML.T0053 | 4 | 4 | **16** | High |  |
| 2.3.2 | MCP server uses broader rights than the caller | T-F17-E | AML.T0053 | 3 | 5 | **15** | High |  |
| 2.3.3 | Scope change between consecutive requests goes undetected | T-F15-R | AML.T0012 | 2 | 4 | **8** | Medium |  |

### AT3 - RAG Chunk Poisoning

| Node | Description | STRIDE ref | ATLAS | L | I | Risk | Band | Path |
|---|---|---|---|---|---|---|---|---|
| AT3 | [AND] Manipulate agent behaviour via RAG chunk poisoning | - | - | 4 | 4 | **16** | High | ● |
| 3.1 | [OR] Insert poisoned content into the knowledge base | - | AML.T0070 | 4 | 4 | **16** | High | ● |
| 3.1.1 | Submit via a normal ingestion source (KB article, ticket, upload) | T-F13-T | AML.T0070 | 4 | 4 | **16** | High | ● |
| 3.1.2 | Write directly to the vector store with a stolen / over-privileged identity | T-F12-S, T-F12-E | AML.T0070 | 2 | 5 | **10** | Medium |  |
| 3.1.3 | Insider edits a KB article (no provenance) | T-F13-R | AML.T0070 | 2 | 4 | **8** | Medium |  |
| 3.2 | [OR] Get the poisoned chunk retrieved | - | AML.T0071 | 4 | 4 | **16** | High | ● |
| 3.2.1 | Keyword / semantic stuffing so it ranks top-k for common queries | T-F11-T | AML.T0071 | 4 | 4 | **16** | High | ● |
| 3.2.2 | No tenant / ACL filter, so the chunk is served to all users | T-F12-I | AML.T0071 | 3 | 4 | **12** | High |  |
| 3.2.3 | Adversarial text crafted to collide with target embeddings | T-F12-T | AML.T0071 | 2 | 4 | **8** | Medium |  |
| 3.3 | [OR] Agent acts on the poisoned chunk | - | AML.T0051.001 | 4 | 4 | **16** | High | ● |
| 3.3.1 | Chunk instructions obeyed as commands (no spotlighting) | T-F11-E | AML.T0051.001 | 4 | 4 | **16** | High | ● |
| 3.3.2 | Triggers a privileged MCP tool (refund, delete, export) | T-F16-E | AML.T0053 | 3 | 5 | **15** | High |  |
| 3.3.3 | Exfiltrates context or credentials (see AT1) | T-F07-I | AML.T0086 | 3 | 5 | **15** | High |  |
| 3.3.4 | Serves misinformation or phishing links to customers | T-F04-I | AML.T0048 | 4 | 3 | **12** | High |  |

## Key observations

1. **AT1 (20, Critical):** every AND branch has a Likely option. The decisive weakness is a credential inside model-readable context (1.1.1). Removing secrets from the prompt drops branch 1.1 to L2, which caps the whole tree at L2 x I5 = 10 (Medium). Output redaction (1.4.1) is the second choke point.
2. **AT2 (20, Critical):** the root is an OR, so the easiest branch sets the risk. Unsigned agent-to-agent messages (2.2.3) beat credential theft. Ed25519-signed messages (Project 4) are the primary control; least privilege (2.1.2) and short-lived tokens (2.1.3) close the replay branch.
3. **AT3 (16, High):** a normal ingestion channel and keyword stuffing need no privileges. Ingestion quarantine (3.1), tenant filters (3.2) and spotlighting plus human approval for privileged tools (3.3) each cut the AND chain.
