# Risk Register - SecureNova AI Customer Service Platform

Project 1 - Task 4. All **100 scored threats** from the STRIDE matrix, ranked by Risk Score (Likelihood x Impact), each with an owner, MITRE ATLAS technique and planned control. Spreadsheet: [Risk-Register.xlsx](./Risk-Register.xlsx). Ties are ordered by higher Impact, then Threat ID.

**Summary:** 5 Critical, 27 High, 57 Medium, 11 Low.

| Owner | Threats owned |
|---|---|
| Platform engineering | 28 |
| AI engineering | 17 |
| IAM team | 16 |
| Security operations (SOC) | 16 |
| Application security | 13 |
| Knowledge-base owner | 9 |
| CISO (third-party risk) | 1 |

## Attack tree roots

| Tree | Root goal | Risk | ATLAS | Owner |
|---|---|---|---|---|
| AT1 | Exfiltrate the LLM API key via prompt injection | **20** Critical | AML.T0051.001 | AI engineering |
| AT2 | Spoof the agent identity to gain elevated API scope (write:admin) | **20** Critical | AML.T0073 | IAM team |
| AT3 | Manipulate agent behaviour via RAG chunk poisoning | **16** High | AML.T0070 | Knowledge-base owner |

## Ranked register

| Rank | Risk ID | Threat ID | STRIDE | Threat | L | I | Risk | Band | ATLAS | Attack tree | Owner |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | R-01 | T-F04-I | Information disclosure | Secret / PII in chat response | 4 | 5 | **20** | Critical | AML.T0057 | 1.4.1, 1.4.2, 3.3.4 | AI engineering |
| 2 | R-02 | T-F04-T | Tampering | Direct prompt injection | 4 | 5 | **20** | Critical | AML.T0051.000 | 1.2.1, 1.3.1, 1.3.2, 1.3.3 | AI engineering |
| 3 | R-03 | T-F07-I | Information disclosure | LLM key placed in model context | 4 | 5 | **20** | Critical | AML.T0083 | 1.1.1, 2.1.1.4, 3.3.3 | AI engineering |
| 4 | R-04 | T-F11-T | Tampering | Injected instructions in chunks | 4 | 5 | **20** | Critical | AML.T0051.001 | 1.2.2, 3.2.1 | AI engineering |
| 5 | R-05 | T-F14-S | Spoofing | Forged orchestrator message | 4 | 5 | **20** | Critical | AML.T0073 | 2.2.3 | AI engineering |
| 6 | R-06 | T-F02-S | Spoofing | Credential stuffing / brute force | 4 | 4 | **16** | High | AML.T0012 | - | IAM team |
| 7 | R-07 | T-F04-E | Elevation of privilege | Role claimed in chat text | 4 | 4 | **16** | High | AML.T0054 | 2.3.1 | Application security |
| 8 | R-08 | T-F06-E | Elevation of privilege | Agent acts as admin on request | 4 | 4 | **16** | High | AML.T0053 | 2.3.1 | AI engineering |
| 9 | R-09 | T-F11-E | Elevation of privilege | Retrieved text treated as command | 4 | 4 | **16** | High | AML.T0051.001 | 3.3.1 | AI engineering |
| 10 | R-10 | T-F13-T | Tampering | Poisoned KB content submitted | 4 | 4 | **16** | High | AML.T0070 | 1.2.3, 3.1.1 | Knowledge-base owner |
| 11 | R-11 | T-F15-S | Spoofing | Replayed / forged M2M token | 4 | 4 | **16** | High | AML.T0091.000 | 2.1.3, 2.2.1 | Application security |
| 12 | R-12 | T-F03-E | Elevation of privilege | Over-broad scopes in user token | 3 | 5 | **15** | High | - | - | IAM team |
| 13 | R-13 | T-F08-I | Information disclosure | M2M secret leaked | 3 | 5 | **15** | High | AML.T0055 | 2.1.1.1 | IAM team |
| 14 | R-14 | T-F09-E | Elevation of privilege | M2M client granted write:admin | 3 | 5 | **15** | High | AML.T0012 | 2.1.2 | IAM team |
| 15 | R-15 | T-F14-E | Elevation of privilege | Agent B runs privileged action for A | 3 | 5 | **15** | High | AML.T0053 | - | AI engineering |
| 16 | R-16 | T-F14-T | Tampering | Delegated task altered | 3 | 5 | **15** | High | - | - | AI engineering |
| 17 | R-17 | T-F16-E | Elevation of privilege | Privileged tool triggered by injection | 3 | 5 | **15** | High | AML.T0053 | 1.4.3, 3.3.2 | AI engineering |
| 18 | R-18 | T-F17-E | Elevation of privilege | MCP server has broader rights | 3 | 5 | **15** | High | AML.T0053 | 2.3.2 | IAM team |
| 19 | R-19 | T-F17-I | Information disclosure | Bulk export through MCP | 3 | 5 | **15** | High | AML.T0086 | - | Platform engineering |
| 20 | R-20 | T-F01-S | Spoofing | Phishing / look-alike login page | 3 | 4 | **12** | High | AML.T0052 | - | IAM team |
| 21 | R-21 | T-F03-I | Information disclosure | Tokens written to logs | 3 | 4 | **12** | High | - | - | Platform engineering |
| 22 | R-22 | T-F04-S | Spoofing | Session cookie hijack | 3 | 4 | **12** | High | AML.T0091.000 | - | Application security |
| 23 | R-23 | T-F10-E | Elevation of privilege | Stolen key used for full account | 3 | 4 | **12** | High | AML.T0012 | - | Platform engineering |
| 24 | R-24 | T-F10-T | Tampering | Model response manipulated | 3 | 4 | **12** | High | AML.T0051 | - | AI engineering |
| 25 | R-25 | T-F11-I | Information disclosure | Cross-tenant retrieval | 3 | 4 | **12** | High | AML.T0082 | - | Knowledge-base owner |
| 26 | R-26 | T-F12-I | Information disclosure | No tenant filter on search | 3 | 4 | **12** | High | - | 3.2.2 | Knowledge-base owner |
| 27 | R-27 | T-F13-S | Spoofing | Fake content source | 3 | 4 | **12** | High | AML.T0073 | - | Knowledge-base owner |
| 28 | R-28 | T-F14-R | Repudiation | Agent-to-agent chain not logged | 3 | 4 | **12** | High | - | - | Security operations (SOC) |
| 29 | R-29 | T-F15-I | Information disclosure | Over-broad API responses | 3 | 4 | **12** | High | AML.T0057 | - | Application security |
| 30 | R-30 | T-F16-I | Information disclosure | Agent token passed through | 3 | 4 | **12** | High | AML.T0091.000 | 2.1.1.3 | Platform engineering |
| 31 | R-31 | T-F16-T | Tampering | Poisoned tool description / result | 3 | 4 | **12** | High | AML.T0099 | - | AI engineering |
| 32 | R-32 | T-F17-R | Repudiation | Original caller lost | 3 | 4 | **12** | High | - | - | Security operations (SOC) |
| 33 | R-33 | T-F02-E | Elevation of privilege | MFA bypass or fatigue | 2 | 5 | **10** | Medium | - | - | IAM team |
| 34 | R-34 | T-F03-T | Tampering | Forged / substituted ID token | 2 | 5 | **10** | Medium | - | - | Application security |
| 35 | R-35 | T-F06-S | Spoofing | Forged user context to agent | 2 | 5 | **10** | Medium | AML.T0073 | 2.2.2 | Application security |
| 36 | R-36 | T-F07-E | Elevation of privilege | Agent tool reads env / config | 2 | 5 | **10** | Medium | AML.T0055 | 1.1.2 | AI engineering |
| 37 | R-37 | T-F07-S | Spoofing | Other workload reads LLM key | 2 | 5 | **10** | Medium | AML.T0055 | - | Platform engineering |
| 38 | R-38 | T-F08-E | Elevation of privilege | Over-broad secret access policy | 2 | 5 | **10** | Medium | AML.T0055 | 2.1.1.2 | Platform engineering |
| 39 | R-39 | T-F08-S | Spoofing | Other workload reads M2M secret | 2 | 5 | **10** | Medium | AML.T0055 | - | Platform engineering |
| 40 | R-40 | T-F09-S | Spoofing | Client-credentials impersonation | 2 | 5 | **10** | Medium | AML.T0012 | - | IAM team |
| 41 | R-41 | T-F10-I | Information disclosure | Key / data in provider logs | 2 | 5 | **10** | Medium | AML.T0057 | 1.1.3, 1.4.4 | CISO (third-party risk) |
| 42 | R-42 | T-F12-E | Elevation of privilege | Query identity can write | 2 | 5 | **10** | Medium | AML.T0070 | 3.1.2 | Platform engineering |
| 43 | R-43 | T-F12-S | Spoofing | Rogue writer to vector store | 2 | 5 | **10** | Medium | AML.T0070 | 3.1.2 | Platform engineering |
| 44 | R-44 | T-F13-I | Information disclosure | Secrets ingested into KB | 2 | 5 | **10** | Medium | AML.T0082 | - | Knowledge-base owner |
| 45 | R-45 | T-F15-E | Elevation of privilege | Scope not enforced on endpoint | 2 | 5 | **10** | Medium | AML.T0012 | - | Application security |
| 46 | R-46 | T-F17-S | Spoofing | MCP identity impersonation | 2 | 5 | **10** | Medium | AML.T0012 | - | IAM team |
| 47 | R-47 | T-F02-D | Denial of service | Login flood / lockout abuse | 3 | 3 | **9** | Medium | - | - | IAM team |
| 48 | R-48 | T-F04-D | Denial of service | Chat flood / cost exhaustion | 3 | 3 | **9** | Medium | AML.T0034 | - | Platform engineering |
| 49 | R-49 | T-F04-R | Repudiation | No prompt-to-action audit | 3 | 3 | **9** | Medium | - | - | Security operations (SOC) |
| 50 | R-50 | T-F06-D | Denial of service | Agent loop / runaway | 3 | 3 | **9** | Medium | AML.T0034.002 | - | AI engineering |
| 51 | R-51 | T-F06-I | Information disclosure | Excess user data in prompt | 3 | 3 | **9** | Medium | - | - | AI engineering |
| 52 | R-52 | T-F06-R | Repudiation | Agent actions not tied to user | 3 | 3 | **9** | Medium | - | - | Security operations (SOC) |
| 53 | R-53 | T-F10-D | Denial of service | Provider quota / outage | 3 | 3 | **9** | Medium | AML.T0029 | - | Platform engineering |
| 54 | R-54 | T-F10-R | Repudiation | LLM calls not attributable | 3 | 3 | **9** | Medium | - | - | Security operations (SOC) |
| 55 | R-55 | T-F11-R | Repudiation | Retrieved chunks not logged | 3 | 3 | **9** | Medium | - | - | Security operations (SOC) |
| 56 | R-56 | T-F16-R | Repudiation | Tool calls not attributable | 3 | 3 | **9** | Medium | - | - | Security operations (SOC) |
| 57 | R-57 | T-F01-T | Tampering | XSS alters prompts | 2 | 4 | **8** | Medium | - | - | Application security |
| 58 | R-58 | T-F02-T | Tampering | Redirect / state tampering | 2 | 4 | **8** | Medium | - | - | IAM team |
| 59 | R-59 | T-F03-S | Spoofing | Web App client impersonation | 2 | 4 | **8** | Medium | AML.T0055 | - | IAM team |
| 60 | R-60 | T-F05-I | Information disclosure | Secrets persisted in chat history | 2 | 4 | **8** | Medium | AML.T0057 | 1.4.4 | Platform engineering |
| 61 | R-61 | T-F05-T | Tampering | Chat history tampering | 2 | 4 | **8** | Medium | AML.T0080.001 | - | Platform engineering |
| 62 | R-62 | T-F06-T | Tampering | User context altered in transit | 2 | 4 | **8** | Medium | - | - | Application security |
| 63 | R-63 | T-F09-I | Information disclosure | M2M token captured | 2 | 4 | **8** | Medium | AML.T0091.000 | - | Platform engineering |
| 64 | R-64 | T-F09-T | Tampering | Scope parameter tampering | 2 | 4 | **8** | Medium | - | - | IAM team |
| 65 | R-65 | T-F12-T | Tampering | Adversarial embeddings | 2 | 4 | **8** | Medium | AML.T0071 | 3.2.3 | Knowledge-base owner |
| 66 | R-66 | T-F13-E | Elevation of privilege | Content source writes privileged namespace | 2 | 4 | **8** | Medium | AML.T0070 | - | Knowledge-base owner |
| 67 | R-67 | T-F13-R | Repudiation | No content provenance | 2 | 4 | **8** | Medium | - | 3.1.3 | Knowledge-base owner |
| 68 | R-68 | T-F14-I | Information disclosure | Excess context passed to Agent B | 2 | 4 | **8** | Medium | - | - | AI engineering |
| 69 | R-69 | T-F15-R | Repudiation | Scope changes undetected | 2 | 4 | **8** | Medium | - | 2.3.3 | Security operations (SOC) |
| 70 | R-70 | T-F15-T | Tampering | API request tampering | 2 | 4 | **8** | Medium | - | - | Application security |
| 71 | R-71 | T-F16-S | Spoofing | Rogue MCP server | 2 | 4 | **8** | Medium | AML.T0011.002 | - | Platform engineering |
| 72 | R-72 | T-F01-I | Information disclosure | Tokens or chat in browser storage | 2 | 3 | **6** | Medium | - | - | Application security |
| 73 | R-73 | T-F02-I | Information disclosure | Authorization code leak | 2 | 3 | **6** | Medium | - | - | IAM team |
| 74 | R-74 | T-F02-R | Repudiation | Login events not retained | 2 | 3 | **6** | Medium | - | - | Security operations (SOC) |
| 75 | R-75 | T-F03-D | Denial of service | Auth0 outage / rate limit | 2 | 3 | **6** | Medium | - | - | Platform engineering |
| 76 | R-76 | T-F05-S | Spoofing | Shared DB account | 2 | 3 | **6** | Medium | - | - | Platform engineering |
| 77 | R-77 | T-F07-D | Denial of service | Secrets Manager unavailable | 2 | 3 | **6** | Medium | - | - | Platform engineering |
| 78 | R-78 | T-F07-R | Repudiation | Secret reads not logged | 2 | 3 | **6** | Medium | - | - | Security operations (SOC) |
| 79 | R-79 | T-F08-D | Denial of service | Secret rotated without rollout | 2 | 3 | **6** | Medium | - | - | IAM team |
| 80 | R-80 | T-F08-R | Repudiation | M2M secret reads not logged | 2 | 3 | **6** | Medium | - | - | Security operations (SOC) |
| 81 | R-81 | T-F09-D | Denial of service | M2M token quota exhausted | 2 | 3 | **6** | Medium | - | - | Platform engineering |
| 82 | R-82 | T-F09-R | Repudiation | M2M token issuance untracked | 2 | 3 | **6** | Medium | - | - | Security operations (SOC) |
| 83 | R-83 | T-F12-D | Denial of service | Index corruption / deletion | 2 | 3 | **6** | Medium | - | - | Platform engineering |
| 84 | R-84 | T-F12-R | Repudiation | Vector writes not audited | 2 | 3 | **6** | Medium | - | - | Security operations (SOC) |
| 85 | R-85 | T-F14-D | Denial of service | Delegation storm | 2 | 3 | **6** | Medium | AML.T0034.002 | - | AI engineering |
| 86 | R-86 | T-F15-D | Denial of service | API flood from agent | 2 | 3 | **6** | Medium | - | - | Platform engineering |
| 87 | R-87 | T-F16-D | Denial of service | Tool flood | 2 | 3 | **6** | Medium | AML.T0034.002 | - | Platform engineering |
| 88 | R-88 | T-F17-D | Denial of service | MCP floods APIs | 2 | 3 | **6** | Medium | - | - | Platform engineering |
| 89 | R-89 | T-F01-R | Repudiation | User denies a prompt | 3 | 2 | **6** | Medium | - | - | Security operations (SOC) |
| 90 | R-90 | T-F08-T | Tampering | M2M secret replaced | 1 | 5 | **5** | Low | - | - | IAM team |
| 91 | R-91 | T-F10-S | Spoofing | Fake LLM endpoint | 1 | 5 | **5** | Low | - | - | Platform engineering |
| 92 | R-92 | T-F05-E | Elevation of privilege | SQL injection via chat metadata | 1 | 4 | **4** | Low | - | - | Application security |
| 93 | R-93 | T-F07-T | Tampering | Key swapped for attacker's key | 1 | 4 | **4** | Low | - | - | Platform engineering |
| 94 | R-94 | T-F11-S | Spoofing | Spoofed RAG service | 1 | 4 | **4** | Low | - | - | Platform engineering |
| 95 | R-95 | T-F17-T | Tampering | Tool arguments changed | 1 | 4 | **4** | Low | - | - | Application security |
| 96 | R-96 | T-F03-R | Repudiation | Token issuance not correlated | 2 | 2 | **4** | Low | - | - | Security operations (SOC) |
| 97 | R-97 | T-F05-D | Denial of service | DB exhaustion | 2 | 2 | **4** | Low | - | - | Platform engineering |
| 98 | R-98 | T-F05-R | Repudiation | DB changes not audited | 2 | 2 | **4** | Low | - | - | Security operations (SOC) |
| 99 | R-99 | T-F11-D | Denial of service | Expensive queries | 2 | 2 | **4** | Low | - | - | Platform engineering |
| 100 | R-100 | T-F13-D | Denial of service | Ingestion flood | 2 | 2 | **4** | Low | - | - | Knowledge-base owner |
