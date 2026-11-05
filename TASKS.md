# Tasks

## Scenario

SecureNova Inc. has recently deployed an Al-powered customer service platform
that uses an LLM agent backed by Auth0 for identity management. The agent calls
internal REST APIs, retrieves knowledge from a RAG pipeline, and invokes MCP
server tools on behalf of authenticated users. SecureNova's security team has raised
concerns about credential exposure through prompt injection, uncontrolled agent
privilege, and lack of audit trails for non-human identities. You have been engaged
as an Al Identity Security Analyst. Your task is to threat model the platform,
implement and test secure IAM controls using Auth0, conduct a structured red team
campaign against the Al identity layer, deploy defensive guardrails, and produce a
governance policy with compliance evidence.

## Requirements

**The process for completing the Al Identity Security Capstone requirements
must follow these steps:**

**Project 1 - Threat Model the Al Identity System**

1. Threat Modelling: Enumerate all identity types in the SecureNova Al platform - human users, Al agent, OAuth M2M client, LLM API key, RAG pipeline
service identity, MCP server identity. For each, document the authentication mechanism and privilege level.

2. STRIDE Matrix: Apply all six STRIDE categories to every identity flow in the
system. Build the complete data-flow diagram in OWASP Threat Dragon. Identify trust boundaries between the user layer, agent layer, and internal API layer.

3. Attack Trees: Build three attack trees in [draw.io](draw.io): 

(1) LLM API key exfiltration via
prompt injection, 

(2) agent identity spoofing to gain elevated API scope, 

(3) RAG chunk poisoning to manipulate agent behavior. Score each threat: Likelihood x Impact = Risk Score.

4. MITRE ATLAS Mapping: Map each attack tree to the closest MITRE ATLAS technique [atlas.mitre.org](atlas.mitre.org). Record the AML.TXXXX Technique ID for each attack path. Produce the final risk-ranked register with owner assigned to each threat.

**Project 2 - Build and Secure the Auth0-Backed Al Application**

1. Auth0 Tenant Setup: Create a free Auth0 developer tenant. Register two
applications: 

(1) a Regular Web Application for the Al chat service, 

(2) a Machine-to-Machine application for the Al agent. Configure allowed callback URLs, grant types, and CORS origins for each.

2. OAuth 2.0 + PKCE: Implement Authorization Code + PKCE flow. 

Define two custom scopes: 
read:ai-data (user-level) and write:admin(admin-level).

Demonstrate that a user-level token is rejected with 403 when calling the admin-scoped endpoint. Decode and verify the JWT at [jwt.io](jwt.io) - confirm
RS256 algorithm, aud, iss, exp, and scope claims.

3. MFA and Attack Protection: Enable TOTP-based MFA for all users via Auth0.
Configure Brute-Force Protection (max 10 attempts, 15-minute lockout) and Suspicious IP Throttling. Capture the MFA enrolment and challenge flow.

4. Credential Rotation: Write a Python script to obtain a short-lived M2M token from Auth0 (TTL 60 seconds), call the /chat API endpoint, then
replay the expired token after 60 seconds to confirm a 401 Unauthorised response. Record timestamped terminal output as evidence.

5. Auth0 Actions: Write an Auth0 post-login Action that adds a custom claim
(agent_id) to the ID token. Deploy the Action and confirm the claim
appears at [jwt.io](jwt.io). Enable SSO and confirm a user authenticated to one
client is accepted by a second registered client without re-authentication.

**Project 3 - Red Team: Al Identity Attacks**

1. Indirect Prompt Injection (OWASP LLM01): Embed a simulated identity credential (fake JWT) in the agent's system context. Craft at least 3 payloads hidden inside documents the agent reads (simulate as text input).
Attempt to exfiltrate the credential without the user requesting it. Record
every payload verbatim and the full model response.

2. Agent Identity Spoofing (OWASP LLM09): In a two-agent setup, craft a message convincing Agent B it is receiving a trusted orchestrator instruction. Demonstrate Agent B executing a privileged action it would refuse under correct identity context. Document the full kill chain.

3. System Prompt Extraction (OWASP LLM07): Attempt 5 extraction techniques: 

repeat-back, 

role-play override, 

translation trick, 

ignore-prior instruction, 

suffix injection. 


Log every prompt and the complete model response. 
Attempt to elevate from user role to admin role via prompt engineering alone.

4. RAG Poisoning and MCP Abuse: 
Inject a malicious instruction into the simulated RAG knowledge base. 
Confirm the agent retrieves it and acts on it. Simulate an MCP tool call triggered by the poisoned chunk.

5. CVSS Scoring and ATLAS Mapping: 
For every successful attack, calculate
the CVSS 3.1 score at first.org and record the full vector string. 

Map each finding to the closest MITRE ATLAS AML.TXXXX technique. 

Produce the red team report with executive summary, one finding page per attack, and top
3 hardening recommendations.

**Project 4 - Blue Team: Guardrails, Hardening and Detection**

1. Input/Output Guardrails: Deploy NeMo Guardrails or Rebuff in your Python venv. 

Run all 5 Project 3 attack payloads through the guardrail and record block vs pass for each. 

Write a custom output guardrail using regex to detect and redact JWT-shaped strings in model responses.

2. Cryptographic Agent Identity Binding: Generate an Ed25519 key pair using Python's cryptography library. 

Sign every outgoing agent message with
the private key. 

On the receiving side, verify the signature before
processing. Demonstrate that a tampered message (one character changed) is rejected with a clear error log.

3. Auth0 Hardening: Reduce token TTL to 300 seconds in Auth0 API settings.

Enable refresh token rotation and confirm old refresh tokens are rejected.

Write an Auth0 Action that blocks login based on a custom risk condition.

Test 10 legitimate inputs against the guardrails and record the false positive rate.

4. Anomaly Detection: Write a Python detection script to alert on: 

LLM API call volume spike (more than 20 requests in 60 seconds), scope change between consecutive agent requests, and token reuse after expiry. 

Replay Project 3 attacks and confirm each alert fires with timestamp, identity, and
event type.

5. Before/After Comparison: Re-run all 5 Project 3 attacks against the hardened application. 

Produce a before/after comparison table showing
attack outcome and the specific control applied for each. 

Calculate the overall attack success rate reduction.

**Project 5 - Policy, Compliance and Summary**

1. Al Identity Security Policy: Write a formal policy covering three sections: 

(1) Identity Lifecycle - how Al agent identities are provisioned, reviewed,
rotated, and decommissioned, with specific timelines; 

(2) Credential Governance - API key rotation schedule (maximum 90 days), prohibition
on long-lived credentials for agents, secrets management standards; 

(3) Incident Response Playbook - three scenarios: leaked LLM API key, compromised agent identity, and successful prompt injection leading to
data exfiltration - each with detection signals, containment, evidence preservation, notification, and recovery steps.

2. Compliance Mapping: Build a compliance mapping spreadsheet with two tabs: 

(1) NIST AI RMF - map each Project 1-4 control to a function (Govern, Map, Measure, Manage) and cite the evidence artefact; 

(2) OWASP LLM Top 10- for each relevant category (LLM01, LLM06, LLM07, LLM09) document the Project 3 attack and the Project 4 control. Identify 3
remaining compliance gaps with finding, obligation, risk, and recommendation for each.

3. GitHub Portfolio: Publish a GitHub repository with five folders:

/01-threat-model, 

/02-iam-design, 

/03-red-team, 

/04-blue-team, 

/05-policy. 


Use GitHub Copilot to generate inline comments and README sections for all code artefacts. Commit history must show contributions across all 5
project days.

4. Final Presentation: Prepare and deliver a 20-minute capstone presentation
covering: 

threat model --> IAM architecture --> red team findings --> blue team controls --> compliance status --> top 5 recommendations. 

Include a 5-minute live demo segment showing one Project 3 attack firing and the Project 4 guardrail blocking it in the same session.

5. Walkthrough: Scope and methodology, Risk priority matrix addressed to a non-technical CTO (no jargon), Top 5 recommendations with business rationale for each.