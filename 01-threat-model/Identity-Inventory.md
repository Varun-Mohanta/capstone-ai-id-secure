# Identity Inventory - SecureNova AI Customer Service Platform

Project 1 - Task 1. Every identity in the platform, how it authenticates and what it is allowed to do. Generated from `threat_model_data.py`.

| ID | Identity | Type | Where | Authentication mechanism | Privilege level | Lifetime |
|---|---|---|---|---|---|---|
| ID-1 | Human user (customer / admin) | Human | User layer (TB1), authenticates at Auth0 (TB2) | Auth0 Universal Login: password + TOTP MFA. OIDC Authorization Code + PKCE (S256). The backend (BFF) keeps the tokens; the browser holds only an HttpOnly, Secure, SameSite session cookie. | Customer: read:ai-data. Admin role only (Auth0 RBAC): write:admin. | Access token 300 s; session idle timeout 30 min |
| ID-2 | AI agent (Orchestrator Agent A + Action Agent B) | Non-human (workload) | Agent layer (TB4) | Workload identity carried as an agent_id claim (added by an Auth0 post-login Action) plus the validated user context from the backend. Agent-to-agent messages are meant to be signed (Ed25519, Project 4); at the start of Project 1 they are unsigned. | Acts on behalf of the signed-in user, so it should never hold more than the user's own scope (read:ai-data). It must not hold standing write:admin. | Per user session |
| ID-3 | OAuth M2M client (Action Agent B) | Non-human (OAuth client) | Agent layer (TB4) -> Auth0 (TB2) -> Internal API layer (TB5) | OAuth 2.0 Client Credentials grant (client_id + client_secret from the Secrets Manager; private_key_jwt is the target). Returns an RS256 JWT access token. | read:ai-data on the Internal REST APIs. write:admin is not granted (least privilege). | Token 60-300 s; secret rotated at least every 90 days |
| ID-4 | LLM API key | Non-human (static API key) | Secrets Manager (TB3) -> Orchestrator Agent A (TB4) -> LLM Provider (TB8) | Static bearer key sent in the Authorization header over TLS to the external LLM Provider | Full inference on the provider account: every model, spend up to the account limit. It is not scoped per user, so a leaked key is a high-value credential. | Static; rotated at least every 90 days |
| ID-5 | RAG pipeline service identity | Non-human (service account) | RAG pipeline (TB6) | Service account: M2M token or mTLS between the RAG Service and the Vector Store. Ingestion uses a separate writer identity. | Query: read-only on the vector store, filtered by tenant. Ingestion writer: append to the staging namespace only. | Token 300 s; certificate 90 days |
| ID-6 | MCP server identity | Non-human (OAuth client) | MCP tool layer (TB7) -> Internal API layer (TB5) | Its own Auth0 M2M client (Client Credentials). It validates the caller's token (aud = MCP server) and never passes the agent's token through. | Per-tool scopes on an allow-list (for example tickets:read, refunds:create up to a limit). Privileged tools need human approval. | Token 300 s; secret rotated at least every 90 days |

## Supporting identities

| Identity | Authentication | Privilege |
|---|---|---|
| Chatbot Backend (Auth0 Regular Web Application) | Confidential OIDC client: client secret + PKCE code exchange | Receives the user's ID token and access token |
| Knowledge-base content sources | None (untrusted input) | Can add content to the RAG ingestion queue |

## Key observations

1. **ID-4 (LLM API key)** is the only static, non-expiring credential and is not scoped per user. It is the target of Attack Tree 1.
2. **ID-2 (AI agent)** has no cryptographic identity of its own at the start: Agent B trusts message text. This is the root of Attack Tree 2.
3. **ID-5 (RAG)** serves content that came from untrusted sources (F13), so retrieved text cannot be trusted as instructions. This is Attack Tree 3.
4. Non-human identities (ID-2 to ID-6) must never hold more privilege than the human they act for (no standing `write:admin`).
