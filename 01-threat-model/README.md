# Project 1 - Threat Model of the AI Identity System

SecureNova AI Customer Service Platform: Auth0 IdP, a two-agent LLM harness (Orchestrator Agent A + Action Agent B), internal REST APIs, a RAG pipeline, an MCP server and an external LLM provider.

Every artefact in this folder is generated from one data file, so the numbers always match:

```bash
python3 01-threat-model/build_threat_model.py         # JSON, XLSX, DRAWIO, MD
python3 01-threat-model/build_threat_model.py --png   # + PNG exports (needs the draw.io desktop CLI)
```

Edit [threat_model_data.py](./threat_model_data.py), then re-run. The script stops with an error if a score does not propagate correctly, a threat ID referenced by an attack tree is missing or scored lower than the attack-tree node, or an ATLAS ID is unknown.

## Artefacts

| Task | Artefact | What it contains |
|---|---|---|
| 1 Identities | [Identity-Inventory.md](./Identity-Inventory.md) | 6 identity types: authentication mechanism, privilege level, lifetime |
| 2 DFD | [SecureNova-Threat-Dragon.json](./SecureNova-Threat-Dragon.json) | OWASP Threat Dragon v2 model: 14 elements, 8 trust boundaries, 17 flows, 6 STRIDE entries per flow |
| 2 DFD (copy) | [Threat Model.drawio](./Threat%20Model.drawio) / [Threat Model.png](./Threat%20Model.png) | The same DFD in draw.io |
| 2 STRIDE | [STRIDE-Matrix.xlsx](./STRIDE-Matrix.xlsx) / [STRIDE-Matrix.md](./STRIDE-Matrix.md) | 17 flows x 6 categories = 102 cells (100 threats, 2 justified N/A) |
| 3 Attack trees | [Attack Trees.drawio](./Attack%20Trees.drawio) / [Attack-Trees.md](./Attack-Trees.md) / 3 PNGs | AT1 = 20, AT2 = 20, AT3 = 16; every node scored L x I |
| 4 ATLAS | [ATLAS-Mapping.md](./ATLAS-Mapping.md) | AML.T technique per tree and per attack path |
| 4 Register | [Risk-Register.xlsx](./Risk-Register.xlsx) / [Risk-Register.md](./Risk-Register.md) | 100 threats ranked by Risk Score, each with owner, ATLAS ID and planned control |

## How the model was built (method)

1. **Enumerate identities (Task 1).** Six identity types: ID-1 human user, ID-2 AI agent, ID-3 OAuth M2M client, ID-4 LLM API key, ID-5 RAG service identity, ID-6 MCP server identity. For each one, record how it authenticates and what it is allowed to do.
2. **Draw the DFD (Task 2).** Put each component in a trust boundary. The three layers in the brief are TB1 **User layer**, TB4 **Agent layer** and TB5 **Internal API layer**. TB2 Auth0, TB3 backend, TB6 RAG, TB7 MCP and TB8 LLM provider are the other boundaries. Then draw every flow that carries an identity or credential (F01-F17) and label it with the identity it uses.
3. **STRIDE per flow (Task 2).** For every flow, ask all six questions (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege). Write a threat and a mitigation, or a one-line reason why the category is N/A. Threat IDs are `T-<flow>-<category>`, e.g. `T-F14-S`.
4. **Score.** Likelihood 1-5 x Impact 1-5 = Risk Score 1-25. Bands: Low 1-5, Medium 6-10, High 12-16, Critical 20-25. Scores are inherent (before the Project 2-4 controls).
5. **Attack trees (Task 3).** Root = attacker goal. AND gate = every child is needed (L = lowest child, I = highest child). OR gate = any child is enough (the highest-risk child propagates). Each leaf points to the STRIDE threat it exploits. The highest-risk path is drawn in thick red.
6. **ATLAS + register (Task 4).** Map each tree, and each node, to the closest MITRE ATLAS technique. Rank every threat by Risk Score and assign an owner (roles from the Project 5 policy).

## Screenshot guide (8 screenshots)

### 1. Threat Dragon: complete DFD with trust boundaries

1. Go to <https://www.threatdragon.com/>, choose **Login to local session**, or use the Threat Dragon desktop app.
2. Select **Open an existing threat model** (or **Import**), then pick or paste `SecureNova-Threat-Dragon.json`.
3. Click the diagram **SecureNova AI Platform - Identity Data Flow (STRIDE)**.
4. Use the zoom buttons so the whole canvas fits. All of these must be visible: the 8 red dashed trust boundaries (TB1-TB8), the 14 elements (with `[ID-x]` labels) and the 17 red flows (F01-F17), plus the identity legend at the bottom left.

### 2. Threat Dragon: STRIDE threats for one identity flow

1. In the same diagram, click flow **F14 Delegated task message** (Orchestrator Agent A -> Action Agent B). This is the agent-identity flow behind AT2.
2. The threats list for the selected flow (shown with its properties) has 6 threats: `T-F14-S` Forged orchestrator message (Critical), plus T, R, I, D and E.
3. Optionally, double-click `T-F14-S` to open the edit dialog with its description, mitigation, severity and score (`L4 x I5 = 20`).
4. Take the screenshot with the selected flow and at least 3 threat cards visible.

Alternatives: F04 (chat request) or F15 (M2M token to the internal APIs).

### 3-5. draw.io: Attack Trees 1, 2 and 3

1. Open <https://app.diagrams.net/> and go to **File > Open from > Device**, then choose `Attack Trees.drawio`. In VS Code you can use the *Draw.io Integration* extension instead.
2. Use the page tabs at the bottom: **AT1 - LLM API Key Exfiltration**, **AT2 - Agent Identity Spoofing**, **AT3 - RAG Chunk Poisoning**.
3. On each page press **Ctrl+Shift+H** (Fit window). The root goal must be at the top, every leaf at the bottom must be readable, and the scoring legend must be visible top right.
4. Take one screenshot per page. The PNGs in this folder show what each one should look like.

### 6. STRIDE threat matrix fully populated

Open `STRIDE-Matrix.xlsx` and go to the **STRIDE Matrix** sheet. It has one row per flow (F01-F17) and the columns S, T, R, I, D, E. Every cell holds either a threat ID + title + score (coloured by band) or a grey **N/A - reason**. Zoom out (about 60-70 %) until rows F01-F17 and all six STRIDE columns fit on screen.

### 7. Risk register ranked by Risk Score

Open `Risk-Register.xlsx` and go to the **Risk Register** sheet. It is already sorted from highest to lowest Risk Score. Make sure these columns are visible: Rank, Threat ID, Threat, Likelihood, Impact, **Risk Score**, Band, MITRE ATLAS and **Owner**. Zoom to about 80 % so at least 10 rows show, or hide the Flow/Identity columns for the screenshot. The **Attack Trees** and **ATLAS Mapping** sheets are useful as supporting evidence.

### 8. MITRE ATLAS technique page

Open one of the three mapped technique pages, with the address bar visible:

| Tree | Technique page |
|---|---|
| AT1 | <https://atlas.mitre.org/techniques/AML.T0051.001> (LLM Prompt Injection: Indirect) |
| AT2 | <https://atlas.mitre.org/techniques/AML.T0073> (Impersonation) |
| AT3 | <https://atlas.mitre.org/techniques/AML.T0070> (RAG Poisoning), recommended because it is the closest one-to-one match |

## Design decisions

- **Why two agents?** Project 3 attacks a two-agent setup (a forged orchestrator message makes Agent B act). Modelling Agent A -> Agent B as flow F14 means AT2's highest-risk path (2.2.3) traces to a real STRIDE threat (`T-F14-S`).
- **Why only 2 N/A cells?** N/A is used only where a category truly cannot apply (DoS and EoP on the user's own keyboard input, F01). Everything else got a real threat.
- **Why F09 and F13?** The M2M client-credentials grant (F09) and RAG content ingestion (F13) are where ID-3 is issued and where AT3 starts. Without them, those identities and attack paths would not appear on the DFD.
- **Root scores 20 / 20 / 16** are used by the Project 5 compliance mapping and presentation. The build script checks they still hold.
