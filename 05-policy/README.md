# 05 - Policy, Compliance and Summary

| Artefact | Task | Description |
|---|---|---|
| [AI-Identity-Security-Policy.md](./AI-Identity-Security-Policy.md) / [.docx](./AI-Identity-Security-Policy.docx) | 5.1 | Formal policy: (1) Identity Lifecycle, (2) Credential Governance, (3) Incident Response Playbook with 3 scenarios |
| [Compliance-Mapping.xlsx](./Compliance-Mapping.xlsx) | 5.2 | Tabs: **NIST AI RMF** (28 controls across Govern/Map/Measure/Manage, each with evidence), **OWASP LLM Top 10** (LLM01/06/07/09 + LLM02/08), **Compliance Gaps** (3), Findings, Controls |
| [Capstone-Presentation.pptx](./Capstone-Presentation.pptx) | 5.4 | 20-minute deck with timings and a 5-minute live demo slide |
| [live_demo.py](./live_demo.py) | 5.4 | Live demo: a Project 3 attack fires and the Project 4 guardrail blocks it in the same session |
| [CTO-Walkthrough.md](./CTO-Walkthrough.md) | 5.5 | Scope and methodology, risk priority matrix, top 5 recommendations, written for a non-technical CTO |
| [Risk-Priority-Matrix.png](./Risk-Priority-Matrix.png) | 5.5 | 5 findings plotted by likelihood and impact, with CVSS labels |
| [Top-5-Recommendations.png](./Top-5-Recommendations.png) | 5.5 | Recommendations with effort estimates and business rationale |
| [capstone_data.py](./capstone_data.py) | - | Single source of truth for findings, controls, mappings and gaps (taken from the Project 1-4 reports) |
| [build_artefacts.py](./build_artefacts.py) | - | Regenerates the .xlsx, .docx, .pptx and both PNGs from `capstone_data.py` |

## Build and run

Uses the repository's Python 3.12 venv (see the root README).

```bash
.venv/bin/pip install -r 05-policy/requirements.txt
.venv/bin/python 05-policy/build_artefacts.py           # regenerate all documents and charts
.venv/bin/python 05-policy/live_demo.py --delay 0.4     # live demo (P2 markdown-image exfiltration)
.venv/bin/python 05-policy/live_demo.py --payload P1 --save   # other payload; transcript to 05-policy/evidence/
```

`live_demo.py` exits with `0` only if Act 1 exfiltrates and Acts 2 and 3 both block.

## Screenshot guide

| # | Screenshot | What to open |
|---|---|---|
| 1 | Policy title page + table of contents with all 3 section headings | `AI-Identity-Security-Policy.docx`, pages 1-2 (in Word, right-click the TOC and choose **Update Field**), or the Markdown file on GitHub |
| 2 | IR Playbook scenario with detection signals and containment | Policy Section 3, Scenario A, B or C |
| 3 | NIST AI RMF tab | `Compliance-Mapping.xlsx` -> **NIST AI RMF** (coverage counts under the table) |
| 4 | OWASP LLM Top 10 tab | `Compliance-Mapping.xlsx` -> **OWASP LLM Top 10** |
| 5 | Repository file tree with all five folders | `github.com/Varun-Mohanta/capstone-ai-id-secure` |
| 6 | Commit history / contributor graph | Repository -> **Insights -> Contributors**, or the **Commits** page |
| 7 | Risk Priority Matrix | `Risk-Priority-Matrix.png` |
| 8 | Top 5 Recommendations | `Top-5-Recommendations.png` (or `CTO-Walkthrough.md` section 3) |
