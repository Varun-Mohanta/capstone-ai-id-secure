"""Build every Project 5 deliverable from capstone_data.py.

Outputs (all in 05-policy/):
  Compliance-Mapping.xlsx         tabs: NIST AI RMF, OWASP LLM Top 10, Compliance Gaps, Findings
  Risk-Priority-Matrix.png        likelihood x impact grid, 5 findings with CVSS labels
  Top-5-Recommendations.png       effort vs business rationale table for the CTO
  AI-Identity-Security-Policy.docx  Word version of the policy (title page + TOC)
  Capstone-Presentation.pptx      20-minute deck incl. live demo segment

Run: .venv/bin/python 05-policy/build_artefacts.py
"""

from __future__ import annotations

import re

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from docx import Document  # noqa: E402
from docx.enum.text import WD_ALIGN_PARAGRAPH  # noqa: E402
from docx.oxml import OxmlElement  # noqa: E402
from docx.oxml.ns import qn  # noqa: E402
from docx.shared import Pt, RGBColor  # noqa: E402
from openpyxl import Workbook  # noqa: E402
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side  # noqa: E402
from openpyxl.worksheet.table import Table, TableStyleInfo  # noqa: E402
from pptx import Presentation  # noqa: E402
from pptx.dml.color import RGBColor as PRGB  # noqa: E402
from pptx.util import Inches, Pt as PPt  # noqa: E402

from capstone_data import (AFTER_RATE, BEFORE_RATE, CONTROLS, FINDINGS, GAPS, NIST_ROWS,  # noqa: E402
                           OWASP_ROWS, POLICY_DIR, RECOMMENDATIONS)

NAVY = "1F3864"
SEV_FILL = {"Critical": "C00000", "High": "ED7D31", "Medium": "FFC000", "Low": "70AD47"}
FUNC_FILL = {"GOVERN": "D9E1F2", "MAP": "E2EFDA", "MEASURE": "FFF2CC", "MANAGE": "FCE4D6"}


# ----------------------------------------------------------------------------- Excel
def _sheet(wb, title, headers, rows, widths, fills=None, table_name=None):
    ws = wb.create_sheet(title)
    thin = Side(style="thin", color="BFBFBF")
    ws.append(headers)
    for row in rows:
        ws.append(list(row))
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=NAVY)
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    for r in ws.iter_rows(min_row=2):
        for cell in r:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            cell.border = Border(top=thin, bottom=thin, left=thin, right=thin)
            if fills:
                color = fills(r, cell)
                if color:
                    cell.fill = PatternFill("solid", fgColor=color)
    for i, w in enumerate(widths):
        ws.column_dimensions[chr(65 + i)].width = w
    ws.freeze_panes = "A2"
    if table_name:
        ref = f"A1:{chr(64 + len(headers))}{len(rows) + 1}"
        tab = Table(displayName=table_name, ref=ref)
        tab.tableStyleInfo = TableStyleInfo(name="TableStyleLight1", showRowStripes=False)
        ws.add_table(tab)
    return ws


def build_workbook():
    wb = Workbook()
    wb.remove(wb.active)

    nist = _sheet(
        wb, "NIST AI RMF",
        ["Ref", "Function", "NIST AI RMF subcategory", "Control / activity", "Project", "Evidence artefact", "Status"],
        NIST_ROWS, [8, 11, 36, 60, 9, 62, 24],
        fills=lambda r, c: FUNC_FILL[r[1].value] if c.column == 2 else None, table_name="NistAiRmf")
    start = len(NIST_ROWS) + 3
    nist.cell(start, 1, "Coverage by function").font = Font(bold=True)
    for i, fn in enumerate(FUNC_FILL, 1):
        nist.cell(start + i, 1, fn).fill = PatternFill("solid", fgColor=FUNC_FILL[fn])
        nist.cell(start + i, 2, f'=COUNTIF(B2:B{len(NIST_ROWS) + 1},"{fn}")')
    nist.cell(start + 5, 1, "Total").font = Font(bold=True)
    nist.cell(start + 5, 2, f"=SUM(B{start + 1}:B{start + 4})")

    _sheet(
        wb, "OWASP LLM Top 10",
        ["Category", "Name (2025)", "Relevant", "Project 3 attack", "Project 3 result", "Project 4 control",
         "Project 4 result", "Evidence", "Residual risk"],
        OWASP_ROWS, [9, 26, 13, 60, 26, 55, 30, 50, 40],
        fills=lambda r, c: "E2EFDA" if c.column == 7 else ("FCE4D6" if c.column == 5 else None),
        table_name="OwaspLlm")

    _sheet(
        wb, "Compliance Gaps",
        ["Gap", "Title", "Finding", "Obligation", "Risk", "Recommendation", "Owner", "Target"],
        GAPS, [8, 28, 60, 42, 45, 60, 20, 10],
        fills=lambda r, c: ("C00000" if "Critical" in str(c.value)[:9] else "ED7D31") if c.column == 5 else None,
        table_name="Gaps")
    for r in wb["Compliance Gaps"].iter_rows(min_row=2, min_col=5, max_col=5):
        r[0].font = Font(color="FFFFFF", bold=True)

    rows = [(f["id"], f["title"], f["owasp"], f["atlas"], f["vector"], f["cvss"], f["severity"], f["likelihood"],
             f["impact"], f"=H{i}*I{i}", f["before"], f["after"], f["controls"]) for i, f in enumerate(FINDINGS, 2)]
    _sheet(
        wb, "Findings",
        ["ID", "Finding", "OWASP", "MITRE ATLAS", "CVSS 3.1 vector", "CVSS", "Severity", "Likelihood", "Impact",
         "L x I", "P3 success", "P4 success", "Project 4 controls"],
        rows, [6, 44, 14, 30, 46, 7, 10, 10, 8, 7, 11, 11, 44],
        fills=lambda r, c: SEV_FILL[c.value] if c.column == 7 else None, table_name="Findings")

    ctl = wb.create_sheet("Controls")
    ctl.append(["ID", "Project 4 control"])
    for k, v in CONTROLS.items():
        ctl.append([k, v])
    ctl.column_dimensions["B"].width = 80
    for cell in ctl[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=NAVY)
    out = POLICY_DIR / "Compliance-Mapping.xlsx"
    wb.save(out)
    return out


# ----------------------------------------------------------------------------- charts
def build_risk_matrix():
    fig, ax = plt.subplots(figsize=(12, 8.5), dpi=150)
    band = lambda s: "#C00000" if s >= 20 else "#ED7D31" if s >= 12 else "#FFC000" if s >= 6 else "#70AD47"
    for l in range(1, 6):
        for i in range(1, 6):
            ax.add_patch(plt.Rectangle((i - 0.5, l - 0.5), 1, 1, color=band(l * i), alpha=0.35, ec="white", lw=2))
            ax.text(i + 0.42, l - 0.42, str(l * i), ha="right", va="bottom", fontsize=8, color="#555")
    offsets = {}
    for f in FINDINGS:
        key = (f["impact"], f["likelihood"])
        n = offsets.get(key, 0)
        offsets[key] = n + 1
        x, y = f["impact"] + (n * 0.5 - 0.25 if key in [(5, 4)] else 0), f["likelihood"]
        ax.scatter(x, y, s=1500, color=SEV_COLOR(f["severity"]), ec="black", lw=1.5, zorder=3)
        ax.text(x, y + 0.03, f["id"], ha="center", va="center", fontsize=13, weight="bold", color="white", zorder=4)
        ax.text(x, y - 0.32, f"CVSS {f['cvss']}\n{f['severity']}", ha="center", va="top", fontsize=8.5,
                weight="bold", zorder=4, bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none", alpha=0.85))
    ax.set_xlim(0.5, 5.5)
    ax.set_ylim(0.5, 5.5)
    ax.set_xticks(range(1, 6), ["1\nNegligible", "2\nMinor", "3\nModerate", "4\nMajor", "5\nSevere"])
    ax.set_yticks(range(1, 6), ["1 Rare", "2 Unlikely", "3 Possible", "4 Likely", "5 Almost\ncertain"])
    ax.set_xlabel("Business impact if it happens  ->", fontsize=12, weight="bold")
    ax.set_ylabel("How likely it is to happen  ->", fontsize=12, weight="bold")
    ax.set_title("SecureNova AI - Risk Priority Matrix (before fixes)\n"
                 "Top-right = fix first. Circle label = finding, CVSS 3.1 score underneath",
                 fontsize=14, weight="bold")
    legend = "\n".join(f"{f['id']}  CVSS {f['cvss']:<4} {f['plain']}" for f in
                       sorted(FINDINGS, key=lambda f: -f["cvss"]))
    fig.text(0.5, 0.01, legend + f"\nAfter Project 4 controls: attack success {BEFORE_RATE} -> {AFTER_RATE}",
             ha="center", va="bottom", fontsize=9.5, family="monospace",
             bbox=dict(boxstyle="round", fc="#F2F2F2", ec="#999"))
    fig.subplots_adjust(bottom=0.27, left=0.12, right=0.97, top=0.9)
    out = POLICY_DIR / "Risk-Priority-Matrix.png"
    fig.savefig(out)
    plt.close(fig)
    return out


def SEV_COLOR(sev):
    return "#" + SEV_FILL[sev]


def build_recommendations_png():
    cols = ["#", "Recommendation", "What we do", "Fixes", "Effort", "Business rationale"]
    wraps = [3, 24, 42, 12, 14, 40]
    import textwrap
    cells = [[textwrap.fill(str(v), w) for v, w in zip(
        [r["rank"], r["title"], r["what"], r["fixes"], r["effort"], r["why"]], wraps)] for r in RECOMMENDATIONS]
    fig, ax = plt.subplots(figsize=(17, 6.5), dpi=150)
    ax.axis("off")
    tab = ax.table(cellText=cells, colLabels=cols, loc="center", cellLoc="left",
                   colWidths=[0.03, 0.16, 0.27, 0.09, 0.11, 0.27])
    tab.auto_set_font_size(False)
    tab.set_fontsize(9.5)
    for (r, c), cell in tab.get_celld().items():
        lines = max(str(t).count("\n") + 1 for t in cells[r - 1]) if r else 1
        cell.set_height(0.04 + 0.034 * lines)
        if r == 0:
            cell.set_facecolor("#" + NAVY)
            cell.set_text_props(color="white", weight="bold")
        elif c == 4:
            cell.set_facecolor("#E2EFDA" if RECOMMENDATIONS[r - 1]["effort"].startswith("Low") else "#FFF2CC")
        elif r % 2 == 0:
            cell.set_facecolor("#F2F2F2")
    fig.suptitle("Top 5 Recommendations for the CTO - effort and business rationale\n"
                 "Total ~18 person-weeks; ranked by risk removed per unit of effort",
                 fontsize=14, weight="bold", y=1.04)
    out = POLICY_DIR / "Top-5-Recommendations.png"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


# ----------------------------------------------------------------------------- Word
def _add_toc(doc):
    p = doc.add_paragraph()
    run = p.add_run()
    for tag, text in (("begin", None), (None, 'TOC \\o "1-2" \\h \\z \\u'), ("separate", None), ("end", None)):
        if tag:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), tag)
            if tag == "begin":
                el.set(qn("w:dirty"), "true")
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        run._r.append(el)


def _inline(par, text):
    for part in re.split(r"(\*\*[^*]+\*\*|`[^`]+`)", text):
        if part.startswith("**") and part.endswith("**"):
            par.add_run(part[2:-2]).bold = True
        elif part.startswith("`") and part.endswith("`"):
            r = par.add_run(part[1:-1])
            r.font.name = "Consolas"
        else:
            par.add_run(re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", part))


def build_policy_docx():
    md = (POLICY_DIR / "AI-Identity-Security-Policy.md").read_text(encoding="utf-8").splitlines()
    doc = Document()
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10.5)

    # Title page
    for _ in range(5):
        doc.add_paragraph()
    t = doc.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = t.add_run("SecureNova Inc.")
    r.font.size, r.bold = Pt(20), True
    t = doc.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = t.add_run("AI Identity Security Policy")
    r.font.size, r.bold, r.font.color.rgb = Pt(32), True, RGBColor(0x1F, 0x38, 0x64)
    t = doc.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    t.add_run("Identity Lifecycle  |  Credential Governance  |  Incident Response Playbook").italic = True
    doc.add_paragraph()
    meta_end = md.index("## Table of Contents")
    rows = [l for l in md[:meta_end] if l.startswith("|") and not l.startswith("|---")][1:]
    tbl = doc.add_table(rows=0, cols=2, style="Light Grid Accent 1")
    for row in rows:
        k, v = [c.strip() for c in row.strip("|").split("|")]
        cells = tbl.add_row().cells
        cells[0].text, cells[1].text = k, v
    doc.add_page_break()

    # Table of contents: Word field (auto-updates on open) + static fallback listing the sections
    doc.add_heading("Table of Contents", level=1)
    _add_toc(doc)
    for line in md:
        if line.startswith("## ") and "Table of Contents" not in line:
            doc.add_paragraph(line[3:], style="List Number")
        elif line.startswith("### ") and md.index(line) > meta_end and line[4:5] in "123S":
            p = doc.add_paragraph(line[4:], style="List Bullet 2")
    doc.add_page_break()

    # Body
    i = md.index("## Purpose, Scope and Definitions")
    table_buf = []

    def flush():
        if not table_buf:
            return
        rows = [[c.strip() for c in l.strip().strip("|").split("|")] for l in table_buf if not l.startswith("|---")]
        tb = doc.add_table(rows=0, cols=len(rows[0]), style="Light Grid Accent 1")
        for n, row in enumerate(rows):
            cells = tb.add_row().cells
            for c, val in zip(cells, row):
                c.text = ""
                _inline(c.paragraphs[0], val)
                if n == 0:
                    for run in c.paragraphs[0].runs:
                        run.bold = True
        doc.add_paragraph()
        table_buf.clear()

    for line in md[i:]:
        if line.startswith("|"):
            table_buf.append(line)
            continue
        flush()
        if line.startswith("## "):
            if line.startswith("## Section") or line.startswith("## Compliance"):
                doc.add_page_break()
            doc.add_heading(line[3:], level=1)
        elif line.startswith("### "):
            doc.add_heading(line[4:], level=2)
        elif re.match(r"^\d+\. ", line):
            _inline(doc.add_paragraph(style="List Number"), re.sub(r"^\d+\. ", "", line))
        elif line.startswith("- "):
            _inline(doc.add_paragraph(style="List Bullet"), line[2:])
        elif line.strip() in ("", "---"):
            continue
        else:
            _inline(doc.add_paragraph(), line)
    flush()
    out = POLICY_DIR / "AI-Identity-Security-Policy.docx"
    doc.save(out)
    return out


# ----------------------------------------------------------------------------- PowerPoint
def build_presentation(matrix_png, recs_png):
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    blank, title_only = prs.slide_layouts[6], prs.slide_layouts[5]

    def slide(title, bullets=None, minutes=None, notes=None):
        s = prs.slides.add_slide(title_only)
        s.shapes.title.text = title
        s.shapes.title.text_frame.paragraphs[0].font.size = PPt(32)
        s.shapes.title.text_frame.paragraphs[0].font.color.rgb = PRGB(0x1F, 0x38, 0x64)
        if bullets:
            box = s.shapes.add_textbox(Inches(0.7), Inches(1.6), Inches(12), Inches(5.4)).text_frame
            box.word_wrap = True
            for n, b in enumerate(bullets):
                p = box.paragraphs[0] if n == 0 else box.add_paragraph()
                level = 1 if b.startswith("  ") else 0
                p.text, p.level = ("- " if level else "") + b.strip(), level
                p.font.size = PPt(16 if level else 20)
                p.space_after = PPt(6)
        if minutes:
            tag = s.shapes.add_textbox(Inches(11.3), Inches(7.0), Inches(2), Inches(0.4)).text_frame
            tag.text = minutes
            tag.paragraphs[0].font.size = PPt(11)
            tag.paragraphs[0].font.color.rgb = PRGB(0x80, 0x80, 0x80)
        if notes:
            s.notes_slide.notes_text_frame.text = notes
        return s

    def table(s, headers, rows, top=1.5, widths=None, size=12):
        shape = s.shapes.add_table(len(rows) + 1, len(headers), Inches(0.4), Inches(top), Inches(12.5),
                                   Inches(0.4 * (len(rows) + 1)))
        t = shape.table
        for c, h in enumerate(headers):
            t.cell(0, c).text = h
        for r, row in enumerate(rows, 1):
            for c, v in enumerate(row):
                t.cell(r, c).text = str(v)
        for r in range(len(rows) + 1):
            for c in range(len(headers)):
                for p in t.cell(r, c).text_frame.paragraphs:
                    p.font.size = PPt(size)
        if widths:
            for c, w in enumerate(widths):
                t.columns[c].width = Inches(w)

    s = prs.slides.add_slide(blank)
    tb = s.shapes.add_textbox(Inches(0.8), Inches(2.3), Inches(11.7), Inches(3)).text_frame
    tb.text = "Securing AI Identities at SecureNova"
    tb.paragraphs[0].font.size, tb.paragraphs[0].font.bold = PPt(44), True
    tb.paragraphs[0].font.color.rgb = PRGB(0x1F, 0x38, 0x64)
    for line in ("AI Identity Security Capstone - final presentation (20 minutes)",
                 "Threat model -> IAM architecture -> Red team -> Blue team -> Compliance -> Recommendations",
                 "AI Identity Security Analyst | 2026-11-10"):
        p = tb.add_paragraph()
        p.text, p.font.size = line, PPt(20)

    slide("Agenda and scope", [
        "Scope: NovaAssist AI customer-service platform - Auth0, AI agents, internal APIs, RAG pipeline, MCP tools",
        "Method: threat model (STRIDE + attack trees) -> build IAM (Auth0) -> attack (red team) -> defend (blue team) -> govern (policy + compliance)",
        "Agenda",
        "  1. Threat model (2 min)   2. IAM architecture (3 min)   3. Red team findings (3 min)",
        "  4. Blue team controls (3 min)   5. LIVE DEMO (5 min)   6. Compliance (2 min)   7. Top 5 recommendations (2 min)",
    ], "0:00-1:00")

    slide("1. Threat model", [
        "6 identity types: human user, AI agent, OAuth M2M client, LLM API key, RAG service, MCP server",
        "14 identity flows x 6 STRIDE categories = 84 assessments; 8 trust boundaries (OWASP Threat Dragon)",
        "3 attack trees scored Likelihood x Impact:",
        "  AT1 LLM API key exfiltration via prompt injection - 20 Critical",
        "  AT2 Agent identity spoofing to gain write:admin - 20 Critical",
        "  AT3 RAG chunk poisoning - 16 High",
        "Every path mapped to MITRE ATLAS (AML.T0051, T0056, T0070, T0073 ...)",
    ], "1:00-3:00", "Show 01-threat-model/Threat Model.png and one attack tree PNG.")

    slide("2. IAM architecture (Auth0)", [
        "Regular Web App (chat) + Machine-to-Machine app (agent), Authorization Code + PKCE",
        "Custom scopes read:ai-data (user) and write:admin (admin) - user token gets 403 on admin endpoint",
        "RS256 JWTs validated for aud, iss, exp, scope with zero leeway",
        "TOTP MFA for all users, brute-force protection (10 attempts / 15 min), suspicious IP throttling",
        "Post-login Action adds agent_id claim; SSO across both clients",
        "Short-lived tokens: 60 s M2M test (200 then 401), hardened to 300 s with refresh token rotation",
    ], "3:00-6:00")

    s = slide("3. Red team findings - 10 of 11 attacks succeeded (90.9 %)", minutes="6:00-9:00")
    table(s, ["ID", "Attack", "OWASP", "ATLAS", "CVSS 3.1", "Success"],
          [(f["id"], f["title"], f["owasp"], f["atlas"], f"{f['cvss']} {f['severity']}", f["before"])
           for f in sorted(FINDINGS, key=lambda f: -f["cvss"])], widths=[0.6, 4.6, 1.5, 3.2, 1.6, 1.0])

    s = slide("4. Blue team controls - 0 of 11 attacks succeeded", minutes="9:00-12:00")
    table(s, ["ID", "Attack", "Before", "After", "Primary / backup control"],
          [(f["id"], f["title"], f["before"], f["after"], f["controls"]) for f in FINDINGS],
          widths=[0.6, 4.5, 1.0, 1.0, 5.4], size=12)
    box = s.shapes.add_textbox(Inches(0.5), Inches(4.6), Inches(12), Inches(2)).text_frame
    box.word_wrap = True
    for n, line in enumerate((f"Attack success rate: {BEFORE_RATE} -> {AFTER_RATE} = 100 % relative reduction",
                              "False positive rate on 10 legitimate inputs: 0 %",
                              "Detection: LLM call spike, scope change, expired-token reuse - all fire on replayed attacks")):
        p = box.paragraphs[0] if n == 0 else box.add_paragraph()
        p.text, p.font.size, p.font.bold = line, PPt(18), n == 0

    slide("5. LIVE DEMO - attack fires, guardrail blocks (5 minutes)", [
        "Command: .venv/bin/python 05-policy/live_demo.py --delay 0.4",
        "Act 1 - Project 3 payload (hidden markdown image) -> agent leaks its token to attacker server: EXFILTRATED",
        "Act 2 - same payload, same session, NeMo input rail ON -> BLOCKED (LLM01-markdown-exfil)",
        "Act 3 - input rail OFF -> JWT output rail replaces token with [REDACTED]: defence in depth",
        "Backup: 04-blue-team/signed_agent_bus.py (tampered agent message rejected)",
    ], "12:00-17:00", "Run in a terminal with large font. If the demo fails, show 05-policy/evidence/live-demo-*.log.")

    s = slide("6. Compliance status", minutes="17:00-18:30")
    table(s, ["Framework", "Status", "Evidence"], [
        ("NIST AI RMF", f"{len(NIST_ROWS)} controls mapped across Govern / Map / Measure / Manage",
         "Compliance-Mapping.xlsx - NIST AI RMF tab"),
        ("OWASP LLM Top 10", "LLM01, LLM06, LLM07, LLM09 (+LLM02, LLM08) attack -> control mapped",
         "Compliance-Mapping.xlsx - OWASP tab"),
        ("Policy", "Identity lifecycle, credential governance (90-day max), 3 IR playbooks",
         "AI-Identity-Security-Policy.docx"),
    ] + [(g[0], g[1], f"Owner {g[6]}, target {g[7]}") for g in GAPS], widths=[2.2, 6.0, 4.3], size=13)

    s = slide("Risk priority matrix (for the CTO)", minutes="18:30-19:00")
    s.shapes.add_picture(str(matrix_png), Inches(2.7), Inches(1.2), height=Inches(6.2))
    s = slide("7. Top 5 recommendations", minutes="19:00-20:00")
    s.shapes.add_picture(str(recs_png), Inches(0.3), Inches(1.3), width=Inches(12.7))
    slide("Questions", ["Repository: github.com/Varun-Mohanta/capstone-ai-id-secure",
                        "Folders: 01-threat-model, 02-iam-design, 03-red-team, 04-blue-team, 05-policy"])
    out = POLICY_DIR / "Capstone-Presentation.pptx"
    prs.save(out)
    return out


def main():
    xlsx = build_workbook()
    matrix = build_risk_matrix()
    recs = build_recommendations_png()
    docx = build_policy_docx()
    pptx = build_presentation(matrix, recs)
    for path in (xlsx, matrix, recs, docx, pptx):
        print(f"wrote {path.relative_to(POLICY_DIR.parent)}")


if __name__ == "__main__":
    main()
