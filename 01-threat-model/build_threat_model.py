"""Generate every Project 1 artefact from threat_model_data.py.

Usage:
    python 01-threat-model/build_threat_model.py           # build JSON, XLSX, DRAWIO, MD
    python 01-threat-model/build_threat_model.py --png     # also export PNGs (needs the draw.io CLI)

Outputs (all in 01-threat-model/):
    SecureNova-Threat-Dragon.json   OWASP Threat Dragon v2 model (DFD + STRIDE threats on every flow)
    Threat Model.drawio             The same DFD in draw.io (exported to Threat Model.png)
    STRIDE-Matrix.xlsx / .md        17 flows x 6 STRIDE categories
    Attack Trees.drawio / .md       AT1-AT3, one page each, scored L x I
    ATLAS-Mapping.md                AML.T technique per attack tree and per attack path
    Risk-Register.xlsx / .md        Every threat ranked by Risk Score with an owner
    Identity-Inventory.md           Task 1 identity inventory
"""

import html
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

import threat_model_data as D

HERE = os.path.dirname(os.path.abspath(__file__))
CAT_NAME = dict(D.STRIDE)
BAND_COLOURS = {  # fill, stroke (draw.io defaults)
    "Low": ("#d5e8d4", "#82b366"),
    "Medium": ("#fff2cc", "#d6b656"),
    "High": ("#ffe6cc", "#d79b00"),
    "Critical": ("#f8cecc", "#b85450"),
    "N/A": ("#eeeeee", "#999999"),
}
PATH_RED = "#C00000"


def band(score):
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def atlas_label(tid):
    return f"{tid} {D.ATLAS_NAMES[tid]}" if tid else ""


# ---------------------------------------------------------------------------
# Model assembly + validation
# ---------------------------------------------------------------------------
FLOW_BY_ID = {f[0]: f for f in D.FLOWS}
ELEM_BY_KEY = {e[0]: e for e in D.ELEMENTS}


def build_threats():
    threats = []
    for fid, _src, _dst, *_ in D.FLOWS:
        entries = D.THREATS[fid]
        cats = [e[0] for e in entries]
        assert cats == [c for c, _ in D.STRIDE], f"{fid} must list S,T,R,I,D,E in order, got {cats}"
        for e in entries:
            tid = f"T-{fid}-{e[0]}"
            if e[1] is None:
                threats.append({"id": tid, "flow": fid, "cat": e[0], "na": True, "title": "N/A", "threat": e[2],
                                "mitigation": "", "L": None, "I": None, "risk": None, "band": "N/A",
                                "owner": "", "owasp": "", "atlas": ""})
                continue
            _c, title, text, mit, L, I, owner, owasp, atlas = e
            assert 1 <= L <= 5 and 1 <= I <= 5, tid
            assert owner in D.OWNERS, f"{tid}: unknown owner {owner}"
            assert not atlas or atlas in D.ATLAS_NAMES, f"{tid}: unknown ATLAS id {atlas}"
            threats.append({"id": tid, "flow": fid, "cat": e[0], "na": False, "title": title, "threat": text,
                            "mitigation": mit, "L": L, "I": I, "risk": L * I, "band": band(L * I),
                            "owner": D.OWNERS[owner], "owasp": owasp, "atlas": atlas})
    return threats


def score_tree(node):
    """Propagate L/I up the tree. AND: L=min, I=max. OR: highest-risk child (tie: higher I, then first)."""
    if not node["children"]:
        node["R"] = node["L"] * node["I"]
        return node
    for c in node["children"]:
        score_tree(c)
    if node["gate"] == "AND":
        node["L"] = min(c["L"] for c in node["children"])
        node["I"] = max(c["I"] for c in node["children"])
    else:
        best = max(node["children"], key=lambda c: (c["R"], c["I"]))
        node["L"], node["I"] = best["L"], best["I"]
    node["R"] = node["L"] * node["I"]
    return node


def mark_path(node):
    """Highest-risk path: AND -> every child is needed; OR -> the child that set the score."""
    node["hot"] = True
    if not node["children"]:
        return
    if node["gate"] == "AND":
        for c in node["children"]:
            mark_path(c)
    else:
        best = max(node["children"], key=lambda c: (c["R"], c["I"]))
        mark_path(best)


def walk(node, depth=0):
    yield node, depth
    for c in node["children"]:
        yield from walk(c, depth + 1)


def validate(threats):
    by_id = {t["id"]: t for t in threats}
    problems = []
    expected_roots = {"AT1": 20, "AT2": 20, "AT3": 16}  # used by 05-policy; change both together
    for tree in D.ATTACK_TREES:
        root = score_tree(tree["root"])
        mark_path(root)
        if root["R"] != expected_roots[tree["key"]]:
            problems.append(f"{tree['key']} root risk {root['R']} != expected {expected_roots[tree['key']]}")
        for n, _ in walk(root):
            n.setdefault("hot", False)
            if n["atlas"] and n["atlas"] not in D.ATLAS_NAMES:
                problems.append(f"{n['id']}: unknown ATLAS id {n['atlas']}")
            for ref in n["refs"]:
                t = by_id.get(ref)
                if t is None or t["na"]:
                    problems.append(f"{n['id']}: reference {ref} missing or N/A")
                elif t["risk"] < n["R"]:
                    problems.append(f"{n['id']} (risk {n['R']}) references {ref} scored lower ({t['risk']})")
    if problems:
        sys.exit("Validation failed:\n  " + "\n  ".join(problems))
    # Attack-tree back references for the register
    for tree in D.ATTACK_TREES:
        for n, _ in walk(tree["root"]):
            for ref in n["refs"]:
                by_id[ref].setdefault("trees", []).append(n["id"])


# ---------------------------------------------------------------------------
# OWASP Threat Dragon v2 model
# ---------------------------------------------------------------------------
def td_uuid(prefix, n):
    return f"{prefix}0000000-0000-4000-8000-{n:012d}"


def build_threat_dragon(threats):
    cells, ids = [], {}
    for i, (tb, label, desc, (x, y, w, h)) in enumerate(D.BOUNDARIES, 1):
        cells.append({
            "position": {"x": x, "y": y}, "size": {"width": w, "height": h},
            "attrs": {"label": {"text": label}}, "visible": True, "shape": "trust-boundary-box",
            "zIndex": -1, "id": td_uuid("b", i),
            "data": {"type": "tm.BoundaryBox", "name": label, "description": desc,
                     "isTrustBoundary": True, "hasOpenThreats": False},
        })
    for i, (key, shape, label, tb, desc, (x, y, w, h)) in enumerate(D.ELEMENTS, 1):
        cid = td_uuid("c", i)
        ids[key] = cid
        line = {"stroke": "#333333", "strokeWidth": 1.5, "strokeDasharray": ""}
        base = {"name": label, "description": f"{desc} Boundary: {tb or 'external (no boundary)'}.",
                "outOfScope": False, "reasonOutOfScope": "", "hasOpenThreats": False, "threats": []}
        if shape == "actor":
            data = {"type": "tm.Actor", "providesAuthentication": key == "auth0", **base}
            attrs = {"text": {"text": label}, "body": line}
        elif shape == "process":
            data = {"type": "tm.Process", "handlesCardPayment": False, "handlesGoodsOrServices": False,
                    "isWebApplication": key in ("ui", "backend"), "privilegeLevel": "", **base}
            attrs = {"text": {"text": label}, "body": line}
        else:
            data = {"type": "tm.Store", "isALog": False, "isEncrypted": True, "isSigned": False,
                    "storesCredentials": key == "secrets", "storesInventory": False, **base}
            attrs = {"text": {"text": label}, "topLine": line, "bottomLine": line}
        cells.append({"position": {"x": x, "y": y}, "size": {"width": w, "height": h}, "attrs": attrs,
                      "visible": True, "shape": shape, "zIndex": 1, "id": cid, "data": data})

    number = 0
    for i, (fid, src, dst, label, data_desc, ident, crossing, proto, verts) in enumerate(D.FLOWS, 1):
        tlist = []
        for t in (t for t in threats if t["flow"] == fid):
            number += 1
            tlist.append({
                "id": td_uuid("e", number), "number": number, "modelType": "STRIDE", "new": False,
                "type": CAT_NAME[t["cat"]],
                "title": f"{t['id']} {t['title']}",
                "status": "NotApplicable" if t["na"] else "Open",
                "severity": "TBD" if t["na"] else t["band"],
                "score": "" if t["na"] else f"L{t['L']} x I{t['I']} = {t['risk']}",
                "description": t["threat"] + ("" if t["na"] or not t["atlas"] else f" [ATLAS {atlas_label(t['atlas'])}]"),
                "mitigation": t["mitigation"] or "Not applicable (see description).",
            })
        name = f"{fid} {label}\n[{ident}]"
        cells.append({
            "shape": "flow", "width": 200, "height": 100, "zIndex": 10, "connector": "smooth",
            "attrs": {"line": {"stroke": "red", "strokeWidth": 2, "targetMarker": {"name": "block"},
                               "sourceMarker": {"name": "block"} if fid not in ("F01", "F07", "F08", "F13") else {"name": ""}}},
            "id": td_uuid("f", i), "labels": [name],
            "source": {"cell": ids[src]}, "target": {"cell": ids[dst]},
            "vertices": [{"x": vx, "y": vy} for vx, vy in verts],
            "data": {"type": "tm.Flow", "name": name,
                     "description": f"{data_desc}. Identity: {ident}. Boundary: {crossing}.",
                     "outOfScope": False, "reasonOutOfScope": "", "protocol": proto,
                     "isBidirectional": fid not in ("F01", "F07", "F08", "F13"), "isEncrypted": proto != "Local UI",
                     "isPublicNetwork": crossing.startswith(("TB1", "TB3 -> TB2", "TB4 -> TB2", "TB4 -> TB8", "External")),
                     "hasOpenThreats": True, "threats": tlist},
        })

    legend = ["IDENTITIES (Task 1)"]
    for idt in D.IDENTITIES:
        legend.append(f"{idt['id']} {idt['name']}: {idt['privilege'].split('. ')[0]}")
    legend += ["", "LAYERS: User layer TB1 -> Agent layer TB4 (F04, F06); Agent layer TB4 -> Internal API layer TB5 (F15, F16 -> F17)",
               "Red flow = open STRIDE threats. Select a flow to see its 6 STRIDE entries."]
    text = "\n".join(legend)
    cells.append({"position": {"x": 20, "y": 720}, "size": {"width": 860, "height": 200},
                  "attrs": {"text": {"text": text}}, "visible": True, "shape": "td-text-block", "zIndex": 11,
                  "id": td_uuid("d", 1), "data": {"type": "tm.Text", "name": text, "hasOpenThreats": False}})

    scored = [t for t in threats if not t["na"]]
    model = {
        "version": "2.2.0",
        "summary": {
            "title": "SecureNova AI Threat Model", "owner": "Varun Mohanta", "id": 0,
            "description": (f"STRIDE-per-flow threat model of the {D.SYSTEM}: Auth0 IdP, two-agent harness, internal REST APIs, "
                            f"RAG pipeline, MCP server, external LLM provider. {len(D.FLOWS)} identity flows x 6 STRIDE "
                            f"categories = {len(threats)} assessments ({len(scored)} threats, {len(threats) - len(scored)} N/A)."),
        },
        "detail": {
            "contributors": [], "reviewer": "", "diagramTop": 1, "threatTop": number,
            "diagrams": [{
                "id": 0, "title": "SecureNova AI Platform - Identity Data Flow (STRIDE)", "diagramType": "STRIDE",
                "placeholder": "New STRIDE diagram description", "thumbnail": "./public/content/images/thumbnail.stride.jpg",
                "version": "2.2.0", "cells": cells,
                "description": "Identity DFD with 8 trust boundaries and 6 identity types (ID-1..ID-6). Each flow carries all six STRIDE categories.",
            }],
        },
    }
    with open(os.path.join(HERE, "SecureNova-Threat-Dragon.json"), "w") as f:
        json.dump(model, f, indent=2)


# ---------------------------------------------------------------------------
# draw.io helpers
# ---------------------------------------------------------------------------
class DrawioPage:
    def __init__(self, name, dx=2400, dy=1400):
        self.diagram = ET.Element("diagram", id=name.replace(" ", "-"), name=name)
        self.model = ET.SubElement(self.diagram, "mxGraphModel", dx=str(dx), dy=str(dy), grid="0", gridSize="10",
                                   guides="1", tooltips="1", connect="1", arrows="1", fold="1", page="0",
                                   pageScale="1", pageWidth="1600", pageHeight="1200", math="0", shadow="0",
                                   background="#FFFFFF")
        self.root = ET.SubElement(self.model, "root")
        ET.SubElement(self.root, "mxCell", id="0")
        ET.SubElement(self.root, "mxCell", id="1", parent="0")
        self.n = 1

    def vertex(self, value, style, x, y, w, h, cid=None):
        self.n += 1
        cid = cid or f"v{self.n}"
        c = ET.SubElement(self.root, "mxCell", id=cid, value=value, style=style, vertex="1", parent="1")
        ET.SubElement(c, "mxGeometry", x=str(x), y=str(y), width=str(w), height=str(h), **{"as": "geometry"})
        return cid

    def edge(self, src, dst, style, value="", points=()):
        self.n += 1
        c = ET.SubElement(self.root, "mxCell", id=f"e{self.n}", value=value, style=style, edge="1",
                          parent="1", source=src, target=dst)
        g = ET.SubElement(c, "mxGeometry", relative="1", **{"as": "geometry"})
        if points:
            arr = ET.SubElement(g, "Array", **{"as": "points"})
            for px, py in points:
                ET.SubElement(arr, "mxPoint", x=str(px), y=str(py))


def write_drawio(pages, filename):
    mxfile = ET.Element("mxfile", host="Electron", agent="build_threat_model.py", type="device")
    for p in pages:
        mxfile.append(p.diagram)
    ET.indent(mxfile)
    ET.ElementTree(mxfile).write(os.path.join(HERE, filename), encoding="utf-8", xml_declaration=False)


# ---------------------------------------------------------------------------
# Attack trees (draw.io)
# ---------------------------------------------------------------------------
LEAF_W, NODE_H, GAP, LEVEL_H = 200, 100, 24, 210
TOP = 200


def subtree_width(n):
    if not n["children"]:
        n["w"] = LEAF_W
    else:
        n["w"] = max(LEAF_W, sum(subtree_width(c) for c in n["children"]) + GAP * (len(n["children"]) - 1))
    return n["w"]


def place(n, x0, depth):
    n["x"] = x0 + n["w"] / 2 - LEAF_W / 2
    n["y"] = TOP + depth * LEVEL_H
    cx = x0 + (n["w"] - (sum(c["w"] for c in n["children"]) + GAP * (len(n["children"]) - 1))) / 2
    for c in n["children"]:
        place(c, cx, depth + 1)
        cx += c["w"] + GAP


def node_label(n, tree=None):
    e = html.escape
    head = f"<b>{e(n['id'])}</b> {e(n['text'])}"
    if n["children"]:
        head = f"<b>{e(n['id'])}</b> [{n['gate']}] {e(n['text'])}"
    meta = " | ".join(x for x in [", ".join(n["refs"]), n["atlas"]] if x)
    if tree is not None:
        meta = f"{tree['owasp'].split(' / ')[0].split(' ')[0]} | {tree['atlas_primary'][0]}"
    risk = f"<b>L{n['L']} x I{n['I']} = {n['R']}</b> ({band(n['R'])})"
    return f"{head}<br><font style=\"font-size:9px\" color=\"#555555\">{e(meta)}</font><br>{risk}"


def build_attack_trees():
    pages = []
    for tree in D.ATTACK_TREES:
        root = tree["root"]
        subtree_width(root)
        place(root, 40, 0)
        p = DrawioPage(tree["page"])
        width = root["w"] + 80
        p.vertex(f"<b>{tree['key']} - {html.escape(tree['title'])}</b> - {html.escape(D.SYSTEM)}",
                 "text;html=1;fontSize=22;align=left;verticalAlign=middle;", 40, 20, 1100, 40)
        p.vertex(f"Root goal risk: <b>L{root['L']} x I{root['I']} = {root['R']} ({band(root['R'])})</b>. "
                 f"MITRE ATLAS: <b>{tree['atlas_primary'][0]} {html.escape(tree['atlas_primary'][1])}</b>. "
                 f"OWASP: {html.escape(tree['owasp'])}. Threat IDs (T-Fxx-X) trace to STRIDE-Matrix.xlsx.",
                 "text;html=1;fontSize=13;align=left;verticalAlign=top;whiteSpace=wrap;", 40, 62, 1300, 40)
        lx = max(width - 470, 1360)
        p.vertex("<b>Scoring</b><br>Likelihood (L): 1 Rare, 2 Unlikely, 3 Possible, 4 Likely, 5 Almost certain<br>"
                 "Impact (I): 1 Negligible, 2 Minor, 3 Moderate, 4 Major, 5 Severe<br>"
                 "<b>Risk = L x I</b> (1-25), inherent (before Project 4 controls)<br>"
                 "AND gate: L = min(children), I = max(children)<br>OR gate: highest-risk child propagates",
                 "rounded=1;whiteSpace=wrap;html=1;align=left;verticalAlign=top;spacingLeft=8;fontSize=11;arcSize=6;",
                 lx, 15, 430, 100)
        for i, b in enumerate(["Low", "Medium", "High", "Critical"]):
            rng = {"Low": "1-5", "Medium": "6-10", "High": "12-16", "Critical": "20-25"}[b]
            fill, stroke = BAND_COLOURS[b]
            p.vertex(f"{b} {rng}", f"rounded=0;whiteSpace=wrap;html=1;fontSize=10;fillColor={fill};strokeColor={stroke};",
                     lx + i * 108, 122, 100, 22)
        a = p.vertex("", "text;", lx, 158, 1, 1)
        bb = p.vertex("Highest-risk attack path", "text;html=1;fontSize=10;align=left;verticalAlign=middle;", lx + 60, 148, 200, 20)
        p.edge(a, bb, f"endArrow=none;html=1;strokeColor={PATH_RED};strokeWidth=3;")

        for n, depth in walk(root):
            fill, stroke = BAND_COLOURS[band(n["R"])]
            hot = n["hot"]
            style = (f"rounded=1;whiteSpace=wrap;html=1;fontSize=11;arcSize=8;fillColor={fill};"
                     f"strokeColor={PATH_RED if hot else stroke};strokeWidth={3 if hot else 1};")
            is_root = depth == 0
            n["cid"] = p.vertex(node_label(n, tree if is_root else None), style + ("fontSize=12;" if is_root else ""),
                                n["x"] - (20 if is_root else 0), n["y"], LEAF_W + (40 if is_root else 0), NODE_H)
            if n["children"]:
                gfill = "#dae8fc" if n["gate"] == "AND" else "#e1d5e7"
                gstroke = "#6c8ebf" if n["gate"] == "AND" else "#9673a6"
                n["gid"] = p.vertex(f"<b>{n['gate']}</b>", f"ellipse;whiteSpace=wrap;html=1;fontSize=10;fillColor={gfill};strokeColor={gstroke};",
                                    n["x"] + LEAF_W / 2 - 28, n["y"] + NODE_H + 18, 56, 26)
                p.edge(n["cid"], n["gid"], f"endArrow=none;html=1;strokeColor={PATH_RED if hot else '#666666'};strokeWidth={3 if hot else 1};")
                for c in n["children"]:
                    on_path = hot and c["hot"]
                    c["_edge"] = (n["gid"], on_path)
        for n, _ in walk(root):
            if "_edge" in n:
                gid, on_path = n["_edge"]
                p.edge(gid, n["cid"], f"edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=none;"
                                      f"strokeColor={PATH_RED if on_path else '#888888'};strokeWidth={3 if on_path else 1};")
        pages.append(p)
    write_drawio(pages, "Attack Trees.drawio")


# ---------------------------------------------------------------------------
# DFD (draw.io copy of the Threat Dragon diagram)
# ---------------------------------------------------------------------------
def build_dfd_drawio():
    p = DrawioPage("Identity DFD")
    for tb, label, desc, (x, y, w, h) in D.BOUNDARIES:
        p.vertex(label, "rounded=0;whiteSpace=wrap;html=1;dashed=1;dashPattern=8 4;fillColor=none;strokeColor=#CC0000;"
                        "strokeWidth=2;verticalAlign=top;align=left;spacingLeft=6;fontStyle=1;fontColor=#CC0000;fontSize=11;",
                 x, y, w, h)
    ids = {}
    for key, shape, label, tb, desc, (x, y, w, h) in D.ELEMENTS:
        val = html.escape(label).replace("\n", "<br>")
        if shape == "actor":
            style = "rounded=0;whiteSpace=wrap;html=1;fillColor=#f5f5f5;strokeColor=#333333;fontStyle=1;"
        elif shape == "process":
            style = "ellipse;whiteSpace=wrap;html=1;aspect=fixed;fillColor=#dae8fc;strokeColor=#333333;fontStyle=1;"
        else:
            style = "shape=partialRectangle;whiteSpace=wrap;html=1;left=0;right=0;fillColor=#fff2cc;strokeColor=#333333;fontStyle=1;"
        ids[key] = p.vertex(val, style, x, y, w, h)
    for fid, src, dst, label, _d, ident, crossing, _p, verts in D.FLOWS:
        both = fid not in ("F01", "F07", "F08", "F13")
        style = ("html=1;rounded=1;strokeColor=#CC0000;strokeWidth=1.5;endArrow=block;endFill=1;fontSize=9;"
                 "labelBackgroundColor=#FFFFFF;" + ("startArrow=block;startFill=1;" if both else ""))
        p.edge(ids[src], ids[dst], style, f"<b>{fid}</b> {html.escape(label)}<br>[{html.escape(ident)}]", verts)
    legend = "<b>IDENTITIES (Task 1)</b><br>" + "<br>".join(
        f"<b>{i['id']}</b> {html.escape(i['name'])}: {html.escape(i['privilege'].split('. ')[0])}" for i in D.IDENTITIES)
    legend += ("<br><br>User layer TB1 -> Agent layer TB4 via F04, F06. Agent layer TB4 -> Internal API layer TB5 via F15, F16 -> F17."
               "<br>Red dashed box = trust boundary. Every flow has 6 STRIDE entries (STRIDE-Matrix.xlsx).")
    p.vertex(legend, "text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;fontSize=11;spacing=6;strokeColor=#999999;", 20, 720, 860, 170)
    p.vertex(f"<b>{html.escape(D.SYSTEM)} - Identity data-flow diagram</b>",
             "text;html=1;fontSize=18;align=left;", 20, -30, 900, 30)
    write_drawio([p], "Threat Model.drawio")


# ---------------------------------------------------------------------------
# Excel workbooks
# ---------------------------------------------------------------------------
THIN = Side(style="thin", color="BBBBBB")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
HEAD_FILL = PatternFill("solid", fgColor="1F3864")
HEAD_FONT = Font(bold=True, color="FFFFFF")
WRAP = Alignment(wrap_text=True, vertical="top")


def fill_for(b):
    return PatternFill("solid", fgColor=BAND_COLOURS[b][0].lstrip("#").upper())


def write_sheet(ws, headers, rows, widths, band_col=None, freeze="A2"):
    ws.append(headers)
    for c in ws[1]:
        c.fill, c.font, c.alignment, c.border = HEAD_FILL, HEAD_FONT, Alignment(wrap_text=True, vertical="center"), BORDER
    for r in rows:
        ws.append(r)
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment, c.border = WRAP, BORDER
        if band_col is not None:
            b = row[band_col].value
            if b in BAND_COLOURS:
                for c in row[band_col - 2: band_col + 1]:
                    c.fill = fill_for(b)
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = freeze
    ws.auto_filter.ref = ws.dimensions


def build_stride_xlsx(threats):
    wb = Workbook()
    ws = wb.active
    ws.title = "STRIDE Matrix"
    headers = ["Flow", "Source -> Destination", "Identity", "Boundary"] + [f"{c} - {n}" for c, n in D.STRIDE]
    ws.append(headers)
    for c in ws[1]:
        c.fill, c.font, c.border = HEAD_FILL, HEAD_FONT, BORDER
        c.alignment = Alignment(wrap_text=True, vertical="center", horizontal="center")
    for fid, src, dst, label, _d, ident, crossing, *_ in D.FLOWS:
        row = [fid, f"{ELEM_BY_KEY[src][2].splitlines()[0]} -> {ELEM_BY_KEY[dst][2].splitlines()[0]}\n({label})", ident, crossing]
        bands = []
        for t in (t for t in threats if t["flow"] == fid):
            if t["na"]:
                row.append(f"N/A - {t['threat'][5:]}" if t["threat"].startswith("N/A:") else f"N/A - {t['threat']}")
            else:
                row.append(f"{t['id']}\n{t['title']}\nL{t['L']}xI{t['I']}={t['risk']} {t['band']}")
            bands.append(t["band"])
        ws.append(row)
        for c, b in zip(ws[ws.max_row][4:], bands):
            c.fill = fill_for(b)
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment, c.border = Alignment(wrap_text=True, vertical="top"), BORDER
            c.font = Font(size=9)
        row[0].font = Font(bold=True, size=10)
        ws.row_dimensions[row[0].row].height = 62
    ws.row_dimensions[1].height = 30
    for i, w in enumerate([6, 30, 16, 14, 25, 25, 25, 25, 25, 25], 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = "E2"
    n_scored = sum(not t["na"] for t in threats)
    ws.cell(row=ws.max_row + 2, column=1,
            value=(f"{len(D.FLOWS)} flows x 6 categories = {len(threats)} cells: {n_scored} scored threats, "
                   f"{len(threats) - n_scored} justified N/A. Colour = risk band (Risk = L x I). Detail and mitigations: 'Threat Detail' sheet.")).font = Font(italic=True)

    ws2 = wb.create_sheet("Threat Detail")
    write_sheet(ws2, ["Threat ID", "Flow", "STRIDE", "Title", "Threat", "Mitigation", "L", "I", "Risk", "Band",
                      "Owner", "OWASP LLM", "MITRE ATLAS"],
                [[t["id"], t["flow"], CAT_NAME[t["cat"]], t["title"], t["threat"], t["mitigation"], t["L"], t["I"],
                  t["risk"], t["band"], t["owner"], t["owasp"], atlas_label(t["atlas"])] for t in threats],
                [10, 6, 14, 26, 50, 50, 4, 4, 6, 9, 20, 14, 30], band_col=9)

    ws3 = wb.create_sheet("Identities")
    write_sheet(ws3, ["ID", "Identity", "Type", "Where", "Authentication mechanism", "Credential", "Privilege level", "Lifetime"],
                [[i["id"], i["name"], i["type"], i["where"], i["authn"], i["credential"], i["privilege"], i["lifetime"]]
                 for i in D.IDENTITIES], [6, 24, 16, 26, 50, 30, 45, 22])
    ws4 = wb.create_sheet("Flows")
    write_sheet(ws4, ["Flow", "Source", "Destination", "Data / credential", "Identity", "Boundary crossed", "Protocol"],
                [[f[0], ELEM_BY_KEY[f[1]][2].replace("\n", " "), ELEM_BY_KEY[f[2]][2].replace("\n", " "), f[4], f[5], f[6], f[7]]
                 for f in D.FLOWS], [6, 24, 24, 50, 22, 22, 18])
    ws5 = wb.create_sheet("Trust Boundaries")
    members = {}
    for key, _s, label, tb, *_ in D.ELEMENTS:
        members.setdefault(tb, []).append(label.split("\n")[0])
    write_sheet(ws5, ["ID", "Boundary", "Components inside", "Why it is a boundary"],
                [[b[0], b[1], ", ".join(members.get(b[0], [])), b[2]] for b in D.BOUNDARIES], [6, 32, 40, 60])
    wb.save(os.path.join(HERE, "STRIDE-Matrix.xlsx"))


def ranked(threats):
    scored = [t for t in threats if not t["na"]]
    return sorted(scored, key=lambda t: (-t["risk"], -t["I"], t["id"]))


def build_register_xlsx(threats):
    wb = Workbook()
    ws = wb.active
    ws.title = "Risk Register"
    rows = []
    for rank, t in enumerate(ranked(threats), 1):
        f = FLOW_BY_ID[t["flow"]]
        rows.append([rank, f"R-{rank:02d}", t["id"], f"{t['flow']} {f[3]}", f[5], CAT_NAME[t["cat"]], t["title"],
                     t["L"], t["I"], t["risk"], t["band"], ", ".join(t.get("trees", [])), atlas_label(t["atlas"]),
                     t["owasp"], t["owner"], "Mitigate", t["mitigation"], D.CONTROL_PROJECT[next(k for k, v in D.OWNERS.items() if v == t["owner"])], "Open"])
    write_sheet(ws, ["Rank", "Risk ID", "Threat ID", "Flow", "Identity", "STRIDE", "Threat", "Likelihood", "Impact",
                     "Risk Score", "Band", "Attack tree node(s)", "MITRE ATLAS", "OWASP LLM", "Owner", "Treatment",
                     "Planned control", "Delivered in", "Status"],
                rows, [6, 7, 10, 26, 14, 14, 32, 6, 6, 7, 9, 14, 30, 12, 22, 10, 50, 24, 8], band_col=10, freeze="D2")
    ws.row_dimensions[1].height = 32

    ws2 = wb.create_sheet("Attack Trees")
    write_sheet(ws2, ["Tree", "Root goal", "Gate", "L", "I", "Risk Score", "Band", "Highest-risk path", "Primary ATLAS",
                      "Other ATLAS", "OWASP LLM", "Owner"],
                [[t["key"], t["goal"], t["root"]["gate"], t["root"]["L"], t["root"]["I"], t["root"]["R"], band(t["root"]["R"]),
                  " -> ".join(n["id"] for n, _ in walk(t["root"]) if n["hot"] and not n["children"]),
                  f"{t['atlas_primary'][0]} {t['atlas_primary'][1]}",
                  "; ".join(f"{a} {b}" for a, b in t["atlas_secondary"]), t["owasp"], D.OWNERS[t["owner"]]]
                 for t in sorted(D.ATTACK_TREES, key=lambda t: -t["root"]["R"])],
                [6, 40, 6, 4, 4, 7, 9, 30, 32, 50, 40, 22], band_col=6)

    ws3 = wb.create_sheet("ATLAS Mapping")
    write_sheet(ws3, ["Tree", "Node", "Attack path step", "L", "I", "Risk", "Band", "On highest-risk path",
                      "ATLAS ID", "ATLAS technique", "STRIDE threat(s)"],
                [[t["key"], n["id"], n["text"] + (f" [{n['gate']}]" if n["children"] else ""), n["L"], n["I"], n["R"],
                  band(n["R"]), "Yes" if n["hot"] else "", n["atlas"] or t["atlas_primary"][0],
                  D.ATLAS_NAMES[n["atlas"] or t["atlas_primary"][0]], ", ".join(n["refs"])]
                 for t in D.ATTACK_TREES for n, _ in walk(t["root"])],
                [6, 8, 55, 4, 4, 6, 9, 10, 14, 40, 18], band_col=6)
    ws4 = wb.create_sheet("Scoring Key")
    write_sheet(ws4, ["Score", "Likelihood", "Impact"],
                [[5, "Almost certain", "Severe: admin takeover, credential leak, mass data exposure"],
                 [4, "Likely", "Major: cross-user data exposure, privileged action"],
                 [3, "Possible", "Moderate: limited data exposure or service degradation"],
                 [2, "Unlikely", "Minor: small, recoverable impact"],
                 [1, "Rare", "Negligible"]], [8, 18, 60])
    ws4.append([])
    for b, rng in [("Low", "1-5"), ("Medium", "6-10"), ("High", "12-16"), ("Critical", "20-25")]:
        ws4.append([rng, b, "Risk Score = Likelihood x Impact"])
        ws4[ws4.max_row][1].fill = fill_for(b)
    wb.save(os.path.join(HERE, "Risk-Register.xlsx"))


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(str(x).replace("|", "/").replace("\n", " ") for x in r) + " |")
    return "\n".join(out)


def write(name, text):
    with open(os.path.join(HERE, name), "w") as f:
        f.write(text.rstrip() + "\n")


def build_markdown(threats):
    n_scored = sum(not t["na"] for t in threats)
    members = {}
    for key, _s, label, tb, *_ in D.ELEMENTS:
        members.setdefault(tb, []).append(label.split("\n")[0])

    write("Identity-Inventory.md", "\n\n".join([
        "# Identity Inventory - " + D.SYSTEM,
        "Project 1 - Task 1. Every identity in the platform, how it authenticates and what it is allowed to do. "
        "Generated from `threat_model_data.py`.",
        md_table(["ID", "Identity", "Type", "Where", "Authentication mechanism", "Privilege level", "Lifetime"],
                 [[i["id"], i["name"], i["type"], i["where"], i["authn"], i["privilege"], i["lifetime"]] for i in D.IDENTITIES]),
        "## Supporting identities",
        md_table(["Identity", "Authentication", "Privilege"], D.SUPPORTING_IDENTITIES),
        "## Key observations",
        "1. **ID-4 (LLM API key)** is the only static, non-expiring credential and is not scoped per user. It is the target of Attack Tree 1.\n"
        "2. **ID-2 (AI agent)** has no cryptographic identity of its own at the start: Agent B trusts message text. This is the root of Attack Tree 2.\n"
        "3. **ID-5 (RAG)** serves content that came from untrusted sources (F13), so retrieved text cannot be trusted as instructions. This is Attack Tree 3.\n"
        "4. Non-human identities (ID-2 to ID-6) must never hold more privilege than the human they act for (no standing `write:admin`).",
    ]))

    parts = ["# STRIDE Matrix - " + D.SYSTEM,
             "Project 1 - Task 2. Every identity flow in the data-flow diagram is checked against all six STRIDE categories. "
             f"{len(D.FLOWS)} flows x 6 = **{len(threats)} cells**: **{n_scored} scored threats** and **{len(threats) - n_scored} justified N/A**. "
             "Spreadsheet version: [STRIDE-Matrix.xlsx](./STRIDE-Matrix.xlsx). Diagram: [SecureNova-Threat-Dragon.json](./SecureNova-Threat-Dragon.json).",
             "Threat ID format: `T-<flow>-<category>`, e.g. `T-F14-S`. Risk = Likelihood x Impact (see [Risk-Register.md](./Risk-Register.md)).",
             "## 1. Trust boundaries",
             md_table(["ID", "Boundary", "Components inside", "Why it is a boundary"],
                      [[b[0], b[1], ", ".join(members.get(b[0], [])), b[2]] for b in D.BOUNDARIES]),
             "The three layers named in the brief: **User layer (TB1) -> Agent layer (TB4)** through F04 and F06; "
             "**Agent layer (TB4) -> Internal API layer (TB5)** through F15 directly and F16 -> F17 via the MCP server.",
             "## 2. Identity flows",
             md_table(["Flow", "Source -> Destination", "Data / credential", "Identity", "Boundary"],
                      [[f[0], f"{ELEM_BY_KEY[f[1]][2].splitlines()[0]} -> {ELEM_BY_KEY[f[2]][2].splitlines()[0]}", f[4], f[5], f[6]] for f in D.FLOWS]),
             "## 3. Matrix overview (risk score per cell)"]
    rows = []
    for f in D.FLOWS:
        cells = []
        for t in (t for t in threats if t["flow"] == f[0]):
            cells.append("N/A" if t["na"] else f"{t['title']} **{t['risk']}**")
        rows.append([f"{f[0]} {f[3]}"] + cells)
    parts.append(md_table(["Flow"] + [n for _, n in D.STRIDE], rows))
    parts.append("## 4. Threat detail (flow by flow)")
    for f in D.FLOWS:
        parts.append(f"### {f[0]} - {f[3]} ({f[5]}, {f[6]})")
        parts.append(md_table(["ID", "Cat", "Threat", "Mitigation", "L", "I", "Risk", "Owner", "ATLAS"],
                              [[t["id"], t["cat"], t["threat"], t["mitigation"] or "-", t["L"] or "-", t["I"] or "-",
                                f"**{t['risk']}** {t['band']}" if t["risk"] else "N/A", t["owner"] or "-", t["atlas"] or "-"]
                               for t in threats if t["flow"] == f[0]]))
    write("STRIDE-Matrix.md", "\n\n".join(parts))

    parts = ["# Attack Trees - " + D.SYSTEM,
             "Project 1 - Task 3. Editable file: [Attack Trees.drawio](./Attack%20Trees.drawio) (one page per tree). PNG exports: "
             "[AT1](./Attack%20Tree%201%20-%20LLM%20API%20Key%20Exfiltration.png), "
             "[AT2](./Attack%20Tree%202%20-%20Agent%20Identity%20Spoofing.png), "
             "[AT3](./Attack%20Tree%203%20-%20RAG%20Chunk%20Poisoning.png).",
             "## Scoring method",
             "- **Likelihood (L) 1-5:** 1 Rare, 2 Unlikely, 3 Possible, 4 Likely, 5 Almost certain\n"
             "- **Impact (I) 1-5:** 1 Negligible, 2 Minor, 3 Moderate, 4 Major, 5 Severe\n"
             "- **Risk Score = L x I** (1-25), inherent risk before the Project 4 controls. Bands: Low 1-5, Medium 6-10, High 12-16, Critical 20-25.\n"
             "- **AND gate** (every child needed): L = lowest child L (hardest step limits the attack), I = highest child I.\n"
             "- **OR gate** (any child is enough): the highest-risk child propagates up.\n"
             "- The **highest-risk path** is drawn with thick red outlines and edges, and marked with a dot (●) below.",
             "## Results",
             md_table(["Tree", "Root goal", "Gate", "L", "I", "Risk", "Band", "Highest-risk path (leaves)", "MITRE ATLAS"],
                      [[t["key"], t["goal"], t["root"]["gate"], t["root"]["L"], t["root"]["I"], f"**{t['root']['R']}**", band(t["root"]["R"]),
                        " + ".join(n["id"] for n, _ in walk(t["root"]) if n["hot"] and not n["children"]),
                        f"{t['atlas_primary'][0]} {t['atlas_primary'][1]}"] for t in D.ATTACK_TREES]),
             "The trees chain together: AT3 can deliver the injection for AT1 (1.2.3), and AT1 can supply the stolen credential for AT2 (2.1.1.4)."]
    for t in D.ATTACK_TREES:
        parts.append(f"### {t['key']} - {t['title']}")
        parts.append(md_table(["Node", "Description", "STRIDE ref", "ATLAS", "L", "I", "Risk", "Band", "Path"],
                              [[n["id"], (f"[{n['gate']}] " if n["children"] else "") + n["text"], ", ".join(n["refs"]) or "-",
                                n["atlas"] or "-", n["L"], n["I"], f"**{n['R']}**", band(n["R"]), "●" if n["hot"] else ""]
                               for n, _ in walk(t["root"])]))
    parts.append("## Key observations\n\n"
                 "1. **AT1 (20, Critical):** every AND branch has a Likely option. The decisive weakness is a credential inside model-readable context (1.1.1). "
                 "Removing secrets from the prompt drops branch 1.1 to L2, which caps the whole tree at L2 x I5 = 10 (Medium). Output redaction (1.4.1) is the second choke point.\n"
                 "2. **AT2 (20, Critical):** the root is an OR, so the easiest branch sets the risk. Unsigned agent-to-agent messages (2.2.3) beat credential theft. "
                 "Ed25519-signed messages (Project 4) are the primary control; least privilege (2.1.2) and short-lived tokens (2.1.3) close the replay branch.\n"
                 "3. **AT3 (16, High):** a normal ingestion channel and keyword stuffing need no privileges. Ingestion quarantine (3.1), tenant filters (3.2) and "
                 "spotlighting plus human approval for privileged tools (3.3) each cut the AND chain.")
    write("Attack-Trees.md", "\n\n".join(parts))

    parts = ["# MITRE ATLAS Mapping - " + D.SYSTEM,
             "Project 1 - Task 4. Each attack tree is mapped to its closest MITRE ATLAS technique ([atlas.mitre.org](https://atlas.mitre.org/)), "
             "and every attack path (node) has its own AML.T technique ID. IDs checked against ATLAS data v5.6.0.",
             "## Tree-level mapping",
             md_table(["Tree", "Root goal", "Risk", "Primary technique", "Why it is the closest match", "Supporting techniques", "Technique page"],
                      [[t["key"], t["goal"], f"**{t['root']['R']}** {band(t['root']['R'])}", f"**{t['atlas_primary'][0]}** {t['atlas_primary'][1]}",
                        {"AT1": "The attack is driven by instructions hidden in content the agent reads; the key leaves through the model's own output.",
                         "AT2": "The attacker poses as a trusted agent (the orchestrator) so Agent B acts on its behalf; Project 3 used the same mapping.",
                         "AT3": "Malicious content is placed in data indexed by the RAG system to steer future answers - the exact ATLAS definition."}[t["key"]],
                        "; ".join(f"{a} {b}" for a, b in t["atlas_secondary"]),
                        f"https://atlas.mitre.org/techniques/{t['atlas_primary'][0]}"] for t in D.ATTACK_TREES])]
    for t in D.ATTACK_TREES:
        parts.append(f"## {t['key']} - {t['title']}: path-level mapping")
        parts.append(md_table(["Node", "Attack path step", "Risk", "ATLAS ID", "Technique"],
                              [[n["id"] + (" ●" if n["hot"] else ""), (f"[{n['gate']}] " if n["children"] else "") + n["text"], n["R"],
                                n["atlas"] or t["atlas_primary"][0], D.ATLAS_NAMES[n["atlas"] or t["atlas_primary"][0]]]
                               for n, _ in walk(t["root"])]))
    write("ATLAS-Mapping.md", "\n\n".join(parts))

    rk = ranked(threats)
    counts = {b: sum(t["band"] == b for t in rk) for b in ["Critical", "High", "Medium", "Low"]}
    owners = {}
    for t in rk:
        owners[t["owner"]] = owners.get(t["owner"], 0) + 1
    parts = ["# Risk Register - " + D.SYSTEM,
             f"Project 1 - Task 4. All **{len(rk)} scored threats** from the STRIDE matrix, ranked by Risk Score (Likelihood x Impact), "
             "each with an owner, MITRE ATLAS technique and planned control. Spreadsheet: [Risk-Register.xlsx](./Risk-Register.xlsx). "
             "Ties are ordered by higher Impact, then Threat ID.",
             "**Summary:** " + ", ".join(f"{v} {k}" for k, v in counts.items()) + ".",
             md_table(["Owner", "Threats owned"], sorted(owners.items(), key=lambda x: -x[1])),
             "## Attack tree roots",
             md_table(["Tree", "Root goal", "Risk", "ATLAS", "Owner"],
                      [[t["key"], t["goal"], f"**{t['root']['R']}** {band(t['root']['R'])}", t["atlas_primary"][0], D.OWNERS[t["owner"]]]
                       for t in D.ATTACK_TREES]),
             "## Ranked register",
             md_table(["Rank", "Risk ID", "Threat ID", "STRIDE", "Threat", "L", "I", "Risk", "Band", "ATLAS", "Attack tree", "Owner"],
                      [[i, f"R-{i:02d}", t["id"], CAT_NAME[t["cat"]], t["title"], t["L"], t["I"], f"**{t['risk']}**", t["band"],
                        t["atlas"] or "-", ", ".join(t.get("trees", [])) or "-", t["owner"]] for i, t in enumerate(rk, 1)])]
    write("Risk-Register.md", "\n\n".join(parts))


# ---------------------------------------------------------------------------
def export_pngs():
    exe = shutil.which("drawio")
    if not exe:
        sys.exit("draw.io CLI not found; open the .drawio files in draw.io and use File > Export as > PNG instead.")
    prefix = ["xvfb-run", "-a"] if shutil.which("xvfb-run") and not os.environ.get("DISPLAY") else []
    jobs = [("Threat Model.drawio", 0, "Threat Model.png")] + [
        ("Attack Trees.drawio", i, f"Attack Tree {i + 1} - {t['title']}.png") for i, t in enumerate(D.ATTACK_TREES)]
    for src, page, out in jobs:
        subprocess.run(prefix + [exe, "--no-sandbox", "--disable-dev-shm-usage", "-x", "-f", "png", "-s", "2", "-b", "20", "-p", str(page + 1),
                                 "-o", os.path.join(HERE, out), os.path.join(HERE, src)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("exported", out)


def main():
    threats = build_threats()
    validate(threats)
    build_threat_dragon(threats)
    build_dfd_drawio()
    build_attack_trees()
    build_stride_xlsx(threats)
    build_register_xlsx(threats)
    build_markdown(threats)
    n = sum(not t["na"] for t in threats)
    print(f"{len(D.FLOWS)} flows, {len(threats)} STRIDE cells, {n} threats, {len(threats) - n} N/A; "
          + ", ".join(f"{t['key']}={t['root']['R']}" for t in D.ATTACK_TREES))
    if "--png" in sys.argv:
        export_pngs()


if __name__ == "__main__":
    main()
