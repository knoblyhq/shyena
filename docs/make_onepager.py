"""Build the one-page Shyena overview (docs/Shyena_OnePager.docx).

    python docs/make_onepager.py

Plain python-docx; Knobly-neutral styling, no banner, A4, generous margins.
"""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

OUT = Path(__file__).parent / "Shyena_OnePager.docx"

INK = RGBColor(0x1F, 0x23, 0x28)
MUTED = RGBColor(0x6B, 0x72, 0x7A)
ACCENT = RGBColor(0x8A, 0x4B, 0x1C)  # hawk-brown accent, used sparingly
RULE = "C9CED3"


def set_cell_shading(cell, hex_fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    tc_pr.append(shd)


def set_cell_borders(cell, color: str = RULE, bottom_only: bool = True) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    sides = ["bottom"] if bottom_only else ["top", "left", "bottom", "right"]
    for side in ["top", "left", "bottom", "right"]:
        el = OxmlElement(f"w:{side}")
        if side in sides:
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), "4")
            el.set(qn("w:color"), color)
        else:
            el.set(qn("w:val"), "nil")
        borders.append(el)
    tc_pr.append(borders)


def para(doc, text="", *, size=10, bold=False, color=INK, after=4, before=0, align=None, italic=False):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(after)
    p.paragraph_format.space_before = Pt(before)
    if align:
        p.alignment = align
    if text:
        run = p.add_run(text)
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.italic = italic
        run.font.color.rgb = color
    return p


def runs(p, parts, size=10):
    """parts: list of (text, bold) tuples."""
    for text, bold in parts:
        r = p.add_run(text)
        r.font.size = Pt(size)
        r.font.bold = bold
        r.font.color.rgb = INK


def heading(doc, text):
    p = para(doc, text.upper(), size=8.5, bold=True, color=ACCENT, before=8, after=3)
    p.paragraph_format.keep_with_next = True
    return p


def bullet(doc, text, bold_lead=None, size=9.5):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.left_indent = Cm(0.5)
    if bold_lead:
        r = p.add_run(bold_lead + " ")
        r.font.bold = True
        r.font.size = Pt(size)
        r.font.color.rgb = INK
    r = p.add_run(text)
    r.font.size = Pt(size)
    r.font.color.rgb = INK
    return p


def mono(doc, lines, size=8.5):
    for line in lines:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.left_indent = Cm(0.5)
        r = p.add_run(line)
        r.font.name = "Consolas"
        r._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
        r.font.size = Pt(size)
        r.font.color.rgb = INK
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def build() -> Path:
    doc = Document()
    section = doc.sections[0]
    section.page_height = Cm(29.7)
    section.page_width = Cm(21.0)
    section.left_margin = section.right_margin = Cm(2.0)
    section.top_margin = Cm(1.6)
    section.bottom_margin = Cm(1.4)

    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), "Calibri")

    # Title block
    p = para(doc, "Shyena", size=26, bold=True, after=0)
    p.paragraph_format.space_after = Pt(0)
    para(doc, "श्येन · the sharp-eyed hawk  |  Code profiler for vulnerabilities, dependencies, licences, secrets, smell and compatibility",
         size=9.5, color=MUTED, after=2)
    para(doc, "Knobly GRC · code module  |  Phase 0 build, 15 October 2026  |  Prashanth Hebbar", size=8.5, color=MUTED, after=6)

    # Lead
    p = para(doc, after=6)
    runs(p, [
        ("One scan, six verdicts. ", True),
        ("Shyena profiles a repository the way a security auditor and a code reviewer would together: it runs the best "
         "open-source engines in one pass, normalises everything into one finding model, and judges only the code that "
         "changed. A pull request passes or fails on new findings in its own lines, never on legacy debt.", False),
    ], size=10)

    # Two-column table: what it checks | how it works
    table = doc.add_table(rows=1, cols=2)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True
    left, right = table.rows[0].cells
    for c in (left, right):
        set_cell_shading(c, "F6F4F1")
        set_cell_borders(c, bottom_only=False, color="E6E1DA")
        c.paragraphs[0].paragraph_format.space_after = Pt(0)

    def cell_heading(cell, text):
        p = cell.paragraphs[0]
        r = p.add_run(text.upper())
        r.font.size = Pt(8.5)
        r.font.bold = True
        r.font.color.rgb = ACCENT
        p.paragraph_format.space_after = Pt(3)

    def cell_line(cell, lead, text):
        p = cell.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run(lead + "  ")
        r.font.bold = True
        r.font.size = Pt(9)
        r.font.color.rgb = INK
        r = p.add_run(text)
        r.font.size = Pt(9)
        r.font.color.rgb = INK

    cell_heading(left, "What it checks")
    cell_line(left, "Code vulnerabilities", "pattern and taint rules of our own, 30+ languages (Semgrep engine)")
    cell_line(left, "Dependencies", "SBOM of every package manager, known CVEs, fix availability (Syft, Grype)")
    cell_line(left, "Licences", "SPDX category per package, deny / warn lists, dated exceptions")
    cell_line(left, "Secrets", "keys and tokens in the change or across history; only a hash is ever stored (Gitleaks)")
    cell_line(left, "Code smell", "cyclomatic complexity, duplication, blocker rules (Lizard, jscpd)")
    cell_line(left, "Compatibility", "runtime versions from manifests, end-of-life dates, container and IaC misconfiguration (Trivy)")

    cell_heading(right, "How it works")
    cell_line(right, "SARIF in, SARIF out", "every engine's output becomes one CodeFinding; the scan ships as a standard SARIF bundle plus JSON and Markdown")
    cell_line(right, "Stable fingerprints", "a finding keeps its identity when code moves or is reformatted, so decisions survive across scans")
    cell_line(right, "Clean as you code", "new / recurring / fixed lifecycle; the gate counts only new findings on changed lines")
    cell_line(right, "Policy in the repo", ".shyena.yml sets thresholds, licence rules and depth; four presets from a 1-minute pre-commit check to a full audit")
    cell_line(right, "AI triage", "a pluggable layer explains, rates confidence and suggests a fix; it can demote a finding, never block a merge")

    heading(doc, "Where it stands")
    bullet(doc, "Probe contract, finding model, fingerprints, SARIF, policy gate, depth presets, reviewer decisions, reports and CLI. 60 automated tests.", "Built.")
    bullet(doc, "Semgrep and Lizard run live. First real scan: one of our own PHP + Python applications, about 600 files, in 30 seconds: 341 findings, 10 high-severity, gate FAIL with the reasons listed. Handed to that team to verify.", "Proven.")
    bullet(doc, "Syft, Grype, Trivy, Gitleaks and jscpd adapters are written and unit-tested but not yet run against live output. AI triage ships with a null provider; Claude and Ollama providers come next.", "Next.")

    heading(doc, "Get it")
    p = para(doc, after=3)
    runs(p, [
        ("Repository: ", True),
        ("github.com/knoblyhq/shyena", False),
        ("  (private, Knobly organisation; ask Prashanth for access). ", False),
        ("Requires Python 3.11 or newer and the Knobly GRC core package.", False),
    ], size=9.5)
    mono(doc, [
        "git clone https://github.com/knoblyhq/shyena.git",
        "pip install -e <path-to-grc-core>  &&  pip install -e shyena[dev]",
        "pip install semgrep lizard            # the two engines proven so far",
        "shyena tools                          # which engines are installed",
        "shyena scan <repo>                    # first scan: whole tree; then --base origin/main for a PR",
    ])
    p = para(doc, after=0)
    runs(p, [
        ("Reports land in runs/<id>/ (report.md, summary.json, results.sarif) and in the GRC dashboard (", False),
        ("vapt serve", True),
        ("). ", False),
        ("Architecture note, policy schema and the first scan handoff are in the repository's docs/ folder.", False),
    ], size=9.5)

    # Footer line
    p = para(doc, "Knobly · Bengaluru · prashanth@knobly.com · github.com/knoblyhq/shyena", size=8, color=MUTED, before=8, after=0, align=WD_ALIGN_PARAGRAPH.LEFT)

    doc.save(OUT)
    return OUT


if __name__ == "__main__":
    print(build())
