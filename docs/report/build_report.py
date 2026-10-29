"""
Build the Micro-SIEM final project report from the college template
(docs/PROJECT_FINAL_INDEX.docx), following the reference report's format.

Usage: python3 docs/report/build_report.py <out.docx> [pages.json]
  pages.json (optional) = {"1.1": 3, ...} page numbers to write into the INDEX.
"""
import copy, json, os, re, sys
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT, WD_LINE_SPACING
from docx.enum.style import WD_STYLE_TYPE
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, Inches, RGBColor, Emu, Twips
from PIL import Image

# ======================= PERSONAL DETAILS (fill these in) =======================
TITLE = "Micro-SIEM: A Lightweight Security Information and Event Management System"
# Team project: (name, enrollment no.) per student, in the order they appear in the report
STUDENTS = [("Jay Sorathiya", "243050601123"), ("Pratixa Rajodiya", "243050601105")]
GUIDE_NAME = "Prof. Vipul K. Chaudhari"
STUDENT_NAME = None          # single-student fields - unused while STUDENTS is set
ENROLLMENT = None
# ================================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))   # works on any machine / clone location
TEMPLATE = f"{HERE}/template_merged.docx"   # the college template (PROJECT_FINAL_INDEX.docx, removed from docs/ - in git history) with split text runs merged
DIAG, SHOTS = f"{HERE}/diagrams", f"{HERE}/screenshots"
OUT = sys.argv[1]
PAGES = json.load(open(sys.argv[2])) if len(sys.argv) > 2 else {}

FONT = "Times New Roman"
BLACK = RGBColor(0, 0, 0)
RED = RGBColor(0xFF, 0, 0)
# colour theme for the report body (front pages keep the college template's look)
NAVY, BLUE, WHITE = "1F3864", "2E75B6", "FFFFFF"
ROW_BAND, GRID = "EAF1FB", "8EAADB"
PASS_GREEN = "2E7D32"
STUDENT_TXT = ", ".join(f"{n} ({e})" for n, e in STUDENTS) if STUDENTS else (STUDENT_NAME or "Student Name")
ENROLL_TXT = " / ".join(e for _, e in STUDENTS) if STUDENTS else (ENROLLMENT or "Enrollment No")
ENROLL_KNOWN = bool(STUDENTS) or ENROLLMENT is not None
# names used by the generic placeholder pass (team details are filled later by team_front_matter)
FM_STUDENT = "Student Name" if STUDENTS else STUDENT_TXT
FM_ENROLL = "Enrollment No" if STUDENTS else ENROLL_TXT
GUIDE_TXT = GUIDE_NAME or "Internal Guide Name"

doc = Document(TEMPLATE)
body = doc.element.body

# ------------------------------------------------------------------ front matter
def fill_front_matter():
    """Replace the template's red placeholders. Filled values turn black;
    anything still unknown stays red so it is impossible to miss."""
    repl = [
        ("Your Title", TITLE, True),
        ("(EnrollmentNo)", f"({FM_ENROLL})", ENROLLMENT is not None),
        ("(Enrollment no)", f"({FM_ENROLL})", ENROLLMENT is not None),
        ("Enrollment no", FM_ENROLL, ENROLLMENT is not None),
        ("Student Name", FM_STUDENT, STUDENT_NAME is not None),
        ("Internal Guide Name", GUIDE_TXT, GUIDE_NAME is not None),
    ]
    def red(r):
        rpr = r.find(qn("w:rPr")); c = rpr.find(qn("w:color")) if rpr is not None else None
        return c is not None and c.get(qn("w:val"), "").upper() in ("FF0000", "C00000", "EE0000")
    # join consecutive red runs ("Internal" + " " + "Guide Name") so placeholders are whole
    for p in body.iter(qn("w:p")):
        runs = p.findall(qn("w:r")); i = 0
        while i < len(runs) - 1:
            r1, r2 = runs[i], runs[i + 1]
            t1, t2 = r1.find(qn("w:t")), r2.find(qn("w:t"))
            if red(r1) and red(r2) and t1 is not None and t2 is not None and r1.getnext() is r2:
                t1.text = (t1.text or "") + (t2.text or ""); t1.set(qn("xml:space"), "preserve")
                p.remove(r2); runs.pop(i + 1)
            else:
                i += 1
    for p in body.iter(qn("w:p")):
        runs = p.findall(qn("w:r"))
        for r in runs:
            t = r.find(qn("w:t"))
            if t is None or not t.text:
                continue
            rpr = r.find(qn("w:rPr"))
            color = rpr.find(qn("w:color")) if rpr is not None else None
            is_red = color is not None and color.get(qn("w:val"), "").upper() in ("FF0000", "C00000", "EE0000")
            for old, new, filled in repl:
                if old in t.text and is_red:
                    t.text = t.text.replace(old, new)
                    t.set(qn("xml:space"), "preserve")
                    if filled and color is not None:
                        rpr.remove(color)
            # stray red brackets/quotes around the title in the template
            if is_red and t.text.strip() in ("(", ")", "“", "”", "\"") and color is not None:
                rpr.remove(color)
    # Title on the cover is wrapped in red "( ... )" - remove the brackets
    for p in doc.paragraphs:
        if TITLE in p.text and p.text.strip().startswith("("):
            for r in p.runs:
                r.text = r.text.replace("(", "").replace(")", "")

fill_front_matter()

def fix_template_fonts():
    """A few template runs (cover "Academic Year", certificate "Date"/"Place") use the PostScript names
    Times-Bold / Times-Roman, which no machine has installed - each renderer substitutes a different font
    (DejaVu Serif, Noto Serif, ...) and a taller one pushes the certificate signatures onto a new page.
    Use Times New Roman like the rest of the report."""
    for rf in body.iter(qn("w:rFonts")):
        name = rf.get(qn("w:ascii"))
        if name in ("Times-Bold", "Times-Roman"):
            for attr in ("w:ascii", "w:hAnsi", "w:cs"):
                rf.set(qn(attr), "Times New Roman")
            if name == "Times-Bold" and rf.getparent().find(qn("w:b")) is None:
                rf.addnext(OxmlElement("w:b"))       # schema order: rFonts comes right before b

fix_template_fonts()

def fix_cover():
    """The cover has no page break - it is sized so the certificate starts where the cover runs out.
    The real title wraps to 2 lines, so drop 2 blank spacer lines above the bottom block and end the
    cover with an explicit page break."""
    paras = [p for p in body if p.tag == qn("w:p")]
    year = next(p for p in paras if p.xpath("string(.)").strip().startswith("Academic Year"))
    inst = year.getprevious().getprevious()          # "Shree Swami ... Institute of Technology" (bottom block)
    removed, prev = 0, inst.getprevious()
    while removed < 2 and prev is not None and prev.tag == qn("w:p") and not prev.xpath("string(.)").strip():
        nxt = prev.getprevious(); body.remove(prev); prev = nxt; removed += 1
    r = OxmlElement("w:r"); br = OxmlElement("w:br"); br.set(qn("w:type"), "page"); r.append(br); year.append(r)

fix_cover()

def team_front_matter():
    """Adapt the single-student template pages to a team of len(STUDENTS)."""
    from docx.text.paragraph import Paragraph
    def black(run):
        rpr = run._r.find(qn("w:rPr"))
        if rpr is not None:
            c = rpr.find(qn("w:color"))
            if c is not None: rpr.remove(c)
    def set_text(par, text):
        runs = par.runs
        runs[0].text = text; black(runs[0])
        for r in runs[1:]: r._r.getparent().remove(r._r)
    def clone_after(par, text, space_before=None):
        el = copy.deepcopy(par._p); par._p.addnext(el)
        q = Paragraph(el, par._parent); set_text(q, text)
        if space_before is not None: q.paragraph_format.space_before = Pt(space_before)
        return q
    def reword(par, pairs):
        for r in par.runs:
            for a, b in pairs:
                if a in r.text: r.text = r.text.replace(a, b)
    (n1, e1), rest = STUDENTS[0], STUDENTS[1:]
    paras = doc.paragraphs
    page = "cover"
    i = 0
    while i < len(paras):
        par = paras[i]; t = par.text.strip()
        if t == "CERTIFICATE": page = "cert"
        elif t == "Self-Declaration": page = "decl"
        elif t == "Acknowledgments": page = "ack"
        elif t == "INDEX": break
        if page == "cover" and t == "Student Name":
            nxt = paras[i + 1]
            set_text(par, f"{n1} ({e1})")
            # second student on the enrollment line, formatted like the name line (keeps the cover height)
            nr = nxt.runs[0]; nr._r.remove(nr._r.find(qn("w:rPr"))) if nr._r.find(qn("w:rPr")) is not None else None
            nr._r.insert(0, copy.deepcopy(par.runs[0]._r.find(qn("w:rPr"))))
            set_text(nxt, "  ".join(f"{n} ({e})" for n, e in rest)); black(nxt.runs[0])
            i += 2; continue
        if page == "cert" and "Student Name" in par.text:
            for r in par.runs:
                if r.text == "Student Name": r.text = n1; black(r)
                elif r.text.startswith(". bearing enrollment no.:"): r.text = " (enrollment no.: "
                elif r.text == ENROLL_TXT or r.text == "Enrollment No":
                    r.text = e1 + ")" + "".join(f" and {n} (enrollment no.: {e})" for n, e in rest); black(r)
                    r.bold = True
        if page in ("decl", "ack") and t == "Student Name":
            # students side by side: a borderless table with one column per student (bold name, enrollment
            # below), first student left-aligned, last right-aligned
            name_p, enr_p = par, paras[i + 1]
            tbl = doc.add_table(rows=1, cols=len(STUDENTS))
            enr_p._p.addnext(tbl._tbl)
            tblpr = tbl._tbl.tblPr
            borders = OxmlElement("w:tblBorders")
            for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
                b = OxmlElement(f"w:{edge}"); b.set(qn("w:val"), "nil"); borders.append(b)
            tblpr.append(borders)
            col_w = Inches(6.27 / len(STUDENTS))
            for k, (n, e) in enumerate(STUDENTS):
                cell = tbl.rows[0].cells[k]; cell.width = col_w
                cell._tc.remove(cell.paragraphs[0]._p)
                for src, txt in ((name_p, n), (enr_p, f"({e})")):
                    el = copy.deepcopy(src._p); cell._tc.append(el)
                    q = Paragraph(el, cell); set_text(q, txt)
                    q.paragraph_format.left_indent = None
                    if k == len(STUDENTS) - 1 and k > 0: q.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            for p_ in (name_p, enr_p): p_._p.getparent().remove(p_._p)
            i += 2; continue
        if page == "decl":
            reword(par, [("I hereby declare", "We hereby declare"), ("carried out by me", "carried out by us")])
        if page == "ack":
            reword(par, [("So, I would like", "So, we would like"), ("So, i would like", "So, we would like"),
                         ("Primarily, I am very much thankful to my", "Primarily, we are very much thankful to our"),
                         ("inspiration for me", "inspiration for us"), ("I also express", "We also express"),
                         ("I am grateful", "We are grateful"), ("providing me", "providing us"),
                         ("Once again, I am grateful", "Once again, we are grateful"), ("giving me the", "giving us the"),
                         ("I would like to take", "We would like to take"), ("I am also thankful", "We are also thankful"),
                         ("Once again, We are", "Once again, we are")])
        i += 1
    singular = re.compile(r"\b(I|me|my)\b")
    left = [p.text for p in doc.paragraphs[:120] if singular.search(p.text) and any(k in p.text for k in ("declare", "thank", "grateful", "opportunity"))]
    if left: print("WARNING singular wording left:", [x[:80] for x in left])

if STUDENTS:
    team_front_matter()

def paginate_front():
    """The template positions each front page with runs of blank paragraphs, so any extra line
    (e.g. a second student) shifts every later page. Replace the blank filler before the
    Self-Declaration, Acknowledgments and INDEX pages with real page breaks."""
    def is_blank(el):
        return el.tag == qn("w:p") and not el.xpath("string(.)").strip() and not el.xpath(".//w:drawing")
    def page_start(el, space_pt):
        prev = el.getprevious()
        while prev is not None and is_blank(prev):
            gone, prev = prev, prev.getprevious(); body.remove(gone)
        ppr = el.find(qn("w:pPr"))
        if ppr is None:
            ppr = OxmlElement("w:pPr"); el.insert(0, ppr)
        pbb = OxmlElement("w:pageBreakBefore"); ppr.insert(0, pbb)
        if space_pt is not None:
            sp_ = ppr.find(qn("w:spacing"))
            if sp_ is None:
                sp_ = OxmlElement("w:spacing"); ppr.append(sp_)
            sp_.set(qn("w:before"), str(int(space_pt * 20)))
    paras = [k for k in body if k.tag == qn("w:p")]
    text = lambda el: el.xpath("string(.)").strip()
    guide_line = next(k for k in paras if text(k).startswith("Internal Guide") and "Head of" in text(k))
    logos = guide_line.getnext()
    while logos is not None and not logos.xpath(".//w:drawing"):
        logos = logos.getnext()
    # blank lines *before* the logos on the declaration page belong to that page's top margin; keep 2
    page_start(logos, 36)
    page_start(next(k for k in paras if text(k) == "Acknowledgments"), 90)
    page_start(next(k for k in paras if text(k) == "INDEX"), 60)

paginate_front()

# ------------------------------------------------------------------ remove trailing empty paragraphs after INDEX
sect_pr_front = body.find(qn("w:sectPr"))
children = list(body)
idx_tbl = [c for c in children if c.tag == qn("w:tbl")][-1]
# The template's INDEX table is a floating table (tblpPr) anchored to the paragraphs after it;
# make it a normal centred inline table so it stays under the INDEX heading.
for fp_ in idx_tbl.xpath("./w:tblPr/w:tblpPr"):
    fp_.getparent().remove(fp_)
_jc = idx_tbl.tblPr.find(qn("w:jc"))
if _jc is None:
    _jc = OxmlElement("w:jc"); idx_tbl.tblPr.append(_jc)
_jc.set(qn("w:val"), "center")
# drop the blank paragraphs between the INDEX heading and the table (they were only needed for the floating layout)
_prev = idx_tbl.getprevious()
while _prev is not None and _prev.tag == qn("w:p") and not _prev.xpath("string(.)").strip():
    _gone, _prev = _prev, _prev.getprevious()
    body.remove(_gone)
if _prev is not None and _prev.xpath("string(.)").strip() == "INDEX":
    from docx.text.paragraph import Paragraph as _P
    _P(_prev, doc._body).paragraph_format.space_after = Pt(18)
for c in children[children.index(idx_tbl) + 2:]:   # keep one empty paragraph after the table
    if c.tag == qn("w:p") and not c.xpath("string(.)").strip():
        body.remove(c)

# ------------------------------------------------------------------ styles
styles = doc.styles

def set_font(run_or_style_font, size=None, bold=None, italic=None, name=FONT, color=None):
    f = run_or_style_font
    f.name = name
    if size: f.size = Pt(size)
    if bold is not None: f.bold = bold
    if italic is not None: f.italic = italic
    if color is not None: f.color.rgb = color

def east_asia(style_or_run_el, name=FONT):
    rpr = style_or_run_el.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts"); rpr.insert(0, rfonts)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(a), name)

def mk_style(name, size, bold=False, align=None, before=0, after=6, outline=None, keep_next=False, italic=False, color=None):
    s = styles.add_style(name, WD_STYLE_TYPE.PARAGRAPH)
    s.base_style = styles["Normal"]
    set_font(s.font, size, bold, italic, color=RGBColor.from_string(color) if color else None)
    east_asia(s.element)
    pf = s.paragraph_format
    pf.space_before, pf.space_after = Pt(before), Pt(after)
    if align is not None: pf.alignment = align
    pf.keep_with_next = keep_next
    if outline is not None:
        ppr = s.element.get_or_add_pPr()
        ol = OxmlElement("w:outlineLvl"); ol.set(qn("w:val"), str(outline)); ppr.append(ol)
    return s

S_BODY = mk_style("Report Body", 12, align=WD_ALIGN_PARAGRAPH.JUSTIFY, after=6)
S_BODY.paragraph_format.line_spacing = 1.15
S_CH = mk_style("Report Chapter", 16, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, after=14, outline=0, keep_next=True, color=NAVY)
S_SEC = mk_style("Report Section", 12, bold=True, before=10, after=8, outline=1, keep_next=True)
S_SUB = mk_style("Report Sub", 12, bold=True, before=8, after=4, outline=2, keep_next=True, color=BLUE)
S_CAP = mk_style("Report Caption", 11, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER, before=4, after=12, color=NAVY)
S_CELL = mk_style("Report Cell", 11, after=0)
S_BUL = mk_style("Report Bullet", 12, align=WD_ALIGN_PARAGRAPH.JUSTIFY, after=3)
S_BUL.paragraph_format.line_spacing = 1.15

# ------------------------------------------------------------------ numbering (bullets + numbered lists)
numbering = doc.part.numbering_part.element
def add_abstract(abs_id, levels):
    a = OxmlElement("w:abstractNum"); a.set(qn("w:abstractNumId"), str(abs_id))
    ml = OxmlElement("w:multiLevelType"); ml.set(qn("w:val"), "hybridMultilevel"); a.append(ml)
    for ilvl, (fmt, text, font, left) in enumerate(levels):
        lvl = OxmlElement("w:lvl"); lvl.set(qn("w:ilvl"), str(ilvl))
        for tag, val in (("w:start", "1"), ("w:numFmt", fmt), ("w:lvlText", text), ("w:lvlJc", "left")):
            e = OxmlElement(tag); e.set(qn("w:val"), val); lvl.append(e)
        ppr = OxmlElement("w:pPr"); ind = OxmlElement("w:ind")
        ind.set(qn("w:left"), str(left)); ind.set(qn("w:hanging"), "360"); ppr.append(ind); lvl.append(ppr)
        if font:
            rpr = OxmlElement("w:rPr"); rf = OxmlElement("w:rFonts")
            for at in ("w:ascii", "w:hAnsi", "w:hint"): rf.set(qn(at), font)
            rf.attrib.pop(qn("w:hint"))
            rpr.append(rf); lvl.append(rpr)
        a.append(lvl)
    first_num = numbering.find(qn("w:num"))
    if first_num is not None: first_num.addprevious(a)
    else: numbering.append(a)

BUL_ABS, NUM_ABS = 90, 91
add_abstract(BUL_ABS, [("bullet", "", "Symbol", 1080), ("bullet", "o", "Courier New", 1800), ("bullet", "", "Wingdings", 2520)])
add_abstract(NUM_ABS, [("decimal", "%1.", None, 1080), ("lowerLetter", "%2)", None, 1800)])
_num_ids = [200]
def new_num(abs_id):
    _num_ids[0] += 1
    n = OxmlElement("w:num"); n.set(qn("w:numId"), str(_num_ids[0]))
    a = OxmlElement("w:abstractNumId"); a.set(qn("w:val"), str(abs_id)); n.append(a)
    for lv in range(2):
        lo = OxmlElement("w:lvlOverride"); lo.set(qn("w:ilvl"), str(lv))
        so = OxmlElement("w:startOverride"); so.set(qn("w:val"), "1"); lo.append(so); n.append(lo)
    numbering.append(n)
    return _num_ids[0]
BUL_NUM = new_num(BUL_ABS)

# ------------------------------------------------------------------ content helpers
def add_runs(p, text, size=None, base_bold=False):
    """Supports **bold** inline markup."""
    for i, part in enumerate(re.split(r"\*\*(.+?)\*\*", text)):
        if not part: continue
        r = p.add_run(part)
        r.bold = True if i % 2 == 1 else (base_bold or None)
        if size: r.font.size = Pt(size)
    return p

def para(text, indent_first=True, style=None, align=None, space_after=None):
    p = doc.add_paragraph(style=style or S_BODY)
    if indent_first: p.paragraph_format.first_line_indent = Inches(0.5)
    if align is not None: p.alignment = align
    if space_after is not None: p.paragraph_format.space_after = Pt(space_after)
    return add_runs(p, text)

def numpr(p, num_id, ilvl=0):
    ppr = p._p.get_or_add_pPr()
    n = OxmlElement("w:numPr")
    il = OxmlElement("w:ilvl"); il.set(qn("w:val"), str(ilvl)); n.append(il)
    ni = OxmlElement("w:numId"); ni.set(qn("w:val"), str(num_id)); n.append(ni)
    ppr.append(n)

def bullets(items, level=0):
    for it in items:
        if isinstance(it, (list, tuple)):
            bullets(it, level + 1); continue
        p = doc.add_paragraph(style=S_BUL); numpr(p, BUL_NUM, level); add_runs(p, it)

def numbered(items):
    nid = new_num(NUM_ABS)
    for it in items:
        if isinstance(it, (list, tuple)):
            for sub in it:
                p = doc.add_paragraph(style=S_BUL); numpr(p, BUL_NUM, 1); add_runs(p, sub)
            continue
        p = doc.add_paragraph(style=S_BUL); numpr(p, nid, 0); add_runs(p, it)

def chapter(num, title, first=False):
    p = doc.add_paragraph(style=S_CH)
    if not first: p.paragraph_format.page_break_before = True
    p.add_run(f"{num}. ")
    r = p.add_run(title.upper()); r.underline = True

def shade(el_ppr_or_tcpr, fill):
    shd = OxmlElement("w:shd"); shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), fill)
    el_ppr_or_tcpr.append(shd)

def section(num, title, new_page=False):
    p = doc.add_paragraph(style=S_SEC)
    if new_page: p.paragraph_format.page_break_before = True
    shade(p._p.get_or_add_pPr(), NAVY)
    r0 = p.add_run(f"{num} ")
    r = p.add_run(title.upper()); r.underline = True
    for r_ in (r0, r): r_.font.color.rgb = RGBColor.from_string(WHITE)

def sub(text, arrow=False):
    p = doc.add_paragraph(style=S_SUB)
    p.add_run(("➢ " if arrow else "") + text)
    return p

def page_break():
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

TEXT_W = 6.27  # inches between margins

def set_cell(cell, text, bold=False, fill=None, align=None, size=11, mono=False, color=None):
    cell.text = ""
    p = cell.paragraphs[0]; p.style = S_CELL
    if align is not None: p.alignment = align
    lines = text.split("\n") if isinstance(text, str) else text
    for i, line in enumerate(lines):
        if i: p = cell.add_paragraph(style=S_CELL)
        add_runs(p, line, size=size, base_bold=bold)
        if mono:
            for r in p.runs: r.font.name = "Courier New"; r.font.size = Pt(9)
        if color:
            for r in p.runs: r.font.color.rgb = RGBColor.from_string(color)
    if fill: shade(cell._tc.get_or_add_tcPr(), fill)
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER

def table(rows, widths, header=True, first_col_bold=False, header_fill=NAVY, size=11, center_cols=()):
    t = doc.add_table(rows=len(rows), cols=len(widths))
    t.style = None
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    tblpr = t._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        e = OxmlElement(f"w:{edge}"); e.set(qn("w:val"), "single"); e.set(qn("w:sz"), "6"); e.set(qn("w:color"), GRID); borders.append(e)
    tblpr.append(borders)
    cm = OxmlElement("w:tblCellMar")
    for side, v in (("top", 30), ("left", 90), ("bottom", 30), ("right", 90)):
        e = OxmlElement(f"w:{side}"); e.set(qn("w:w"), str(v)); e.set(qn("w:type"), "dxa"); cm.append(e)
    tblpr.append(cm)
    fix_widths(t, widths)
    for ri, row in enumerate(rows):
        for ci, val in enumerate(row):
            c = t.cell(ri, ci); c.width = Inches(widths[ci])
            is_head = header and ri == 0
            is_pass = not is_head and str(val) == "Pass"
            band = ROW_BAND if (not is_head and (ri - header) % 2 == 1) else None
            set_cell(c, str(val), bold=is_head or is_pass or (first_col_bold and ci == 0),
                     fill=header_fill if is_head else band, size=size,
                     color=WHITE if is_head else (PASS_GREEN if is_pass else None),
                     align=WD_ALIGN_PARAGRAPH.CENTER if (ci in center_cols and not is_head) else None)
        if header and ri == 0:
            trpr = t.rows[0]._tr.get_or_add_trPr()
            th = OxmlElement("w:tblHeader"); th.set(qn("w:val"), "true"); trpr.append(th)
    for row in t.rows:
        trpr = row._tr.get_or_add_trPr()
        cs = OxmlElement("w:cantSplit"); cs.set(qn("w:val"), "true"); trpr.append(cs)
    doc.add_paragraph(style=S_BODY).paragraph_format.space_after = Pt(4)
    return t

def fix_widths(t, widths):
    """Explicit grid + fixed layout so Word and LibreOffice both honour column widths."""
    tw = int(sum(widths) * 1440)
    tblpr = t._tbl.tblPr
    for tag in ("w:tblW", "w:tblLayout"):
        e = tblpr.find(qn(tag))
        if e is not None: tblpr.remove(e)
    w = OxmlElement("w:tblW"); w.set(qn("w:w"), str(tw)); w.set(qn("w:type"), "dxa"); tblpr.append(w)
    lay = OxmlElement("w:tblLayout"); lay.set(qn("w:type"), "fixed"); tblpr.append(lay)
    grid = t._tbl.tblGrid
    for gc, wd in zip(grid.findall(qn("w:gridCol")), widths):
        gc.set(qn("w:w"), str(int(wd * 1440)))
    t.autofit = False

FIG = {"n": {}}
def figure(path, caption, chap, max_w=TEXT_W, max_h=7.9, border=True):
    im = Image.open(path); w, h = im.size
    scale = min(max_w / (w / 96), max_h / (h / 96), 1e9)
    wi = min(max_w, max_h * w / h)
    p = doc.add_paragraph(style=S_BODY); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True; p.paragraph_format.space_after = Pt(2)
    run = p.add_run(); run.add_picture(path, width=Inches(wi))
    if border:
        sppr = run._r.xpath(".//pic:spPr")[0]
        ln = OxmlElement("a:ln"); ln.set("w", "9525")
        sf = OxmlElement("a:solidFill"); clr = OxmlElement("a:srgbClr"); clr.set("val", GRID); sf.append(clr); ln.append(sf)
        sppr.append(ln)
    FIG["n"][chap] = FIG["n"].get(chap, 0) + 1
    cp = doc.add_paragraph(style=S_CAP)
    cp.add_run(f"Figure {chap}.{FIG['n'][chap]}: {caption}")

# =========================================================================================
#                                   BODY  (new section)
# =========================================================================================
# Section break: front matter stays unnumbered, chapters start at page 1 with header/footer.
brk = doc.add_paragraph()
new_sect = doc.sections[-1]  # placeholder; real break added via add_section below
doc.add_section(WD_SECTION.NEW_PAGE)
front, main = doc.sections[0], doc.sections[1]
# remove the empty paragraph we used to anchor (keeps index page clean)
body.remove(brk._p) if brk._p.getparent() is not None and not brk.text else None

main.top_margin, main.bottom_margin = Inches(0.95), Inches(0.85)
main.left_margin = main.right_margin = Inches(1.0)
main.header_distance, main.footer_distance = Inches(0.45), Inches(0.42)
sp = main._sectPr
pg = sp.find(qn("w:pgNumType"))
if pg is None:
    pg = OxmlElement("w:pgNumType"); sp.append(pg)
pg.set(qn("w:start"), "1")
# page border identical to the front matter
if sp.find(qn("w:pgBorders")) is None and sect_pr_front.find(qn("w:pgBorders")) is not None:
    pgsz = sp.find(qn("w:pgMar"))
    pgsz.addnext(copy.deepcopy(sect_pr_front.find(qn("w:pgBorders"))))

main.header.is_linked_to_previous = False
main.footer.is_linked_to_previous = False
hp = main.header.paragraphs[0]; hp.alignment = WD_ALIGN_PARAGRAPH.CENTER
hr = hp.add_run("Micro-SIEM: Lightweight Security Information and Event Management"); hr.bold = True; set_font(hr.font, 12)
fp = main.footer.paragraphs[0]
fr = fp.add_run(ENROLL_TXT); fr.bold = True; set_font(fr.font, 11)
if not ENROLL_KNOWN: fr.font.color.rgb = RED
fp.add_run("\t\t")
def field(par, instr):
    r = par.add_run(); r.bold = True; set_font(r.font, 11)
    b = OxmlElement("w:fldChar"); b.set(qn("w:fldCharType"), "begin"); r._r.append(b)
    r2 = par.add_run(); r2.bold = True
    it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = instr; r2._r.append(it)
    r3 = par.add_run(); r3.bold = True
    s = OxmlElement("w:fldChar"); s.set(qn("w:fldCharType"), "separate"); r3._r.append(s)
    r4 = par.add_run("1"); r4.bold = True; set_font(r4.font, 11)
    r5 = par.add_run()
    e = OxmlElement("w:fldChar"); e.set(qn("w:fldCharType"), "end"); r5._r.append(e)
field(fp, " PAGE ")
# front matter: explicitly no header/footer
front.header.is_linked_to_previous = False; front.footer.is_linked_to_previous = False

# =========================================================================================
# CHAPTER 1
# =========================================================================================
chapter(1, "Project Description", first=True)
sub("Introduction", arrow=True)
para("**Micro-SIEM** is a lightweight **Security Information and Event Management (SIEM)** system built from scratch "
     "for learning, demonstration and small-scale monitoring. It continuously collects security-relevant log events from a web "
     "application and its Nginx web server, stores them centrally in OpenSearch, runs automated detection rules every few "
     "seconds, and presents the resulting alerts on role-based dashboards. Every alert is mapped to the **MITRE ATT&CK** "
     "framework (or to OWASP/CWE for web attacks), so an analyst immediately knows which attacker technique was observed.")
para("The project also contains a deliberately weak **demo web portal** (login + search page) that acts as the attack target. "
     "Brute-force, password-spraying, credential-compromise and Cross-Site Scripting (XSS) attacks performed against this "
     "portal are captured as logs and detected live, which makes the complete SIEM life-cycle (collect, store, detect, alert, "
     "respond) visible in a single demonstration.")

sub("1) Existing System")
para("Small organizations, college labs and students usually have no central place where security logs are analysed. "
     "The common situation has several problems:")
bullets([
    "**Scattered logs** – Web server, application and authentication logs are stored as separate files on different machines and are rarely read.",
    "**Manual inspection** – An administrator must open log files and search them by hand (grep), which is slow and error-prone.",
    "**No real-time detection** – Attacks such as brute force or password spraying are discovered late, often only after an account is compromised.",
    "**No context** – Raw log lines do not say which attack technique they represent or how severe it is.",
    "**Commercial SIEMs are heavy** – Splunk, IBM QRadar and Microsoft Sentinel are powerful but expensive, licence-bound and need large hardware, which puts them out of reach for students and small teams.",
])
sub("➔ Modules in the Micro-SIEM System")
bullets([
    "**Log Collection Module** – Demo web login events and Nginx access logs written as structured JSON lines.",
    "**Log Ingestion Module** – Vector tails the log files, parses them and ships them to OpenSearch.",
    "**Storage & Search Module** – OpenSearch indexes every event for fast queries and aggregations.",
    "**Detection Engine Module** – Four correlation/threshold rules run automatically every 5 seconds.",
    "**Alert Management Module** – De-duplicated, MITRE-mapped alerts are stored as a permanent history.",
    "**Dashboard Module** – Admin console and read-only viewer dashboard with live charts.",
    "**Authentication & Access Control Module** – Token sessions, admin/viewer roles and login rate limiting.",
    "**Demo Attack Surface Module** – Intentionally vulnerable login and search pages used as the attack target.",
    "**Response Module (future)** – IP firewall blocking and account blocking, built and tested but switched off.",
])
sub("2) Need for the New System")
para("Micro-SIEM addresses the shortcomings of manual log handling by providing:")
bullets([
    "**Centralized logging** – All events from different sources are stored in one searchable place.",
    "**Automated real-time detection** – Attacks are detected within seconds without anyone watching the logs.",
    "**Standard threat mapping** – Alerts carry MITRE ATT&CK technique IDs (T1110, T1110.003, T1078) or CWE-79.",
    "**Clear visualization** – Charts and tables show login success rate, log activity and attack vectors at a glance.",
    "**Role-based access** – Administrators can investigate and act; viewers can only observe.",
    "**Low cost** – Built only with free and open-source software, running on one laptop with Docker.",
    "**Learning value** – Every component (ingestion, storage, detection, dashboard) is small enough to be understood completely.",
])
sub("3) Objectives of the New System")
numbered([
    "**Centralize security logs** from more than one source into a single searchable store.",
    "**Detect common credential and web attacks automatically** with transparent, explainable rules.",
    "**Map every alert to an industry framework** (MITRE ATT&CK / OWASP CWE) with a severity level.",
    "**Visualize security posture** through live dashboards for different user roles.",
    "**Protect the SIEM itself** with authentication, authorization, rate limiting, input validation and output escaping.",
    "**Run anywhere** using Docker containers started with a single command.",
])
sub("4) Problem Definition")
bullets([
    "Security events are produced continuously, but without collection and correlation they are useless.",
    "An attacker trying many passwords (brute force) or one password against many accounts (spraying) must be noticed quickly.",
    "A successful login after several failures can mean a guessed credential and must be highlighted.",
    "Malicious input such as XSS payloads in URLs must be recognised even when it is URL-encoded.",
    "Alerts must not be duplicated every few seconds while an attack continues, otherwise analysts suffer alert fatigue.",
    "The monitoring system itself must not become a new attack surface (spoofed IPs, stored XSS, open database).",
])
sub("5) Core Components")
sub("➔ User Categories")
para("The Micro-SIEM system has the following types of users:", indent_first=False)
p = sub("1. Admin (Security Analyst)")
bullets(["Logs in to the admin console with a session token.", "Views dashboard statistics, all raw logs and all alerts.",
         "Analyses an alert and opens the mitigation panel (IP / account blocking – planned).", "Views the blocked list and logs out."])
sub("2. Viewer")
bullets(["Logs in to a read-only dashboard.", "Sees statistics and charts but cannot see raw logs or take any action (enforced on the server with HTTP 403)."])
sub("3. Demo User / Attacker")
bullets(["Uses the demo portal on port 8080: login page and search page.", "Every login attempt and every page request is logged and analysed.",
         "Simulates attacks: brute force, password spraying, credential compromise and XSS."])
sub("4. Detection Engine (system actor)")
bullets(["A background task that wakes up every 5 seconds, runs all rules and writes new alerts."])

section("1.1", "Project Profile", new_page=True)
table([
    ["Project Attribute", "Details"],
    ["Project Title", TITLE],
    ["Project Category", "Cyber Security – Web-based Security Monitoring System"],
    ["Time Duration", "4 Months (July 2026 – October 2026)"],
    ["Front-End", "HTML5, Tailwind CSS 3.4, JavaScript, Chart.js 4.5"],
    ["Back-End", "Python 3.11, FastAPI 0.111, Uvicorn"],
    ["Database / Storage", "OpenSearch 3.8 (NoSQL document store and search engine)"],
    ["Log Pipeline", "Vector 0.59 (log collector and shipper)"],
    ["Web Server / Proxy", "Nginx 1.30"],
    ["Deployment", "Docker Engine and Docker Compose (6 containers)"],
    ["Threat Framework", "MITRE ATT&CK, OWASP Top 10 / CWE-79"],
    ["Security Measures", "Token sessions, role-based access, login rate limiting, trusted-proxy IP validation, output escaping, localhost-only database"],
    ["College Guide", GUIDE_TXT],
    ["Developed By", "\n".join(f"{n} ({e})" for n, e in STUDENTS) if STUDENTS else f"{STUDENT_TXT} ({ENROLL_TXT})"],
], [2.0, 4.2], first_col_bold=True)

section("1.2", "Project Definition")
para("Micro-SIEM is a containerised Security Information and Event Management system that collects web authentication and "
     "web server logs, stores them in OpenSearch, detects attacks with four automated rules, and displays MITRE-mapped alerts "
     "on secure, role-based dashboards. It is designed to be small enough to run on a single laptop yet complete enough to "
     "demonstrate the full monitoring life-cycle used by real Security Operations Centres (SOC).")
sub("➔ Key Aspects of the System:")
sub("1. Purpose:")
bullets(["To provide one central place where security events from different sources can be searched and analysed.",
         "To detect password attacks and web injection attempts automatically and in near real time.",
         "To demonstrate, in a practical and explainable way, how a SIEM works internally."])
sub("2. Core Functionalities:")
bullets([
    "**Log Ingestion:** Two live log sources (web login events and Nginx access log) shipped by Vector into OpenSearch.",
    "**Detection Rules:** Brute force (T1110), password spraying (T1110.003), fail-then-success correlation (T1078) and XSS signatures (CWE-79).",
    "**Alert History:** Every alert is stored permanently, de-duplicated to one alert per rule per source IP per 5 minutes.",
    "**Admin Console:** Statistics, login success rate, live activity chart, attack-vector chart, full log stream and threat list.",
    "**Viewer Dashboard:** Read-only statistics and charts for managers or auditors.",
    "**Security of the SIEM:** Server-side sessions, roles, rate limiting, IP validation, escaping and localhost-only storage.",
])

# =========================================================================================
# CHAPTER 2
# =========================================================================================
chapter(2, "Environment Description")
para("The development and deployment of Micro-SIEM require a defined hardware and software environment. Because every "
     "component runs inside Docker containers, the same environment can be reproduced on any machine with Docker installed. "
     "The following sections describe the hardware and software specification and the development methodology.")
section("2.1", "Hardware and Software Specification")
sub("A. Hardware Requirements")
para("OpenSearch is the most resource-hungry component (it runs on the Java Virtual Machine with a 512 MB heap), so memory is "
     "the most important hardware requirement.", indent_first=False)
table([
    ["Component", "Minimum Requirement", "Recommended Requirement", "Used for Development"],
    ["Processor", "Dual-core x86-64, virtualization enabled", "Quad-core or better", "AMD Ryzen 7 7435HS (12 vCPU)"],
    ["RAM", "4 GB", "8 GB or higher", "8 GB"],
    ["Storage", "20 GB free", "40 GB SSD", "38 GB virtual disk (SSD)"],
    ["Network", "Ethernet / Wi-Fi (LAN)", "LAN + Internet for ngrok demo", "Wi-Fi LAN"],
    ["Peripherals", "Keyboard, Mouse, Monitor", "Second device (phone / PC) for live demo", "Laptop + mobile phone"],
], [1.25, 1.6, 1.65, 1.7], first_col_bold=True)
sub("B. Software Requirements")
table([
    ["Software Component", "Technology / Tool Used"],
    ["Operating System", "Kali GNU/Linux Rolling (kernel 6.19) – any OS with Docker works"],
    ["Containerization", "Docker Engine 28.5, Docker Compose 2.40"],
    ["Backend Language & Framework", "Python 3.11, FastAPI 0.111.0, Uvicorn 0.30.1, Pydantic 2.7.4"],
    ["Database / Search Engine", "OpenSearch 3.8.0 (opensearch-py 2.6.0 client)"],
    ["Data Exploration UI", "OpenSearch Dashboards 3.8.0"],
    ["Log Shipper", "Vector 0.59.0 (VRL transforms)"],
    ["Web Server / Reverse Proxy", "Nginx 1.30.6 (with real-IP module)"],
    ["Frontend", "HTML5, Tailwind CSS 3.4.17, JavaScript (ES2020), Chart.js 4.5.1"],
    ["Browser", "Chromium / Firefox"],
    ["IDE / Code Editor", "Visual Studio Code"],
    ["Version Control", "Git and GitHub (GitHub CLI)"],
    ["Remote Demo Access", "ngrok (HTTP tunnel)"],
    ["Testing Tools", "curl, headless Chromium, Python test scripts"],
], [2.3, 3.9], first_col_bold=True)

section("2.2", "Development Description")
para("Micro-SIEM was developed with a structured, modular approach so that each part of the pipeline could be built and "
     "verified independently before being connected to the next one.", indent_first=False)
sub("A. Development Approach")
para("The project followed the **Spiral model** of software development. Work was divided into five risk-driven cycles; "
     "each cycle set its objectives, analysed the risks (especially security risks), built and tested one part of the "
     "system and was evaluated before the next cycle was planned. The work covered the following phases:", indent_first=False)
numbered([
    "**Requirement Analysis** – Studying SIEM concepts, MITRE ATT&CK techniques and the log formats to be collected.",
    "**System Design** – Designing the container architecture, data flow, index structure and detection rules.",
    "**Pipeline Development** – Setting up OpenSearch and Vector and verifying that log events reach the index.",
    "**Backend & Detection Development** – Building the FastAPI service, demo login API, detection rules and alert storage.",
    "**Dashboard Development** – Building the admin and viewer dashboards with authentication and role checks.",
    "**Security Hardening** – Code review of the SIEM itself and fixing issues (IP spoofing, stored XSS, rate limiting, exposure).",
    "**Testing & Documentation** – Unit, integration, live end-to-end and browser testing, followed by this report.",
])
sub("B. Modules & Development Tools")
table([
    ["Module", "Technology Used"],
    ["Log Collection", "FastAPI JSON-line logger, Nginx JSON access log format"],
    ["Log Ingestion", "Vector file sources, VRL parse_json transform, Elasticsearch-compatible bulk sink"],
    ["Storage & Search", "OpenSearch indices: logs-index, alerts-index, blocked-index"],
    ["Detection Engine", "Python, OpenSearch aggregations and scroll scan, asyncio background task"],
    ["Alert Management", "Fixed alert IDs and create-only writes (no duplicates)"],
    ["Authentication & RBAC", "FastAPI dependencies, secrets.token_hex session tokens, environment variables (.env)"],
    ["Dashboards", "HTML, Tailwind CSS, JavaScript fetch API, Chart.js"],
    ["Reverse Proxy", "Nginx proxy_pass /api/, real_ip module"],
    ["Response (planned)", "iptables / ip6tables (INPUT + DOCKER-USER chains)"],
    ["Deployment", "Docker Compose, named volumes, health checks"],
], [2.2, 4.0], first_col_bold=True)

# =========================================================================================
# CHAPTER 3
# =========================================================================================
chapter(3, "System Description")
section("3.1", "Introduction")
para("A Security Information and Event Management (SIEM) system combines two older ideas: **Security Information Management** "
     "(collecting and storing logs for analysis and compliance) and **Security Event Management** (real-time monitoring, "
     "correlation and alerting). Micro-SIEM implements both ideas on a small scale. Its working can be summarised as a "
     "five-stage pipeline:")
numbered(["**Generate** – The demo portal and Nginx write one JSON line per event.",
          "**Collect & ship** – Vector reads new lines and sends them to OpenSearch in bulk.",
          "**Store & index** – OpenSearch makes every event searchable within about a second.",
          "**Detect** – The detection engine queries recent events every 5 seconds and evaluates four rules.",
          "**Present & respond** – Alerts appear on the dashboards, where the admin can analyse them."])
figure(f"{DIAG}/architecture.png", "Micro-SIEM Data Flow Architecture", 3, max_h=5.2)

section("3.2", "Scope of the System")
para("The scope defines what Micro-SIEM covers in this version and what is intentionally left out.", indent_first=False)
sub("In Scope:")
bullets([
    "Two live log sources: demo web-application login events and Nginx web server access logs (dashboard logins are also logged).",
    "Four detection rules: brute force, password spraying, fail-then-success correlation and XSS signature detection.",
    "Permanent, de-duplicated alert history with severity and MITRE ATT&CK / CWE mapping.",
    "Admin console and read-only viewer dashboard with server-side role enforcement.",
    "Deployment of the complete stack on one host with Docker Compose; access from LAN devices (demo portal also through ngrok).",
    "Security of the SIEM itself: authentication, rate limiting, IP trust validation, output escaping, localhost-only database.",
])
sub("Out of Scope (current version):")
bullets([
    "Automatic blocking – the firewall and account blocking code exists but is disabled behind a \"Coming Soon\" message.",
    "Operating-system logs (SSH, Windows Event Logs), firewall logs and network packet capture.",
    "Machine-learning based anomaly detection and external threat-intelligence feeds.",
    "Multi-node clusters, long-term retention policies and cloud deployment.",
])
section("3.3", "Objective of the System")
bullets([
    "**Visibility:** Give a single, real-time view of authentication activity and web traffic.",
    "**Fast detection:** Raise an alert within about 5–15 seconds of an attack pattern appearing.",
    "**Accuracy:** Keep different attacks separate (brute force vs. spraying) and avoid false positives on normal users.",
    "**Explainability:** Every alert states the rule that matched, the attempt count and the MITRE technique.",
    "**No alert fatigue:** One alert per rule per source IP per 5 minutes, even while an attack continues.",
    "**Secure by design:** The SIEM must not be usable to attack its own users (stored XSS, spoofed IPs, open database).",
    "**Easy deployment:** One command (docker compose up) starts the whole system.",
])

section("3.4", "Functionality of System")
sub("1. Log Collection")
para("The FastAPI service writes every demo login attempt to **/var/log/webapp/login.log** as a JSON line containing the "
     "timestamp, log type, event (login_success, login_failed, login_blocked), username, source IP and result. Dashboard "
     "logins are recorded in the same file with log type **dashboard_login**. Nginx writes every HTTP request to "
     "**access_json.log** using a custom JSON log format (timestamp, source IP, method, path, status).")
sub("2. Log Ingestion and Storage")
para("Vector watches both files, parses each JSON line with a VRL **parse_json** transform and ships the events to the "
     "**logs-index** in OpenSearch with the bulk API. Vector remembers its read position in a persistent volume, so no lines "
     "are skipped or duplicated when the container restarts.")
sub("3. Detection Engine")
para("The detection engine is a background task started together with the API. Every 5 seconds it runs four rules. Counting "
     "is done by OpenSearch aggregations, so large attacks are counted completely.")
table([
    ["Rule", "Logic", "Window", "Mapping"],
    ["Web Login Brute Force", "5 or more failed logins on the SAME username from one source IP (attempts on blocked accounts also count)", "2 min", "MITRE T1110"],
    ["Password Spraying Attack", "Failed logins on 3 or more DIFFERENT usernames from one source IP (case-insensitive)", "5 min", "MITRE T1110.003"],
    ["Suspicious Login: Failed Attempts Then Success", "2 or more failures followed by a successful login from the same source IP", "2 min", "MITRE T1078"],
    ["XSS Attempt Detected", "Known XSS signatures (<script, onerror=, javascript:, <img, <svg, …) in the URL-decoded request path", "2 min", "OWASP / CWE-79"],
], [1.55, 2.95, 0.65, 1.05], size=10)
sub("4. Alert Management")
para("Before writing an alert the engine checks whether the same alert type was raised for the same source IP in the last 5 "
     "minutes. The alert document ID is built from the alert type, source IP and 5-minute time window and saved in "
     "**create-only** mode, so OpenSearch refuses a duplicate even if two detection runs overlap. Each alert stores the timestamp, "
     "alert type, source IP, attempt count, severity, matched rule and the MITRE technique, ID and tactic.")
sub("5. Admin Console")
bullets(["Statistic cards: total logs, active alerts, suspicious IPs and login success rate.",
         "Charts: login authentication status (doughnut), log activity per minute (line) and attack vectors (colour-coded bar chart).",
         "All Logs view: the latest 100 events with readable details (e.g. \"login_failed · user: admin\" or \"GET /search.html?q=… → 200\").",
         "Threats & Action view: latest alert per source IP with severity, MITRE ID and an Analyze / Mitigate button.",
         "Blocked panel and mitigation console (blocking shows \"Coming Soon\" in this version)."])
sub("6. Viewer Dashboard")
bullets(["Same statistics and charts as the admin console, without raw logs, threat details or action buttons.",
         "Calls to admin-only endpoints are rejected by the server with HTTP 403."])
sub("7. Authentication and Access Control")
bullets(["Dashboard login issues a random 48-character session token valid for 8 hours; every API call must send it as a Bearer token.",
         "Passwords are read from environment variables (.env file, not stored in the source code) and compared in constant time.",
         "After 5 failed logins from one IP within 5 minutes the API answers HTTP 429 (rate limiting).",
         "Logout invalidates the token on the server immediately."])
sub("8. Demo Attack Surface")
bullets(["Home page, login page with three demo accounts, and a search page that reflects the query without escaping (intentionally vulnerable).",
         "Used to generate realistic attack traffic during the demonstration."])
sub("9. Response Module (planned, disabled)")
para("The API contains complete code for blocking an IP at the host firewall (iptables / ip6tables in both the INPUT and "
     "DOCKER-USER chains) and for blocking a demo account. Protected addresses (loopback, the machine's own IP and the Docker "
     "network) can never be blocked. The feature is switched off with **BLOCKING_ENABLED = False** and is planned for a future version.")

section("3.5", "Expected Outcome")
bullets([
    "Every login attempt and web request is visible in one place within seconds.",
    "Each of the four attack types produces exactly one correctly classified, MITRE-mapped alert, while normal users produce none.",
    "Detection works continuously, even when no dashboard is open.",
    "Administrators and viewers see role-appropriate information; unauthorized actions are refused by the server.",
    "The SIEM resists attacks against itself: spoofed IP headers, stored XSS through log data and brute force on the dashboard login.",
    "The whole system starts with one command and works offline (all dashboard libraries are served locally).",
])

# =========================================================================================
# CHAPTER 4
# =========================================================================================
chapter(4, "Project Planning and Scheduling")
section("4.1", "Feasibility Study")
para("A feasibility study was carried out to check whether Micro-SIEM can be built and used successfully within the available "
     "time, budget and skills. Four aspects were evaluated.")
sub("A. Technical Feasibility")
para("Technical feasibility checks whether the system can be built with the available technology and knowledge.", indent_first=False)
bullets(["**Evaluation of technologies**",
         ["OpenSearch provides indexing, search and aggregations needed for detection (open-source fork of Elasticsearch).",
          "Vector is a fast, lightweight log shipper with a built-in transformation language (VRL).",
          "FastAPI offers automatic request validation and interactive API documentation.",
          "Docker Compose runs all six services with one configuration file."],
         "**Scalability assessment**",
         ["Aggregation queries let OpenSearch count events, so rules keep working for large attacks.",
          "More log sources can be added by adding a Vector source without changing the detection code structure."],
         "**Security implementation**",
         ["Token-based sessions, roles, rate limiting and output escaping are implemented with standard library features.",
          "OpenSearch is bound to localhost so the unauthenticated database is not reachable from the network."]])
sub("B. Economic Feasibility")
para("Economic feasibility checks whether the project is financially viable.", indent_first=False)
bullets(["**Cost-benefit analysis**",
         ["All software is free and open-source: OpenSearch (Apache 2.0), Vector (MPL 2.0), FastAPI (MIT), Nginx, Docker.",
          "No licence fees, unlike commercial SIEMs that charge per GB of data ingested per day.",
          "Runs on an existing laptop; no server or cloud cost."],
         "**Benefit**",
         ["Provides practical knowledge of SOC tools that are in high demand in the cyber-security industry.",
          "Can be reused by small labs or organizations as a starting point for log monitoring."]])
sub("C. Operational Feasibility")
para("Operational feasibility checks whether the system will be usable and accepted by its users.", indent_first=False)
bullets(["**System usability**", ["Dark, terminal-style dashboards that are readable on desktop and mobile screens.",
                                  "Readable log details and colour-coded attack charts reduce analysis time."],
         "**Automation**", ["Detection, de-duplication and alert storage run automatically without operator action."],
         "**Accessibility**", ["Dashboards (port 8090) and demo portal (port 8080) are reachable from any device on the LAN, each through a single port; the demo portal was also exposed through ngrok."]])
sub("D. Schedule Feasibility")
para("Schedule feasibility ensures that the project can be completed on time.", indent_first=False)
bullets(["**Timeline evaluation**", ["The project followed a four-month plan (July – October 2026) divided into five Spiral cycles.",
                                    "The early cycles delivered a working log pipeline first, reducing integration risk."],
         "**Risk mitigation strategies**", ["A risk-analysis step at the start of every cycle, before any code was written.",
                                           "Image versions pinned to avoid surprise breaking upgrades before the demonstration.",
                                           "Testing and review at the end of each cycle and a written progress log (PROGRESS.md)."]])

section("4.2", "Software Engineering Model")
sub("A. Overview of the Spiral Model")
para("Micro-SIEM was developed using the **Spiral model** (Barry Boehm). The Spiral model combines the step-by-step "
     "structure of the Waterfall model with iterative development, and puts **risk analysis** at the centre of every "
     "iteration. The project moves outwards in loops (cycles); every loop builds a bigger part of the system and passes "
     "through the same four quadrants:")
numbered([
    "**Determine objectives, alternatives and constraints** – what this cycle must deliver, which tools or designs could "
    "do it, and the limits (one laptop, 4-month schedule, free tools only).",
    "**Identify and resolve risks** – list what could go wrong (technical and security risks), and resolve the biggest "
    "ones first, by research, a small prototype or a design decision.",
    "**Develop and test** – build the part planned for the cycle and test it with the parts already built.",
    "**Evaluate and plan the next iteration** – review the result (with the internal guide), record findings in the "
    "progress log and plan the objectives of the next cycle.",
])
sub("B. Why the Spiral Model for a Security Project")
para("A SIEM is a security tool, so its biggest risks are security risks: a SIEM that can be fooled, bypassed or "
     "attacked itself is worse than no SIEM, because it gives a false feeling of safety. The Spiral model was chosen "
     "because it makes this risk analysis a compulsory step of every cycle instead of something done only at the end:")
bullets([
    "**Risk-driven by design:** every cycle starts with \"what could go wrong?\", so threats are analysed before code is "
    "written. Security is built in from the first cycle, not added as a last patch.",
    "**The SIEM itself is attack surface:** risk analysis found real weaknesses in our own system – client-IP spoofing "
    "through X-Forwarded-For that could hide or frame an attacker, stored XSS in the admin dashboard through a fake IP, "
    "a brute-forceable dashboard login and an OpenSearch port open without authentication – and each was fixed in the "
    "following engineering step (implementation in Chapter 6, tests in Chapter 7).",
    "**Dangerous features are prototyped first:** automatic IP blocking could lock the administrator out of their own "
    "machine. It was prototyped with safety checks (loopback, own IP and Docker network refused) and kept switched off "
    "behind a flag until it is fully tested, instead of being shipped as-is.",
    "**Detection quality is a risk too:** missed attacks (false negatives) and false alarms (false positives) were "
    "checked in every evaluation step – for example, URL-encoded XSS payloads that were missed and brute force that "
    "also fired on password spraying were found and fixed in a later cycle.",
    "**New threats fit into the next loop:** when a new attack technique became relevant (password spraying, "
    "T1110.003), it was added as the objective of a later cycle without restarting the project.",
    "**Review before moving on:** the evaluation quadrant acted as a security sign-off with the internal guide before "
    "the next cycle started, which suits a project that must be demonstrated live.",
])
sub("C. Cycles (Loops) of the Project")
table([
    ["Cycle", "Objective", "Key risks analysed", "Deliverable"],
    ["1", "Requirements & concept", "Wrong scope, tools too heavy for one laptop, rules without a real threat model",
     "Scope, four rules mapped to MITRE ATT&CK / CWE, tool choice (OpenSearch, Vector, FastAPI)"],
    ["2", "Architecture & log pipeline", "Lost or wrongly parsed events, OpenSearch version incompatibilities",
     "Docker Compose stack; web-login and Nginx events indexed in logs-index"],
    ["3", "Backend & detection", "False positives / negatives, duplicate alerts, big attacks under-counted",
     "FastAPI service, demo portal, brute force, spraying, correlation and XSS rules, alert index"],
    ["4", "Dashboards, auth & response", "Unauthorised access, viewer using admin actions, blocking own machine",
     "Admin and viewer dashboards, token sessions, role checks, blocking module (kept disabled)"],
    ["5", "Security hardening & validation", "IP spoofing, stored XSS, dashboard brute force, exposed database",
     "Trusted-proxy IP handling, output escaping, rate limiting, localhost-only OpenSearch, live end-to-end tests"],
], [0.55, 1.35, 2.15, 2.2], center_cols=(0,), size=10)
sub("D. Advantages of the Spiral Model for this Project")
bullets(["Security risks were found and fixed during development, before the live demonstration.",
         "A working log pipeline existed early (cycle 2), which reduced the risk of late integration failures.",
         "Flexible scope: new rules and fixes were added in later cycles when their need became clear.",
         "Testing and evaluation at the end of every cycle produced a reliable system for the demonstration."])

section("4.3", "Requirement Analysis and Data Gathering")
sub("A. Data Gathering Techniques")
bullets([
    "**Study of documentation:** OpenSearch, Vector, FastAPI, Nginx and Docker official documentation.",
    "**Study of threat frameworks:** MITRE ATT&CK techniques T1110, T1110.003 and T1078; OWASP Top 10 and CWE-79.",
    "**Observation of real log formats:** Nginx access logs and authentication logs were studied to decide which fields are needed.",
    "**Review of existing SIEMs:** Concepts such as correlation rules, alert de-duplication and role-based dashboards were studied from Splunk, Wazuh and Elastic Security.",
    "**Discussions with the internal guide** to fix the scope, the rules and the demonstration flow.",
])
sub("B. Functional Requirements")
table([
    ["ID", "Requirement"],
    ["FR-1", "The system shall record every demo login attempt with timestamp, username, source IP and result."],
    ["FR-2", "The system shall record every HTTP request to the demo portal (method, path, status, source IP)."],
    ["FR-3", "The system shall ship all events to a central searchable store within seconds."],
    ["FR-4", "The system shall detect brute force, password spraying, fail-then-success and XSS attempts automatically."],
    ["FR-5", "The system shall store alerts permanently with severity and MITRE ATT&CK / CWE mapping."],
    ["FR-6", "The system shall raise at most one alert per rule per source IP per 5 minutes."],
    ["FR-7", "The system shall authenticate dashboard users and support admin and viewer roles."],
    ["FR-8", "The admin shall be able to view statistics, raw logs, alerts and the blocked list."],
    ["FR-9", "The viewer shall only see statistics and charts."],
    ["FR-10", "The system shall provide an API with interactive documentation."],
], [0.8, 5.4], center_cols=(0,))
sub("C. Non-Functional Requirements")
table([
    ["ID", "Category", "Requirement"],
    ["NFR-1", "Performance", "Detection runs every 5 s; an alert appears within about 15 s of the attack."],
    ["NFR-2", "Security", "Server-side sessions, role checks, rate limiting, validated client IPs, escaped output, localhost-only database."],
    ["NFR-3", "Reliability", "Detection survives OpenSearch restarts; no duplicate alerts; persistent Vector checkpoints."],
    ["NFR-4", "Usability", "Readable dashboards in IST time, usable on desktop and mobile."],
    ["NFR-5", "Portability", "Runs on any OS with Docker; pinned versions; works offline."],
    ["NFR-6", "Maintainability", "Modular rules, documented code, progress log and README."],
], [0.8, 1.3, 4.1], center_cols=(0,))

section("4.4", "Time Line Chart", new_page=True)
para("The project was planned over four months (July – October 2026) as five Spiral cycles. The Gantt chart below "
     "shows each cycle split into its four quadrants – objectives, risk analysis, development and testing, and "
     "evaluation – followed by documentation.", indent_first=False)
figure(f"{DIAG}/gantt.png", "Project Time Line (Gantt) Chart", 4)

# =========================================================================================
# CHAPTER 5
# =========================================================================================
chapter(5, "System Analysis & Design")
section("5.1", "Use Case Diagram")
para("The use case diagram shows the actors of Micro-SIEM and the functions each actor can perform.", indent_first=False)
figure(f"{DIAG}/usecase.png", "Use Case Diagram of Micro-SIEM", 5, max_h=7.8)
sub("Use Case Description")
table([
    ["Use Case", "Actor", "Description"],
    ["Login to Dashboard", "Admin, Viewer", "Enter username and password; receive a session token and role (rate-limited)."],
    ["View Dashboard Statistics", "Admin, Viewer", "See total logs, active alerts, suspicious IPs, success rate and charts."],
    ["View All Logs", "Admin", "See the latest events from all sources with readable details."],
    ["View Threats / Alerts", "Admin", "See the latest alert per source IP with severity and MITRE ID."],
    ["Analyze / Mitigate Alert", "Admin", "Open the security action panel for a source IP."],
    ["Block / Unblock IP or Account", "Admin", "Planned response action (disabled in this version)."],
    ["View Blocked List", "Admin", "See blocked IPs and accounts."],
    ["Logout", "Admin, Viewer", "Invalidate the session token on the server."],
    ["Login to Demo Portal", "Demo User / Attacker", "Attempt a login; every attempt is logged."],
    ["Search Records", "Demo User / Attacker", "Search page that reflects the query (XSS target)."],
    ["Collect & Store Logs", "Detection Engine", "Vector ships events to OpenSearch."],
    ["Run Detection Rules", "Detection Engine", "Evaluate the four rules every 5 seconds."],
    ["Raise MITRE-Mapped Alert", "Detection Engine", "Write a de-duplicated alert to the alert history."],
], [1.9, 1.4, 2.9])

section("5.2", "Class Diagram", new_page=True)
para("The backend is a single FastAPI service. Its class diagram is shown in two parts for readability: Figure 5.2 shows "
     "the API layer with the session manager, detection engine, firewall manager and request models; Figure 5.3 shows the "
     "detection engine with its four rules and the data objects stored in OpenSearch.",
     indent_first=False)
figure(f"{DIAG}/class_core.png", "Class Diagram – API, Sessions, Firewall and Requests", 5, max_h=7.6)
figure(f"{DIAG}/class_rules.png", "Class Diagram – Detection Engine, Rules and Data Objects", 5, max_h=7.6)

section("5.3", "Activity Diagram", new_page=True)
sub("5.3.1 Dashboard Login and Admin Activity")
figure(f"{DIAG}/activity_admin.png", "Activity Diagram – Dashboard Login and Admin Console", 5, max_h=7.8)
sub("5.3.2 Detection Engine Activity")
figure(f"{DIAG}/activity_detection.png", "Activity Diagram – Detection Engine Cycle", 5, max_h=7.6)
sub("5.3.3 Demo User / Attacker Activity")
figure(f"{DIAG}/activity_attacker.png", "Activity Diagram – Demo Portal Login and Attack Flow", 5, max_h=7.6)

section("5.4", "Deployment Diagram", new_page=True)
para("Micro-SIEM is deployed as six Docker containers on one host. Only the demo portal (8080), the dashboards (8090) and "
     "the API (8000) are reachable from the network; OpenSearch and OpenSearch Dashboards are bound to 127.0.0.1.", indent_first=False)
figure(f"{DIAG}/deployment.png", "Deployment Diagram of Micro-SIEM", 5, max_h=6.0)
table([
    ["Container", "Image", "Port", "Role"],
    ["opensearch", "opensearchproject/opensearch:3.8.0", "127.0.0.1:9200", "Stores and indexes logs, alerts, blocklist"],
    ["opensearch-dashboards", "opensearch-dashboards:3.8.0", "127.0.0.1:5601", "Raw data exploration"],
    ["vector", "timberio/vector:0.59.0-alpine", "–", "Tails log files, ships to OpenSearch"],
    ["fastapi-app", "micro-siem-api (Python 3.11)", "8000 (host)", "API, auth, detection engine"],
    ["nginx-loginpage", "nginx:1.30.6-alpine", "8080", "Demo portal + /api proxy"],
    ["react-console", "nginx:1.30.6-alpine", "8090", "Dashboards + /api proxy"],
], [1.45, 2.15, 1.15, 1.45], size=10)

section("5.5", "Database Design", new_page=True)
para("Micro-SIEM uses **OpenSearch**, a NoSQL document store. Data is stored as JSON documents in three indices (the "
     "equivalent of tables). Text fields are automatically indexed both as full-text (text) and as exact values (keyword) "
     "for filtering and aggregations. The structure below was read from the live index mappings.")
sub("1) Index: logs-index")
para("Primary key: _id (generated by OpenSearch). Stores every event from both log sources.", indent_first=False)
table([
    ["Field Name", "Data Type", "Source", "Description"],
    ["timestamp", "date", "All", "Time of the event (UTC)"],
    ["log_type", "text + keyword", "All", "web_login, dashboard_login or nginx_access"],
    ["event", "text + keyword", "Login logs", "login_success, login_failed, login_blocked, dashboard_login_*"],
    ["username", "text + keyword", "Login logs", "Username entered in the login form"],
    ["source_ip", "text + keyword", "All", "Validated client IP address"],
    ["result", "text + keyword", "Login logs", "success, failed or blocked"],
    ["method", "text + keyword", "Nginx", "HTTP method (GET, POST)"],
    ["path", "text + keyword", "Nginx", "Requested URI including the query string"],
    ["status", "long", "Nginx", "HTTP response status code"],
    ["message", "text + keyword", "Vector", "Original raw log line"],
    ["file / host / source_type", "text + keyword", "Vector", "Source file, collector host and source type metadata"],
], [1.55, 1.2, 1.05, 2.4], size=10)
sub("2) Index: alerts-index")
para("Primary key: _id = \"alert_type | source_ip | 5-minute window\" (deterministic, prevents duplicate alerts).", indent_first=False)
table([
    ["Field Name", "Data Type", "Description"],
    ["timestamp", "date", "Time the alert was raised"],
    ["alert_type", "text + keyword", "Name of the detected attack"],
    ["source_ip", "text + keyword", "Attacker IP address"],
    ["target_username", "text + keyword", "Targeted account (brute force only)"],
    ["attempt_count", "long", "Number of attempts / distinct usernames / matching requests"],
    ["severity", "text + keyword", "Severity level (HIGH)"],
    ["matched_rule", "text + keyword", "Rule that matched, e.g. 5_failed_web_logins_same_user_2min"],
    ["mitre_technique", "text + keyword", "Technique name, e.g. Brute Force"],
    ["mitre_id", "text + keyword", "T1110, T1110.003, T1078 or CWE-79"],
    ["mitre_tactic", "text + keyword", "Credential Access, Initial Access or N/A"],
], [1.6, 1.3, 3.3], size=10)
sub("3) Index: blocked-index")
para("Primary key: _id (generated). Stores blocked IPs and accounts (used by the planned response module).", indent_first=False)
table([
    ["Field Name", "Data Type", "Description"],
    ["type", "text + keyword", "ip or account"],
    ["ip", "text + keyword", "Blocked IP address (normalised)"],
    ["username", "text + keyword", "Blocked demo account"],
    ["blocked_at", "date", "Time of blocking"],
    ["blocked_by", "text + keyword", "Who blocked it (admin)"],
], [1.6, 1.3, 3.3], size=10)

# =========================================================================================
# CHAPTER 6
# =========================================================================================
chapter(6, "System Implementation")
section("6.1", "Source Code / Screen Shots")
sub("6.1.1 Source Code")
para("The complete source code is kept in the project repository; instead of printing long listings, the table below "
     "explains what each part of the implementation does. The screenshots in Section 6.1.2 show the result of this code "
     "running, and Chapter 7 shows how it was tested.", indent_first=False)
table([
    ["File / Component", "What it does"],
    ["docker-compose.yml", "Starts all six containers with one command, pins every image version, keeps OpenSearch reachable only "
     "from the host itself and waits until OpenSearch is healthy before starting the other services."],
    ["vector/vector.toml", "Reads the web-login log and the Nginx access log, parses each JSON line and ships the events to the "
     "logs-index in OpenSearch; remembers its read position so no line is lost or read twice after a restart."],
    ["nginx/default.conf", "Serves the demo portal, writes every request as a JSON access-log line and passes the real client IP "
     "to the API (an IP header is trusted only from the Docker network or the host itself)."],
    ["main.py – client IP check", "Works out the real source IP of each request and rejects fake or malformed IP headers, which "
     "stops attackers from hiding or framing someone else and blocks stored XSS through the IP field."],
    ["main.py – demo login", "The login of the demo portal; every attempt (success, failure, blocked account) is written to the "
     "web-login log with time, username and source IP."],
    ["main.py – detection loop", "Runs all four rules every 5 seconds in the background, whether or not a dashboard is open, and "
     "writes at most one alert per rule per source IP in each 5-minute window."],
    ["main.py – brute force rule", "Raises an alert when one IP fails to log in 5 or more times on the same username within "
     "2 minutes (MITRE T1110)."],
    ["main.py – password spraying rule", "Raises an alert when one IP fails against 3 or more different usernames within "
     "5 minutes (MITRE T1110.003)."],
    ["main.py – correlation rule", "Raises an alert when an IP logs in successfully after earlier failed attempts – a "
     "possibly guessed password (MITRE T1078)."],
    ["main.py – XSS rule", "Decodes each requested URL and looks for known XSS patterns such as script tags and event "
     "handlers (OWASP / CWE-79)."],
    ["main.py – dashboard login", "Checks the admin / viewer password, allows at most 5 failures per IP in 5 minutes and logs "
     "every dashboard login attempt."],
    ["main.py – role checks", "Every API call needs a valid session; admin-only actions (block / unblock) are refused for the "
     "viewer role on the server side."],
    ["admin.html / viewer.html", "The dashboards: show times in IST, turn raw log lines into readable details and escape every "
     "value before showing it, so log data can never run as script in the browser."],
], [1.9, 4.3], first_col_bold=True, size=10.5)

sub("6.1.2 Screen Shots")
SHOT_SIZE = {  # cropped screenshots are shown smaller than full-width ones
    "08-admin-threats": dict(max_h=5.4), "09-admin-mitigation-modal": dict(max_w=4.6),
    "10-admin-coming-soon": dict(max_w=4.2), "07-admin-logs": dict(max_h=5.0),
}
def shot(name, caption, title=None):
    if title:
        p = doc.add_paragraph(style=S_SUB); p.add_run(title)
    figure(f"{SHOTS}/{name}.png", caption, 6, **SHOT_SIZE.get(name, {}))

doc.add_paragraph(style=S_SUB).add_run("MODULE NAME – DEMO PORTAL (ATTACK TARGET)")
shot("01-demo-home", "Demo Portal – Home Page (port 8080)")
shot("02-demo-login-failed", "Demo Portal – Login Page showing a failed attempt (logged as login_failed)")
shot("03-demo-search-xss", "Demo Portal – Search Page reflecting an XSS payload (intentionally vulnerable)")
p = doc.add_paragraph(style=S_SUB); p.add_run("MODULE NAME – DASHBOARD ACCESS")
shot("04-dashboard-login", "Micro-SIEM Dashboard Sign-In (port 8090)")
shot("05-dashboard-login-failed", "Dashboard Sign-In – invalid credentials (attempt logged, rate-limited after 5 failures)")
p = doc.add_paragraph(style=S_SUB); p.add_run("MODULE NAME – ADMIN CONSOLE")
shot("06-admin-dashboard", "Admin Console – Statistics, Login Status, Log Activity and Attack Vectors")
shot("07-admin-logs", "Admin Console – All Logs (system event stream with readable details)")
shot("08-admin-threats", "Admin Console – Threats & Action (MITRE-mapped alerts per source IP)")
shot("09-admin-mitigation-modal", "Admin Console – Security Action Panel for the brute-force attacker")
shot("10-admin-coming-soon", "Admin Console – IP blocking shows \"Coming Soon\" (response module disabled)")
p = doc.add_paragraph(style=S_SUB); p.add_run("MODULE NAME – VIEWER")
shot("11-viewer-dashboard", "Viewer Dashboard – read-only statistics and charts")
p = doc.add_paragraph(style=S_SUB); p.add_run("MODULE NAME – API AND DATA")
shot("12-swagger-api-docs", "FastAPI Interactive Documentation – all 12 API endpoints")
shot("13-opensearch-discover", "OpenSearch Dashboards – Discover view of logs-index")
p = doc.add_paragraph(style=S_SUB); p.add_run("MODULE NAME – DEPLOYMENT AND LIVE DETECTION")
shot("term_ps", "All six containers running (docker compose ps)")
shot("term_detect", "Live detection test – each attack raises exactly one alert, normal user raises none")

# =========================================================================================
# CHAPTER 7
# =========================================================================================
chapter(7, "System Testing")
section("7.1", "Testing Strategies")
para("System testing is the phase in which the complete, integrated system is evaluated against its requirements. For a "
     "security monitoring system testing has two goals: the SIEM must **detect** every attack it is designed for without "
     "false alarms, and the SIEM must itself be **secure**. Micro-SIEM was tested offline with a mocked database, live on the "
     "running Docker stack with real attack traffic, and in a real (headless) web browser.")
sub("1. White-Box Testing")
para("White-box (glass-box) testing examines the internal logic of the code. Each detection rule, the IP trust function, the "
     "rate limiter, the session handling and the firewall helper functions were tested directly with known inputs against a "
     "fake OpenSearch client (48 automated checks).", indent_first=False)
bullets(["All branches of every rule (threshold reached / not reached, already alerted / not alerted).",
         "Boundary values: exactly 1 vs. 2 failures before success, 2 vs. 3 usernames, case variants of usernames.",
         "Error paths: missing index, OpenSearch not yet ready, missing firewall chain."])
sub("2. Black-Box Testing")
para("Black-box testing checks the behaviour from the outside without looking at the code. All 12 API endpoints were "
     "called with valid, invalid, missing and malicious input, and the HTTP status and response were compared with the "
     "expected result (49 checks).", indent_first=False)
bullets(["Incorrect or missing input (422), missing / invalid / expired token (401), wrong role (403), disabled feature (503).",
         "Boundary values for the limit parameter (0, 1000, 1001, 5000, non-numeric)."])
sub("3. Unit Testing")
bullets(["**Client IP module:** trusted proxy header accepted, HTML in header rejected, untrusted peer cannot spoof.",
         "**Protected addresses:** loopback in all forms (::1, 0:0::1, 127.0.0.2, ::ffff:127.0.0.1), own IP and Docker range refused.",
         "**Detection rules:** each rule fires only for its own pattern; XSS payloads detected even when URL-encoded or double-encoded.",
         "**Frontend helpers:** time conversion for both timestamp formats; HTML escaping of quotes and tags."])
sub("4. Integration Testing")
para("Integration testing verifies that the components work together correctly across the whole pipeline.", indent_first=False)
numbered(["**Ingestion pipeline:** demo login / Nginx request → log file → Vector → OpenSearch logs-index.",
          "**Detection pipeline:** logs-index → background detection loop → alerts-index (with no dashboard open).",
          "**Dashboard pipeline:** browser → Nginx /api proxy → FastAPI → OpenSearch → rendered charts and tables.",
          "**Account blocking:** block via admin API → enforced on the real demo login and existing sessions → unblock."])
sub("5. System and Security Testing")
bullets(["Live end-to-end run of all four attacks plus normal traffic from distinct client IPs.",
         "Security tests: rate limit, IP spoofing from an untrusted network, OpenSearch reachability from another network.",
         "Browser test: login, all dashboard views, modal and logout in headless Chromium with zero JavaScript errors."])

section("7.2", "Test Cases", new_page=True)
TC = [
    ["TC ID", "Test Case", "Input / Steps", "Expected Result", "Status"],
    ["TC-01", "Log ingestion", "Demo login attempts and page requests", "Events appear in logs-index with correct IP and timestamp", "Pass"],
    ["TC-02", "Brute force", "6 wrong passwords for 'admin' from one IP", "1 'Web Login Brute Force' alert (T1110), no spraying alert", "Pass"],
    ["TC-03", "Password spraying", "1 wrong password each for admin, test, guest", "1 'Password Spraying Attack' alert (T1110.003), no brute force", "Pass"],
    ["TC-04", "Correlation", "2 failures, then correct password", "1 'Failed Attempts Then Success' alert (T1078)", "Pass"],
    ["TC-05", "Correlation boundary", "1 failure, then correct password", "No alert", "Pass"],
    ["TC-06", "XSS (encoded)", "search.html?q=%3Cimg%20src%3Dx%20onerror%3D…%3E", "1 'XSS Attempt Detected' alert (CWE-79)", "Pass"],
    ["TC-07", "Normal user", "Correct login + normal search", "No alert (no false positive)", "Pass"],
    ["TC-08", "Alert de-duplication", "Attack continues after first alert", "Still exactly 1 alert per rule per IP", "Pass"],
    ["TC-09", "Detection without dashboard", "Attack with no dashboard open", "Alert raised by background loop", "Pass"],
    ["TC-10", "Blocked-account attacks", "6 attempts on a blocked account", "Brute force alert (login_blocked counted)", "Pass"],
    ["TC-11", "Dashboard login", "Correct admin / viewer credentials", "Token issued with correct role", "Pass"],
    ["TC-12", "Invalid login", "Wrong password / unknown user", "HTTP 401, attempt logged", "Pass"],
    ["TC-13", "Rate limiting", "6 wrong dashboard logins from one IP", "401 ×5 then 429 Too Many Requests", "Pass"],
    ["TC-14", "Missing token", "GET /alerts without token", "HTTP 401", "Pass"],
    ["TC-15", "Role check", "Viewer calls POST /block/8.8.8.8", "HTTP 403 Forbidden", "Pass"],
    ["TC-16", "Limit validation", "GET /logs?limit=99999", "HTTP 422 (not 500)", "Pass"],
    ["TC-17", "Logout", "POST /auth/logout, reuse token", "Token rejected with 401", "Pass"],
    ["TC-18", "IP spoofing (direct)", "Fake X-Real-IP from untrusted network", "Real peer IP logged, fake ignored", "Pass"],
    ["TC-19", "Stored XSS via header", "X-Forwarded-For: <img src=x onerror=…>", "Value rejected, never stored or rendered", "Pass"],
    ["TC-20", "Database exposure", "Connect to :9200 from another network", "Connection refused; works on localhost only", "Pass"],
    ["TC-21", "Account blocking", "Admin blocks 'test', user logs in", "Refused even with right password; session ended", "Pass"],
    ["TC-22", "Account unblocking", "Admin unblocks 'test'", "User can log in immediately", "Pass"],
    ["TC-23", "Dashboard rendering", "Login in headless Chromium, open all views", "Charts, tables, IST times; 0 JS errors", "Pass"],
    ["TC-24", "Readable log details", "Open All Logs view", "No raw JSON; XSS payload shown as text only", "Pass"],
    ["TC-25", "Fresh start", "Start stack with empty indices", "Endpoints return 200 with empty lists", "Pass"],
]
table(TC, [0.6, 1.25, 1.75, 2.05, 0.55], size=9.5, center_cols=(0, 4))
sub("Summary of Test Results")
table([
    ["Test Suite", "Environment", "Checks", "Result"],
    ["Unit / white-box (mocked OpenSearch)", "Python virtual environment", "48", "48 passed"],
    ["Live pipelines (ingestion, detection, dashboards, security)", "Docker stack", "35", "34 passed, 1 inconclusive*"],
    ["All 12 API endpoints (black-box)", "Docker stack", "49", "49 passed"],
    ["Account blocking end-to-end", "Docker stack", "28", "28 passed"],
    ["Attacks on blocked accounts", "Docker stack", "7", "7 passed"],
    ["Dashboards in a real browser", "Headless Chromium", "UI flows", "0 JavaScript errors"],
], [2.6, 1.5, 0.8, 1.3], size=10, center_cols=(2,))
para("* Spoofing a valid-looking IP from a second physical device on the Wi-Fi network cannot be simulated from one machine "
     "and is verified manually with a mobile phone.", indent_first=False)

# =========================================================================================
# CHAPTER 8
# =========================================================================================
chapter(8, "Conclusion and Future Scope")
sub("Conclusion:")
para("**Micro-SIEM** successfully demonstrates the complete working of a Security Information and Event Management system "
     "using only free and open-source tools. Web login events and Nginx access logs are collected, shipped by Vector, indexed "
     "by OpenSearch and analysed automatically every five seconds. Four detection rules recognise brute-force, password-spraying, "
     "credential-compromise and Cross-Site Scripting attacks, and every alert is mapped to the MITRE ATT&CK framework or to "
     "OWASP/CWE. Admin and viewer dashboards present the security situation clearly, while server-side sessions, roles, rate "
     "limiting and validated input keep the monitoring system itself secure.", indent_first=False)
para("Extensive testing (unit, API, integration, live attack scenarios and browser tests) showed that every attack produces "
     "exactly one correctly classified alert and normal users produce none. The project gave practical experience of the "
     "tools and ideas used in real Security Operations Centres.", indent_first=False)
para("Key benefits of the system:", indent_first=False)
numbered(["**Centralized visibility:** All security events in one searchable place.",
          "**Real-time detection:** Attacks detected within seconds, even with no one watching.",
          "**Standard mapping:** MITRE ATT&CK and CWE identifiers make alerts meaningful.",
          "**Secure by design:** The SIEM resists IP spoofing, stored XSS and brute force against itself.",
          "**Low cost and portable:** Runs with one command on a single laptop, even offline."])
sub("Limitations:")
bullets(["Only two log sources (web application and Nginx) are monitored in this version.",
         "Automatic blocking is implemented but disabled; responses are manual.",
         "OpenSearch runs as a single node without its security plugin (protected by binding to localhost).",
         "Rules are threshold and signature based, so new or slow attacks may go unnoticed."])
sub("Future Scope:")
numbered([
    "**Enable the response module:** Activate IP blocking (INPUT + DOCKER-USER chains) and account blocking after field testing.",
    "**More log sources:** SSH / Linux auth logs, Windows Event Logs, firewall and DNS logs.",
    "**Sigma rule support:** Import community detection rules written in the vendor-neutral Sigma format.",
    "**Additional rules:** Web scanning / directory enumeration, impossible travel, privilege escalation.",
    "**Alert notifications:** E-mail, Telegram or Slack messages for high-severity alerts.",
    "**Threat intelligence and GeoIP:** Enrich IPs with reputation, country and ASN information.",
    "**Machine learning:** Behaviour-based anomaly detection for unknown attack patterns.",
    "**Production hardening:** OpenSearch security plugin with TLS, index lifecycle management for retention, multi-node cluster.",
    "**Incident management:** Alert status workflow (new, investigating, resolved) with analyst notes.",
    "**Cloud deployment:** Hosting the stack on a cloud VM for continuous monitoring.",
])

# =========================================================================================
# CHAPTER 9
# =========================================================================================
chapter(9, "Bibliography")
table([
    ["Category", "Details"],
    ["Books", "1. Security Information and Event Management (SIEM) Implementation – David R. Miller, Shon Harris, Allen Harper, Stephen VanDyke, Chris Blask (McGraw-Hill)\n"
              "2. Applied Network Security Monitoring – Chris Sanders, Jason Smith (Syngress)\n"
              "3. The Practice of Network Security Monitoring – Richard Bejtlich (No Starch Press)\n"
              "4. The Web Application Hacker's Handbook – Dafydd Stuttard, Marcus Pinto (Wiley)\n"
              "5. Docker Deep Dive – Nigel Poulton"],
    ["Standards & Research Papers", "1. NIST SP 800-92: Guide to Computer Security Log Management – K. Kent, M. Souppaya\n"
              "2. NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide\n"
              "3. MITRE ATT&CK: Design and Philosophy – The MITRE Corporation\n"
              "4. OWASP Top 10 – Open Worldwide Application Security Project"],
    ["Websites", "1. https://attack.mitre.org – MITRE ATT&CK techniques T1110, T1110.003, T1078\n"
              "2. https://cwe.mitre.org/data/definitions/79.html – CWE-79 Cross-Site Scripting\n"
              "3. https://owasp.org – OWASP XSS prevention and Top 10\n"
              "4. https://opensearch.org/docs – OpenSearch and OpenSearch Dashboards documentation\n"
              "5. https://vector.dev/docs – Vector sources, VRL and sinks\n"
              "6. https://fastapi.tiangolo.com – FastAPI documentation\n"
              "7. https://nginx.org/en/docs – Nginx log_format and real_ip module\n"
              "8. https://docs.docker.com – Docker Compose, networking and packet filtering (DOCKER-USER)\n"
              "9. https://www.chartjs.org and https://tailwindcss.com – frontend libraries"],
    ["College Materials", "1. Software engineering and SDLC notes from faculty\n2. Lecture notes on requirement analysis, UML and system design"],
    ["Tools & Technologies", "Backend: Python, FastAPI, Uvicorn\nStorage: OpenSearch, OpenSearch Dashboards\nLog pipeline: Vector\n"
              "Web server: Nginx\nFrontend: HTML, Tailwind CSS, JavaScript, Chart.js\nDeployment: Docker, Docker Compose\n"
              "Diagrams: Graphviz, Matplotlib\nVersion control: Git, GitHub"],
], [1.45, 4.75], first_col_bold=True, size=10.5)

# =========================================================================================
# INDEX page numbers
# =========================================================================================
if PAGES:
    from docx.table import Table as _T
    tbl = _T(idx_tbl, doc._body)
    for row in tbl.rows:
        cells = row.cells
        key = None
        for c in cells[:3]:
            tx = c.text.strip()
            if re.fullmatch(r"\d\.\d", tx): key = tx; break
        if key is None:
            first = cells[0].text.strip()
            if first in ("7", "8", "9"): key = first
        if key and key in PAGES:
            last = cells[-1]
            lp = last.paragraphs[0]           # keep the template's paragraph formatting (tight spacing)
            for r_ in list(lp.runs): r_._r.getparent().remove(r_._r)
            r = lp.add_run(str(PAGES[key])); r.bold = True; set_font(r.font, 11)
            lp.alignment = WD_ALIGN_PARAGRAPH.CENTER

# ---------------------------------------------------------------- schema order (Word is strict)
ORDER = {
    "tblPr": ["tblStyle", "tblpPr", "tblOverlap", "bidiVisual", "tblStyleRowBandSize", "tblStyleColBandSize", "tblW", "jc",
              "tblCellSpacing", "tblInd", "tblBorders", "shd", "tblLayout", "tblCellMar", "tblLook", "tblCaption", "tblDescription"],
    "sectPr": ["headerReference", "footerReference", "footnotePr", "endnotePr", "type", "pgSz", "pgMar", "paperSrc", "pgBorders",
               "lnNumType", "pgNumType", "cols", "formProt", "vAlign", "noEndnote", "titlePg", "textDirection", "bidi", "rtlGutter",
               "docGrid", "printerSettings", "sectPrChange"],
    "tcPr": ["cnfStyle", "tcW", "gridSpan", "hMerge", "vMerge", "tcBorders", "shd", "noWrap", "tcMar", "textDirection",
             "tcFitText", "vAlign", "hideMark", "headers", "cellIns", "cellDel", "cellMerge", "tcPrChange"],
    "pPr": ["pStyle", "keepNext", "keepLines", "pageBreakBefore", "framePr", "widowControl", "numPr", "suppressLineNumbers",
            "pBdr", "shd", "tabs", "suppressAutoHyphens", "kinsoku", "wordWrap", "overflowPunct", "topLinePunct", "autoSpaceDE",
            "autoSpaceDN", "bidi", "adjustRightInd", "snapToGrid", "spacing", "ind", "contextualSpacing", "mirrorIndents",
            "suppressOverlap", "jc", "textDirection", "textAlignment", "textboxTightWrap", "outlineLvl", "divId", "cnfStyle",
            "rPr", "sectPr", "pPrChange"],
    "trPr": ["cnfStyle", "divId", "gridBefore", "gridAfter", "wBefore", "wAfter", "cantSplit", "trHeight", "tblHeader",
             "tblCellSpacing", "jc", "hidden", "ins", "del", "trPrChange"],
}
def reorder(root):
    for tag, order in ORDER.items():
        for el in root.iter(qn(f"w:{tag}")):
            kids = list(el)
            def key(k):
                name = k.tag.split("}")[1]
                return order.index(name) if name in order else len(order)
            kids_sorted = sorted(kids, key=key)
            if kids_sorted != kids:
                for k in kids: el.remove(k)
                for k in kids_sorted: el.append(k)
reorder(doc.element)
reorder(doc.styles.element)
for sct in doc.sections:
    for hf in (sct.header, sct.footer):
        reorder(hf._element)

doc.save(OUT)
print("saved", OUT)
