import logging
import re
import sys
from copy import deepcopy
from io import BytesIO
from urllib.parse import urlparse
from zipfile import ZipFile

from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor

from pipeline.constants import LOCALES
from pipeline.dependencies import Document, OxmlElement, qn
from pipeline.formatting import word_rows
from pipeline.output import title_date

log = logging.getLogger(__name__)
URL_PATTERN = re.compile(r"https?://[^\s<>，；。]+")


def replace_text(container, text):
    paragraphs = getattr(container, "paragraphs", [container])
    first = paragraphs[0]
    first.clear()
    first.add_run(str(text))
    for paragraph in paragraphs[1:]:
        paragraph._p.getparent().remove(paragraph._p)


def _font(run, size=11, bold=False):
    run.font.name = "Arial"
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = RGBColor(0, 0, 0)
    props = run._element.get_or_add_rPr()
    fonts = props.get_or_add_rFonts()
    for key in list(fonts.attrib):
        if "theme" in key.lower():
            del fonts.attrib[key]
    fonts.set(qn("w:eastAsia"), "Arial Unicode MS")
    # The original template sets a separate complex-script size.
    size_cs = props.find(qn("w:szCs"))
    if size_cs is not None:
        size_cs.set(qn("w:val"), str(int(size * 2)))


def _paragraph(paragraph, centered=False):
    fmt = paragraph.paragraph_format
    fmt.alignment = WD_ALIGN_PARAGRAPH.CENTER if centered else WD_ALIGN_PARAGRAPH.LEFT
    fmt.space_before = Pt(0)
    fmt.space_after = Pt(2)
    fmt.line_spacing = 1.12
    fmt.widow_control = True
    fmt.keep_with_next = False
    props = paragraph._p.get_or_add_pPr()
    # Template grid snapping and paragraph-mark sizes cause oversized gaps.
    for tag in ("rPr", "ind"):
        node = props.find(qn("w:" + tag))
        if node is not None:
            props.remove(node)
    snap = props.find(qn("w:snapToGrid"))
    if snap is None:
        snap = OxmlElement("w:snapToGrid")
        props.insert_element_before(snap, "w:spacing", "w:jc", "w:rPr", "w:sectPr")
    snap.set(qn("w:val"), "0")


def _hyperlink(paragraph, label, url):
    from docx.opc.constants import RELATIONSHIP_TYPE

    node = OxmlElement("w:hyperlink")
    node.set(qn("r:id"), paragraph.part.relate_to(url, RELATIONSHIP_TYPE.HYPERLINK, is_external=True))
    run = OxmlElement("w:r")
    props = OxmlElement("w:rPr")
    for tag, attrs in (
        ("rFonts", {"ascii": "Arial", "hAnsi": "Arial", "eastAsia": "Arial Unicode MS"}),
        ("color", {"val": "245F91"}),
        ("sz", {"val": "22"}),
        ("u", {"val": "single"}),
    ):
        child = OxmlElement("w:" + tag)
        for key, value in attrs.items():
            child.set(qn("w:" + key), value)
        props.append(child)
    run.append(props)
    text = OxmlElement("w:t")
    text.text = label
    run.append(text)
    node.append(run)
    paragraph._p.append(node)


def _append_text(paragraph, text, compact_urls=False):
    end = 0
    for match in URL_PATTERN.finditer(text):
        _font(paragraph.add_run(text[end:match.start()]))
        raw = match.group(0)
        url = raw.rstrip(".,;:)]}）")
        label = urlparse(url).netloc.removeprefix("www.") if compact_urls else url
        _hyperlink(paragraph, label, url)
        _font(paragraph.add_run(raw[len(url):]))
        end = match.end()
    _font(paragraph.add_run(text[end:]))


def _fill_cell(cell, text, prefix="", compact_urls=False):
    replace_text(cell, "")
    paragraph = cell.paragraphs[0]
    if prefix:
        _font(paragraph.add_run(prefix), bold=True)
        text = text[len(prefix):]
    lines = str(text).splitlines() or [""]
    for index, line in enumerate(lines):
        if index:
            # Keep a patch link beside its description instead of on a spare line.
            if URL_PATTERN.fullmatch(line.strip()):
                _font(paragraph.add_run("  "))
            else:
                paragraph = cell.add_paragraph()
        _append_text(paragraph, line, compact_urls=compact_urls)


def fill_table(table, card, lang):
    labels = LOCALES[lang]["labels"]
    full_width_fields = {0: "title", 4: "hazard", 5: "scope", 6: "ref", 7: "patch", 8: "link"}
    for row_index, row_data in enumerate(word_rows(card, lang)):
        cells = table.rows[row_index].cells
        if len(row_data) == 1:
            text = row_data[0]
            prefix = labels[full_width_fields[row_index]]
            if lang == "en" and row_index == 5 and cells[0].text.startswith(LOCALES["en"]["scope_alt_prefix"]):
                text = text.replace(prefix, LOCALES["en"]["scope_alt_prefix"], 1)
                prefix = LOCALES["en"]["scope_alt_prefix"]
            _fill_cell(cells[0], text, prefix, compact_urls=row_index in (6, 7))
        else:
            for cell, text in zip(cells, row_data):
                _fill_cell(cell, text)


def ensure_table_count(doc, count):
    if count and not doc.tables:
        raise ValueError("The DOCX template must contain a vulnerability table")
    while len(doc.tables) < count:
        doc.tables[-1]._element.addnext(deepcopy(doc.tables[-1]._element))
    for table in list(doc.tables[count:]):
        table._element.getparent().remove(table._element)


def add_page_break_after(table):
    paragraph = OxmlElement("w:p")
    props = OxmlElement("w:pPr")
    spacing = OxmlElement("w:spacing")
    for key in ("before", "after"):
        spacing.set(qn("w:" + key), "0")
    spacing.set(qn("w:line"), "20")
    spacing.set(qn("w:lineRule"), "exact")
    props.append(spacing)
    paragraph.append(props)
    run = OxmlElement("w:r")
    br = OxmlElement("w:br")
    br.set(qn("w:type"), "page")
    run.append(br)
    paragraph.append(run)
    table._element.addnext(paragraph)


def _shade(cell, fill):
    props = cell._tc.get_or_add_tcPr()
    node = props.find(qn("w:shd"))
    if node is None:
        node = OxmlElement("w:shd")
        props.insert_element_before(node, "w:vAlign", "w:hideMark", "w:tcPrChange")
    node.set(qn("w:fill"), fill)


def _polish_table(table):
    # Keep the template's grid, merges, field order and total width.
    table.autofit = False
    props = table._tbl.tblPr
    for tag in ("tblBorders", "tblCellMar"):
        node = props.find(qn("w:" + tag))
        if node is not None:
            props.remove(node)
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        node = OxmlElement("w:" + edge)
        for key, value in (("val", "single"), ("sz", "4"), ("color", "D9D9D9")):
            node.set(qn("w:" + key), value)
        borders.append(node)
    props.insert_element_before(borders, "w:shd", "w:tblLayout", "w:tblCellMar", "w:tblLook")
    margins = OxmlElement("w:tblCellMar")
    for edge, value in (("top", "80"), ("bottom", "80"), ("left", "120"), ("right", "120")):
        node = OxmlElement("w:" + edge)
        node.set(qn("w:w"), value)
        node.set(qn("w:type"), "dxa")
        margins.append(node)
    props.insert_element_before(margins, "w:tblLook", "w:tblCaption", "w:tblDescription", "w:tblPrChange")
    for index, row in enumerate(table.rows):
        row_props = row._tr.get_or_add_trPr()
        for tag in ("trHeight", "cantSplit", "tblHeader"):
            for node in list(row_props.findall(qn("w:" + tag))):
                row_props.remove(node)
        if index < 4:
            row_props.append(OxmlElement("w:cantSplit"))
        if index == 0:
            row_props.append(OxmlElement("w:tblHeader"))
        seen = set()
        for col, cell in enumerate(row.cells):
            if cell._tc in seen:
                continue
            seen.add(cell._tc)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            _shade(cell, "F2F4F6" if index == 0 or (0 < index < 4 and col % 2 == 0) else "FFFFFF")
            for paragraph in cell.paragraphs:
                _paragraph(paragraph, centered=0 < index < 4)
                for run in paragraph.runs:
                    _font(run, size=11.5 if index == 0 else 10.5 if index < 4 else 11,
                          bold=index == 0 or (index < 4 and col % 2 == 0) or bool(run.bold))


def _save_from_template(doc, template_path, output_path):
    """Keep all opaque template parts byte-for-byte, including its page furniture."""
    edited = BytesIO()
    doc.save(edited)
    with ZipFile(template_path) as original, ZipFile(edited) as generated, ZipFile(output_path, "w") as output:
        for info in original.infolist():
            if info.filename in ("word/document.xml", "word/_rels/document.xml.rels"):
                output.writestr(info, generated.read(info.filename))
            else:
                output.writestr(info, original.read(info.filename))


def build_docx(cards, cfg, lang, output_path):
    if Document is None:
        sys.exit("Missing Python package: docx. Run with the bundled Codex Python.")
    log.info("Building template-based DOCX (%s, %d table(s)) -> %s", lang, len(cards), output_path)
    template_path = cfg["docx_template"]
    doc = Document(template_path)
    title = next((p for p in doc.paragraphs if p.text.strip()), doc.paragraphs[0])
    replace_text(title, title_date(cards, lang, cfg=cfg))
    _paragraph(title, centered=True)
    title.paragraph_format.space_after = Pt(12)
    title.paragraph_format.keep_with_next = True
    for run in title.runs:
        _font(run, 16, bold=True)
    # Sample spacers contain inherited large type and can create empty pages.
    for paragraph in list(doc.paragraphs):
        if paragraph._p is not title._p and not paragraph.text.strip():
            paragraph._p.getparent().remove(paragraph._p)
    ensure_table_count(doc, len(cards))
    for index, (table, card) in enumerate(zip(doc.tables, cards)):
        fill_table(table, card, lang)
        _polish_table(table)
        if index < len(cards) - 1:
            add_page_break_after(table)
    _save_from_template(doc, template_path, output_path)
    log.info("DOCX saved: %s", output_path)
