import logging
import sys
from copy import deepcopy
from io import BytesIO
from zipfile import ZipFile

from docx.shared import Emu, Twips

from pipeline.constants import LOCALES
from pipeline.dependencies import Document, OxmlElement, qn
from pipeline.formatting import word_rows
from pipeline.output import title_date

log = logging.getLogger(__name__)


def replace_text(container, text):
    """Replace sample text without changing the template's paragraph or run styles."""
    paragraphs = getattr(container, "paragraphs", [container])
    first = paragraphs[0]
    if first.runs:
        first.runs[0].text = str(text)
        for run in first.runs[1:]:
            run.text = ""
    else:
        first.add_run(str(text))
    for paragraph in paragraphs[1:]:
        for run in paragraph.runs:
            run.text = ""


def fill_table(table, card, lang):
    for row_index, row_data in enumerate(word_rows(card, lang)):
        cells = table.rows[row_index].cells
        if len(row_data) == 1:
            text = row_data[0]
            if lang == "en" and row_index == 5 and cells[0].text.startswith(LOCALES["en"]["scope_alt_prefix"]):
                text = text.replace(LOCALES["en"]["labels"]["scope"], LOCALES["en"]["scope_alt_prefix"], 1)
            replace_text(cells[0], text)
        else:
            for cell, text in zip(cells, row_data):
                replace_text(cell, text)


def ensure_table_count(doc, count):
    if count and not doc.tables:
        raise ValueError("The DOCX template must contain a vulnerability table")
    while len(doc.tables) < count:
        doc.tables[-1]._element.addnext(deepcopy(doc.tables[-1]._element))
    for table in list(doc.tables[count:]):
        table._element.getparent().remove(table._element)


def _fit_table_to_page(table, section):
    """Use consistent fixed widths so Word cannot stretch long report text off-page."""
    available = Emu(section.page_width - section.left_margin - section.right_margin - section.gutter).twips
    grid = table._tbl.tblGrid.gridCol_lst
    original = [column.w.twips for column in grid]
    total = sum(original)
    if available <= 0 or total <= 0:
        raise ValueError("The DOCX template must have usable page and table widths")
    width = min(total, available)
    widths = [round(value * width / total) for value in original[:-1]]
    widths.append(width - sum(widths))
    table.autofit = False
    props = table._tbl.tblPr
    preferred = props.find(qn("w:tblW"))
    if preferred is None:
        preferred = OxmlElement("w:tblW")
        props.insert_element_before(preferred, "w:jc", "w:tblInd", "w:tblBorders", "w:tblLayout", "w:tblLook")
    preferred.set(qn("w:type"), "dxa")
    preferred.set(qn("w:w"), str(width))
    indent = props.find(qn("w:tblInd"))
    if indent is None:
        indent = OxmlElement("w:tblInd")
        props.insert_element_before(indent, "w:tblBorders", "w:shd", "w:tblLayout", "w:tblCellMar", "w:tblLook")
    indent.set(qn("w:type"), "dxa")
    indent.set(qn("w:w"), "0")
    for column, value in zip(grid, widths):
        column.w = Twips(value)
    for row in table.rows:
        before = row._tr.trPr.find(qn("w:gridBefore")) if row._tr.trPr is not None else None
        column = int(before.get(qn("w:val"))) if before is not None else 0
        for cell in row._tr.tc_lst:
            cell.width = Twips(sum(widths[column:column + cell.grid_span]))
            column += cell.grid_span


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
    ensure_table_count(doc, len(cards))
    for index, (table, card) in enumerate(zip(doc.tables, cards)):
        fill_table(table, card, lang)
        _fit_table_to_page(table, doc.sections[0])
        if index < len(cards) - 1:
            add_page_break_after(table)
    # Unused sample spacers after the last table can spill onto a blank page.
    tail = doc.tables[-1]._element.getnext() if doc.tables else None
    while tail is not None and tail.tag == qn("w:p"):
        if tail.xpath(".//w:t | .//w:br | .//w:drawing | .//w:pict | .//w:sectPr"):
            break
        following = tail.getnext()
        tail.getparent().remove(tail)
        tail = following
    _save_from_template(doc, template_path, output_path)
    log.info("DOCX saved: %s", output_path)
