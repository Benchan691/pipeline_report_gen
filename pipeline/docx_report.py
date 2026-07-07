import logging
import sys
from copy import deepcopy

from pipeline.dependencies import Document, OxmlElement, qn
from pipeline.formatting import word_rows
from pipeline.output import title_date

log = logging.getLogger(__name__)


def replace_text(container, text):
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
    from pipeline.constants import LOCALES

    for row_index, row_data in enumerate(word_rows(card, lang)):
        cells = table.rows[row_index].cells
        if len(row_data) == 1:
            if lang == "en" and row_index == 5 and cells[0].text.startswith(LOCALES["en"]["scope_alt_prefix"]):
                row_data = (row_data[0].replace(LOCALES["en"]["labels"]["scope"], LOCALES["en"]["scope_alt_prefix"], 1),)
            replace_text(cells[0], row_data[0])
        else:
            for cell, text in zip(cells, row_data):
                replace_text(cell, text)


def ensure_table_count(doc, count):
    while len(doc.tables) < count:
        doc.tables[-1]._element.addnext(deepcopy(doc.tables[-1]._element))
    for table in list(doc.tables[count:]):
        table._element.getparent().remove(table._element)


def add_page_break_after(table):
    paragraph = OxmlElement("w:p")
    run = OxmlElement("w:r")
    br = OxmlElement("w:br")
    br.set(qn("w:type"), "page")
    run.append(br)
    paragraph.append(run)
    table._element.addnext(paragraph)


def build_docx(cards, cfg, lang, output_path):
    if Document is None:
        sys.exit("Missing Python package: docx. Run with the bundled Codex Python.")
    log.info("Building DOCX (%s, %d table(s)) -> %s", lang, len(cards), output_path)
    doc = Document(cfg["docx_template"])
    title = next((p for p in doc.paragraphs if p.text.strip()), doc.paragraphs[0])
    replace_text(title, title_date(cards, lang))
    ensure_table_count(doc, len(cards))
    for index, (table, card) in enumerate(zip(doc.tables, cards)):
        fill_table(table, card, lang)
        if index < len(cards) - 1:
            add_page_break_after(table)
    doc.save(output_path)
    log.info("DOCX saved: %s", output_path)
