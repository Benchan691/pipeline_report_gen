import logging
import re
import sys
from copy import deepcopy
from collections import Counter
from urllib.parse import urlparse

from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor

from pipeline.dependencies import Document, OxmlElement, qn
from pipeline.formatting import asset_text, card_date, cve_text, display_date, format_severity, localized, product_text, vendor_text, word_rows
from pipeline.output import report_date_prefix
from pipeline.utils import unique

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


def _font(run, size=11, bold=False, color="000000"):
    run.font.name = "Arial"
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = RGBColor.from_string(color)
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), "Arial Unicode MS")


def _shade(cell, color):
    node = OxmlElement("w:shd")
    node.set(qn("w:fill"), color)
    cell._tc.get_or_add_tcPr().append(node)


def _table(doc, rows, widths, header=False):
    table = doc.add_table(rows=0, cols=len(widths))
    table.autofit = False
    for col, width in zip(table.columns, widths):
        col.width = Inches(width)
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        node = OxmlElement("w:" + edge)
        for k, v in (("val", "single"), ("sz", "4"), ("color", "D9D9D9")):
            node.set(qn("w:" + k), v)
        borders.append(node)
    table._tbl.tblPr.append(borders)
    margins = OxmlElement("w:tblCellMar")
    for edge, value in (("top", "70"), ("bottom", "70"), ("left", "85"), ("right", "85")):
        node = OxmlElement("w:" + edge)
        node.set(qn("w:w"), value)
        node.set(qn("w:type"), "dxa")
        margins.append(node)
    table._tbl.tblPr.append(margins)
    for index, values in enumerate(rows):
        row = table.add_row()
        row._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
        for cell, value, width in zip(row.cells, values, widths):
            cell.width = Inches(width)
            cell.text = str(value)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.line_spacing = 1.1
            fill = "17324D" if header and index == 0 else "F3F6FA" if index % 2 else "FFFFFF"
            _shade(cell, fill)
            for run in p.runs:
                _font(run, 10, header and index == 0, "FFFFFF" if header and index == 0 else "000000")
    if header:
        table.rows[0]._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))
    return table


def _hyperlink(paragraph, label, url=None, anchor=None, size=9.5):
    from docx.opc.constants import RELATIONSHIP_TYPE
    node = OxmlElement("w:hyperlink")
    if anchor:
        node.set(qn("w:anchor"), anchor)
    else:
        node.set(qn("r:id"), paragraph.part.relate_to(url, RELATIONSHIP_TYPE.HYPERLINK, is_external=True))
    run = OxmlElement("w:r")
    props = OxmlElement("w:rPr")
    for tag, attrs in (("rFonts", {"ascii": "Arial", "hAnsi": "Arial", "eastAsia": "Arial Unicode MS"}), ("color", {"val": "245F91"}), ("sz", {"val": str(int(size * 2))}), ("u", {"val": "single"})):
        element = OxmlElement("w:" + tag)
        for k, v in attrs.items():
            element.set(qn("w:" + k), v)
        props.append(element)
    run.append(props)
    text = OxmlElement("w:t")
    text.text = label
    run.append(text)
    node.append(run)
    paragraph._p.append(node)


def _body(doc, heading, value, zh):
    doc.add_heading(heading, level=2)
    value = str(value or "").strip()
    if not value or value == "-":
        value = "现有来源未提供相关信息。" if zh else "Not provided in the available sources."
    previous = None
    for line in value.splitlines():
        if line.strip():
            line = line.strip()
            if previous is not None and re.fullmatch(r"https?://[^\s<>，；。]+", line):
                p = previous
                p.add_run("  ")
            else:
                p = doc.add_paragraph()
                p.paragraph_format.widow_control = True
            end = 0
            for match in re.finditer(r"https?://[^\s<>，；。]+", line):
                p.add_run(line[end:match.start()])
                raw = match.group(0)
                url = raw.rstrip(".,;:)]}）")
                parsed = urlparse(url)
                _hyperlink(p, parsed.netloc.removeprefix("www."), url=url, size=11)
                p.add_run(raw[len(url):])
                end = match.end()
            p.add_run(line[end:])
            previous = p


def build_docx(cards, cfg, lang, output_path):
    if Document is None:
        sys.exit("Missing Python package: docx. Run with the bundled Codex Python.")
    log.info("Building DOCX (%s, %d vulnerability record(s)) -> %s", lang, len(cards), output_path)
    doc = Document()
    zh = lang == "zh"
    for fonts in doc.styles.element.xpath(".//w:rFonts"):
        for key in list(fonts.attrib):
            if "theme" in key.lower():
                del fonts.attrib[key]
        fonts.set(qn("w:ascii"), "Arial")
        fonts.set(qn("w:hAnsi"), "Arial")
        fonts.set(qn("w:eastAsia"), "Arial Unicode MS")
    for borders in doc.styles.element.xpath(".//w:pBdr"):
        borders.getparent().remove(borders)
    section = doc.sections[0]
    section.page_width, section.page_height = Inches(8.5), Inches(11)
    section.left_margin = section.right_margin = Inches(0.8)
    section.top_margin = section.bottom_margin = Inches(0.65)
    section.header_distance = section.footer_distance = Inches(0.3)
    for name, size in (("Normal", 11), ("Title", 24), ("Subtitle", 11), ("Heading 1", 18), ("Heading 2", 12)):
        style = doc.styles[name]
        style.font.name, style.font.size = "Arial", Pt(size)
        style.font.color.rgb = RGBColor(0, 0, 0)
        style._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), "Arial Unicode MS")
        style.paragraph_format.line_spacing = 1.15
        style.paragraph_format.space_after = Pt(6)
        if name.startswith("Heading"):
            style.font.bold = True
            style.paragraph_format.keep_with_next = True
            style.paragraph_format.space_before = Pt(10)
    _font(section.header.paragraphs[0].add_run("漏洞情报周报" if zh else "Weekly vulnerability intelligence"), 9)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _font(footer.add_run("第 " if zh else "Page "), 9)
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)
    _font(footer.add_run(" 页" if zh else ""), 9)
    title = "每周漏洞情报报告" if zh else "Weekly vulnerability report"
    doc.core_properties.title = title
    doc.add_paragraph(title, style="Title")
    period = cfg.get("report_date_label") or report_date_prefix(cards, cfg=cfg)
    doc.add_paragraph(("报告周期  " if zh else "Reporting period  ") + period, style="Subtitle")
    doc.add_paragraph("本报告汇总本期筛选中与软件清单相关的漏洞记录。请结合产品、受影响版本和处置建议确认实际影响。发布日期按原始公告保留。" if zh else "This report summarizes vulnerability records selected for the software inventory in this reporting period. Use the product, affected versions and response guidance to assess exposure. Publication dates retain the original advisory dates.")
    doc.add_heading("漏洞总览" if zh else "Vulnerability overview", level=1)
    counts = Counter(c.get("severity") for c in cards)
    doc.add_paragraph(f"共 {len(cards)} 条记录  严重 {counts['Critical']} 条  高危 {counts['High']} 条  中危 {counts['Medium']} 条" if zh else f"{len(cards)} records   Critical {counts['Critical']}   High {counts['High']}   Medium {counts['Medium']}")
    headers = ("序号", "影响产品", "CVE编号", "级别", "发布日期") if zh else ("No", "Product", "CVE", "Severity", "Published")
    rows = [headers] + [(str(i), product_text(c), cve_text(c), format_severity(c.get("severity"), lang), display_date(card_date(c)) or "-") for i, c in enumerate(cards, 1)]
    overview = _table(doc, rows, (0.45, 2.55, 1.8, 0.85, 1.25), header=True)
    for i, row in enumerate(overview.rows[1:], 1):
        row.cells[0].text = ""
        _hyperlink(row.cells[0].paragraphs[0], str(i), anchor=f"vuln_{i}")
    doc.add_paragraph("点击序号查看漏洞详情。" if zh else "Select a record number to jump to its details.")
    for i, card in enumerate(cards, 1):
        heading = doc.add_heading(f"{i:02d} {product_text(card)}", level=1)
        heading.paragraph_format.page_break_before = True
        start, end = OxmlElement("w:bookmarkStart"), OxmlElement("w:bookmarkEnd")
        start.set(qn("w:id"), str(i))
        start.set(qn("w:name"), f"vuln_{i}")
        end.set(qn("w:id"), str(i))
        heading._p.insert(1 if heading._p.pPr is not None else 0, start)
        heading._p.append(end)
        p = doc.add_paragraph(localized(card, "title", lang) or "-")
        for run in p.runs:
            _font(run, 11, True)
        metadata = [
            ("CVE编号" if zh else "CVE", cve_text(card), "威胁级别" if zh else "Severity", format_severity(card.get("severity"), lang)),
            ("厂商" if zh else "Vendor", vendor_text(card), "发布日期" if zh else "Published", display_date(card_date(card)) or "-"),
            ("影响产品" if zh else "Product", product_text(card), "关联软件" if zh else "Inventory", asset_text(card)),
        ]
        table = _table(doc, metadata, (0.8, 2.65, 0.8, 2.65))
        for row in table.rows:
            for col in (0, 2):
                _shade(row.cells[col], "EEF2F6")
                for run in row.cells[col].paragraphs[0].runs:
                    _font(run, 10, True)
        _body(doc, "漏洞概述" if zh else "What happened", localized(card, "what_happened", lang), zh)
        _body(doc, "影响与风险" if zh else "Impact", localized(card, "why_matters", lang), zh)
        versions = unique(card.get("affected_versions") or [])
        if versions:
            product = product_text(card)
            display_versions = [str(v)[len(product):].strip() if str(v).casefold().startswith(product.casefold() + " ") else str(v) for v in versions]
            _body(doc, "受影响版本" if zh else "Affected versions", "; ".join(display_versions), zh)
        elif card.get("affected_products"):
            _body(doc, "影响范围" if zh else "Affected scope", "; ".join(card["affected_products"]), zh)
        _body(doc, "处置建议" if zh else "Recommended response", localized(card, "how_to_respond", lang), zh)
        doc.add_heading("参考来源" if zh else "Sources", level=2)
        refs = unique(card.get("references") or [])
        for cve in card.get("cve_ids") or ([card["cve_id"]] if card.get("cve_id") else []):
            link = "https://nvd.nist.gov/vuln/detail/" + cve
            if link not in refs:
                refs.append(link)
        for offset in range(0, len(refs), 3):
            p = doc.add_paragraph()
            p.paragraph_format.space_after = Pt(3)
            for j, url in enumerate(refs[offset:offset + 3]):
                parsed = urlparse(str(url))
                if j:
                    _font(p.add_run("   "), 9.5)
                host = parsed.netloc.removeprefix("www.")
                label = "NVD" if host == "nvd.nist.gov" else "CVE record" if host == "raw.githubusercontent.com" else host
                if parsed.scheme in ("http", "https") and host:
                    _hyperlink(p, f"{offset + j + 1} {label}", url=str(url))
                else:
                    _font(p.add_run(str(url)), 9.5)
        if not refs:
            doc.add_paragraph("未提供参考来源。" if zh else "No sources provided.")
    doc.save(output_path)
    log.info("DOCX saved: %s", output_path)
