import tempfile
import unittest
from copy import copy, deepcopy
from pathlib import Path
from zipfile import ZipFile

from docx.shared import Emu, Inches

from pipeline.dependencies import Document, load_workbook, qn
from pipeline.docx_report import build_docx
from pipeline.excel_report import build_weekly_excel, weekly_region_blocks
from pipeline.output import title_date


ROOT = Path(__file__).resolve().parents[1]
WORD_TEMPLATE = ROOT / "templates/report.docx"
EXCEL_TEMPLATE = ROOT / "templates/weekly_disclosure.xlsx"


def report_card(index=0):
    return {
        "cnvd_id": f"GHSA-example-{index}",
        "source": "github_advisory",
        "cve_id": f"CVE-2026-{1000 + index}",
        "cve_ids": [f"CVE-2026-{1000 + index}"],
        "vendors": ["Example"],
        "affected_products": ["Example Server"],
        "report_identity": {"vendor": "Example", "product": "Example Server"},
        "cluster_label": "Example Server",
        "severity": "High",
        "doc": {"published_at": "2026-11-02"},
        "title": {"zh": f"示例服务器漏洞 {index + 1}", "en": f"Example Server issue {index + 1}"},
        "what_happened": {"zh": "攻击者可读取敏感信息。", "en": "An attacker can read sensitive information."},
        "why_matters": {"zh": "可能导致信息泄露。", "en": "Confidential information may be exposed."},
        "affected_versions": ["Example Server 1.0", "Example Server 1.1"],
        "references": [
            "https://example.test/security/advisory-2026-1000",
            "https://example.test/security/advisory-2026-1000/details",
        ],
        "how_to_respond": {
            "zh": "安装安全更新。\nhttps://example.test/updates/server-1.2",
            "en": "Install the security update.\nhttps://example.test/updates/server-1.2",
        },
    }


def xml_or_none(element):
    return element.xml if element is not None else None


class ReportAppearanceTests(unittest.TestCase):
    def build_word(self, directory, cards, lang):
        path = Path(directory) / f"report-{lang}.docx"
        build_docx(cards, {"docx_template": str(WORD_TEMPLATE)}, lang, str(path))
        return path, Document(path)

    def build_excel(self, directory, cards):
        path = Path(directory) / "weekly.xlsx"
        build_weekly_excel(cards, {
            "weekly_excel_template": str(EXCEL_TEMPLATE),
            "output_weekly_excel": str(path),
        })
        return path, load_workbook(path).active

    def assert_word_table_style(self, actual, expected):
        properties = []
        for table in (actual, expected):
            props = deepcopy(table._tbl.tblPr)
            for tag in ("tblW", "tblLayout", "tblInd"):
                for node in list(props.findall(qn("w:" + tag))):
                    props.remove(node)
            properties.append(props.xml)
        self.assertEqual(*properties)
        self.assertEqual(len(actual.columns), len(expected.columns))
        self.assertEqual(len(actual.rows), 9)
        for actual_row, expected_row in zip(actual.rows, expected.rows):
            self.assertEqual(xml_or_none(actual_row._tr.trPr), xml_or_none(expected_row._tr.trPr))
            for actual_cell, expected_cell in zip(actual_row._tr.tc_lst, expected_row._tr.tc_lst):
                properties = []
                for cell in (actual_cell, expected_cell):
                    props = deepcopy(cell.tcPr)
                    for node in list(props.findall(qn("w:tcW"))):
                        props.remove(node)
                    properties.append(props.xml)
                self.assertEqual(*properties)
                self.assertEqual(len(actual_cell.p_lst), len(expected_cell.p_lst))
                for actual_p, expected_p in zip(actual_cell.p_lst, expected_cell.p_lst):
                    self.assertEqual(xml_or_none(actual_p.pPr), xml_or_none(expected_p.pPr))
                    self.assertEqual(
                        [xml_or_none(run.rPr) for run in actual_p.r_lst],
                        [xml_or_none(run.rPr) for run in expected_p.r_lst],
                    )

    def test_word_preserves_template_formatting_in_both_languages_and_expands_tables(self):
        template = Document(WORD_TEMPLATE)
        for lang in ("zh", "en"):
            for count in (0, 1, 3):
                with self.subTest(lang=lang, count=count), tempfile.TemporaryDirectory() as directory:
                    cards = [report_card(index) for index in range(count)]
                    _, report = self.build_word(directory, cards, lang)
                    self.assertEqual(len(report.tables), count)
                    self.assertEqual(report.paragraphs[0].text, title_date(cards, lang))
                    self.assertEqual(report.paragraphs[0]._p.pPr.xml, template.paragraphs[0]._p.pPr.xml)
                    self.assertEqual(
                        report.paragraphs[0].runs[0]._r.rPr.xml,
                        template.paragraphs[0].runs[0]._r.rPr.xml,
                    )
                    self.assertEqual(report.sections[0]._sectPr.xml, template.sections[0]._sectPr.xml)
                    breaks = report.element.body.xpath("./w:p/w:r/w:br[@w:type='page']")
                    self.assertEqual(len(breaks), max(0, count - 1))
                    for index, table in enumerate(report.tables):
                        self.assert_word_table_style(table, template.tables[min(index, len(template.tables) - 1)])
                    if count:
                        self.assertEqual(report.tables[-1]._element.getnext().tag, report.sections[-1]._sectPr.tag)

    def test_word_fixed_table_widths_fit_the_page_including_merged_cells(self):
        for page_width in (None, Inches(6)):
            with self.subTest(page_width=page_width), tempfile.TemporaryDirectory() as directory:
                template = Document(WORD_TEMPLATE)
                if page_width is not None:
                    template.sections[0].page_width = page_width
                    template.sections[0].left_margin = Inches(1)
                    template.sections[0].right_margin = Inches(1)
                path = Path(directory) / "template.docx"
                template.save(path)
                for lang in ("zh", "en"):
                    card = report_card()
                    card["title"][lang] = "A long title that must wrap within the page " * 6
                    output = Path(directory) / f"fixed-{lang}.docx"
                    build_docx([card] * 3, {"docx_template": str(path)}, lang, str(output))
                    report = Document(output)
                    section = report.sections[0]
                    available = Emu(section.page_width - section.left_margin - section.right_margin - section.gutter).twips
                    original = [column.width.twips for column in template.tables[0].columns]
                    for table in report.tables:
                        widths = [column.width.twips for column in table.columns]
                        self.assertEqual(sum(widths), available)
                        self.assertFalse(table.autofit)
                        self.assertEqual(table._tbl.tblPr.find(qn("w:tblW")).get(qn("w:w")), str(available))
                        self.assertEqual(table._tbl.tblPr.find(qn("w:tblInd")).get(qn("w:w")), "0")
                        for actual, source in zip(widths, original):
                            self.assertAlmostEqual(actual, source * available / sum(original), delta=1)
                        for row in table.rows:
                            column = 0
                            for cell in row._tr.tc_lst:
                                self.assertEqual(cell.width.twips, sum(widths[column:column + cell.grid_span]))
                                column += cell.grid_span

    def test_word_retains_full_urls_current_fields_versions_and_opaque_parts(self):
        card = report_card()
        card["cve_ids"].append("CVE-2026-2000")
        with tempfile.TemporaryDirectory() as directory:
            for lang in ("zh", "en"):
                path, report = self.build_word(directory, [card], lang)
                table = report.tables[0]
                self.assertIn("CVE-2026-2000", table.rows[1].cells[1].text)
                self.assertEqual(table.rows[1].cells[3].text, "Example")
                self.assertEqual(table.rows[2].cells[3].text, "Example Server")
                for version in card["affected_versions"]:
                    self.assertIn(version, table.rows[5].cells[0].text)
                for url in card["references"]:
                    self.assertIn(url, table.rows[6].cells[0].text)
                self.assertIn(card["how_to_respond"][lang], table.rows[7].cells[0].text)
                self.assertNotIn("CNVD-2026-24916", report.element.xml)
                with ZipFile(WORD_TEMPLATE) as source, ZipFile(path) as output:
                    self.assertEqual(source.namelist(), output.namelist())
                    for name in source.namelist():
                        if name not in ("word/document.xml", "word/_rels/document.xml.rels"):
                            self.assertEqual(output.read(name), source.read(name), name)

    def assert_excel_settings(self, actual, template):
        self.assertEqual(
            {key: dict(value) for key, value in actual.column_dimensions.items()},
            {key: dict(value) for key, value in template.column_dimensions.items()},
        )
        self.assertEqual(actual.sheet_view, template.sheet_view)
        # openpyxl recomputes the cached column outline level when saving.
        self.assertEqual(
            {key: value for key, value in dict(actual.sheet_format).items() if key != "outlineLevelCol"},
            {key: value for key, value in dict(template.sheet_format).items() if key != "outlineLevelCol"},
        )
        self.assertEqual(actual.page_setup, template.page_setup)
        self.assertEqual(actual.page_margins, template.page_margins)
        self.assertEqual(actual.print_options, template.print_options)
        self.assertEqual(actual.print_area, template.print_area)
        self.assertEqual(actual.print_title_rows, template.print_title_rows)
        self.assertEqual(actual.sheet_properties, template.sheet_properties)
        self.assertIsNone(actual.freeze_panes)
        self.assertIsNone(actual.auto_filter.ref)
        self.assertEqual(len(actual.data_validations.dataValidation), 0)

    def test_empty_excel_preserves_all_template_styles_heights_and_merges(self):
        template = load_workbook(EXCEL_TEMPLATE).active
        with tempfile.TemporaryDirectory() as directory:
            _, sheet = self.build_excel(directory, [])
            self.assert_excel_settings(sheet, template)
            self.assertEqual(set(map(str, sheet.merged_cells.ranges)), set(map(str, template.merged_cells.ranges)))
            self.assertEqual(sheet.max_row, template.max_row)
            for row in range(1, sheet.max_row + 1):
                self.assertEqual(sheet.row_dimensions[row].height, template.row_dimensions[row].height)
                for cell in sheet[row]:
                    self.assertEqual(cell._style, template.cell(row, cell.column)._style, cell.coordinate)
                    if row >= 3 and cell.column >= 2:
                        self.assertIsNone(cell.value, cell.coordinate)
            self.assertEqual(sheet["D2"].value, "厂商")

    def test_excel_short_rows_keep_original_styles_and_heights(self):
        template = load_workbook(EXCEL_TEMPLATE).active
        with tempfile.TemporaryDirectory() as directory:
            _, sheet = self.build_excel(directory, [report_card()])
            self.assert_excel_settings(sheet, template)
            for row in range(1, sheet.max_row + 1):
                self.assertEqual(sheet.row_dimensions[row].height, template.row_dimensions[row].height)
                for cell in sheet[row]:
                    self.assertEqual(cell._style, template.cell(row, cell.column)._style, cell.coordinate)
            for start, _, _ in weekly_region_blocks(sheet):
                self.assertEqual(sheet.cell(start, 3).value, "CVE-2026-1000")
                self.assertEqual(sheet.cell(start, 4).value, "Example")
                self.assertEqual(sheet.cell(start, 5).value, "Example Server")
                self.assertIsNone(sheet.cell(start, 2).value)

    def test_excel_expands_each_region_and_preserves_each_separator(self):
        template = load_workbook(EXCEL_TEMPLATE).active
        original_blocks = weekly_region_blocks(template)
        for count in (3, 13):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                cards = [report_card(index) for index in range(count)]
                _, sheet = self.build_excel(directory, cards)
                self.assert_excel_settings(sheet, template)
                blocks = weekly_region_blocks(sheet)
                self.assertEqual([block[2] for block in blocks], [block[2] for block in original_blocks])
                for (start, end, _), (source_start, source_end, _) in zip(blocks, original_blocks):
                    self.assertEqual(end - start + 1, max(count, source_end - source_start + 1))
                    for offset, card in enumerate(cards):
                        self.assertEqual(sheet.cell(start + offset, 3).value, card["cve_id"])
                        self.assertIsNone(sheet.cell(start + offset, 2).value)
                        self.assertEqual(copy(sheet.cell(start + offset, 6).font), copy(template.cell(source_start, 6).font))
                    if source_end < template.max_row:
                        self.assertEqual(sheet.row_dimensions[end + 1].height, template.row_dimensions[source_end + 1].height)
                        for col in range(1, 8):
                            self.assertEqual(sheet.cell(end + 1, col)._style, template.cell(source_end + 1, col)._style)
                        self.assertEqual(
                            f"A{end + 1}:G{end + 1}" in set(map(str, sheet.merged_cells.ranges)),
                            f"A{source_end + 1}:G{source_end + 1}" in set(map(str, template.merged_cells.ranges)),
                        )

    def test_excel_populated_rows_have_consistent_fonts_sizes_and_alignment(self):
        template = load_workbook(EXCEL_TEMPLATE).active
        original_blocks = weekly_region_blocks(template)
        # These differently formatted placeholders caused the visible jump in
        # text size and alignment once a report reached its eighth record.
        self.assertEqual(template["C3"].font.sz, 12)
        self.assertEqual(template["C10"].font.sz, 14)
        self.assertEqual(template["C10"].alignment.horizontal, "left")
        for count in (9, 23):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                cards = [report_card(index) for index in range(count)]
                _, sheet = self.build_excel(directory, cards)
                self.assert_excel_settings(sheet, template)
                for (start, _, _), (source_start, source_end, _) in zip(weekly_region_blocks(sheet), original_blocks):
                    for offset, card in enumerate(cards):
                        row = start + offset
                        self.assertEqual(sheet.cell(row, 3).value, card["cve_id"])
                        self.assertGreaterEqual(sheet.row_dimensions[row].height, template.row_dimensions[source_start].height)
                        for col in range(2, 8):
                            actual = sheet.cell(row, col)
                            expected = template.cell(source_start, col)
                            self.assertEqual(copy(actual.font), copy(expected.font), actual.coordinate)
                            self.assertEqual(copy(actual.alignment), copy(expected.alignment), actual.coordinate)
                    for offset in range(count, source_end - source_start + 1):
                        row, source_row = start + offset, source_start + offset
                        self.assertEqual(sheet.row_dimensions[row].height, template.row_dimensions[source_row].height)
                        for col in range(2, 8):
                            self.assertEqual(sheet.cell(row, col)._style, template.cell(source_row, col)._style)

    def test_excel_wraps_long_text_and_multiple_cves_without_changing_fonts_or_values(self):
        template = load_workbook(EXCEL_TEMPLATE).active
        cards = [report_card(index) for index in range(3)]
        cards[0]["cve_ids"].append("CVE-2026-2000")
        cards[1]["title"]["zh"] = "示例服务器安全漏洞需要安装安全更新以防止敏感信息泄露。" * 6
        cards[2]["title"]["zh"] = "=SUM(1,2)"
        with tempfile.TemporaryDirectory() as directory:
            _, sheet = self.build_excel(directory, cards)
            for start, _, _ in weekly_region_blocks(sheet):
                self.assertEqual(sheet.cell(start, 3).value, "CVE-2026-1000\nCVE-2026-2000")
                self.assertTrue(sheet.cell(start, 3).alignment.wrap_text)
                self.assertTrue(sheet.cell(start + 1, 6).alignment.wrap_text)
                for row in (start, start + 1):
                    self.assertGreater(sheet.row_dimensions[row].height, template.row_dimensions[row].height)
                    self.assertEqual(copy(sheet.cell(row, 6).font), copy(template.cell(row, 6).font))
                self.assertEqual(sheet.cell(start + 1, 6).value, cards[1]["title"]["zh"])
                self.assertEqual(sheet.cell(start + 2, 6).value, "=SUM(1,2)")
                self.assertEqual(sheet.cell(start + 2, 6).data_type, "s")
                self.assertEqual(sheet.row_dimensions[start + 3].height, template.row_dimensions[start + 3].height)


if __name__ == "__main__":
    unittest.main()
