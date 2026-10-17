import logging
import math
import sys
import unicodedata
from copy import copy

from openpyxl.styles import Border, Font, PatternFill, Side
from openpyxl.worksheet.datavalidation import DataValidation

from pipeline.dependencies import Alignment, get_column_letter, load_workbook
from pipeline.formatting import weekly_row

log = logging.getLogger(__name__)


def row_height(ws, values):
    lines = 1
    for col_index, value in enumerate(values, start=1):
        width = ws.column_dimensions[get_column_letter(col_index)].width or 12
        cell_lines = 0
        for part in str(value or "").splitlines() or [""]:
            characters = sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in part)
            cell_lines += max(1, math.ceil(characters / max(width - 3, 8)))
        lines = max(lines, cell_lines)
    return min(409, max(38, lines * 18 + 10))


def copy_cell(src, dst, value=None):
    dst.value = value
    if isinstance(value, str):
        dst.data_type = "s"
    font = copy(src.font)
    font.sz = 12
    dst.font = font
    dst.fill = copy(src.fill)
    dst.border = copy(src.border)
    dst.number_format = src.number_format
    dst.protection = copy(src.protection)
    dst.alignment = copy(src.alignment)


def weekly_region_blocks(ws):
    blocks = []
    for merged in ws.merged_cells.ranges:
        if merged.min_col == merged.max_col == 1 and merged.min_row >= 3:
            blocks.append((merged.min_row, merged.max_row, ws.cell(merged.min_row, 1).value))
    return sorted(blocks)


def weekly_row_style(ws, row_index):
    return [copy(ws.cell(row_index, col)) for col in range(1, 8)], ws.row_dimensions[row_index].height


def rebuild_weekly_sheet(ws, cards):
    blocks = weekly_region_blocks(ws)
    if not blocks:
        return False
    block_styles = []
    for start, end, label in blocks:
        rows = [weekly_row_style(ws, row) for row in range(start, end + 1)]
        block_styles.append({"label": label, "rows": rows})
    sep_row = blocks[0][1] + 1
    sep_style = weekly_row_style(ws, sep_row) if sep_row <= ws.max_row else None
    for merged in list(ws.merged_cells.ranges):
        if str(merged) != "A1:G1":
            ws.unmerge_cells(str(merged))
    if ws.max_row > 2:
        ws.delete_rows(3, ws.max_row - 2)
    row_index = 3
    row_count = max(len(cards), max(len(block["rows"]) for block in block_styles))
    for block_index, block in enumerate(block_styles):
        start = row_index
        end = start + row_count - 1
        for offset in range(row_count):
            source_cells, source_height = block["rows"][min(offset, len(block["rows"]) - 1)]
            values = weekly_row(cards[offset]) if offset < len(cards) else [""] * 7
            values[0] = block["label"] if offset == 0 else None
            values[1] = ""
            for col_index, value in enumerate(values, start=1):
                copy_cell(source_cells[col_index - 1], ws.cell(row_index, col_index), value)
                ws.cell(row_index, col_index).alignment = Alignment(
                    horizontal="center",
                    vertical="center",
                    wrap_text=True,
                )
            ws.row_dimensions[row_index].height = row_height(ws, values) if offset < len(cards) else source_height
            row_index += 1
        ws.merge_cells(start_row=start, start_column=1, end_row=end, end_column=1)
        if block_index < len(block_styles) - 1:
            if sep_style:
                source_cells, source_height = sep_style
                for col_index, source in enumerate(source_cells, start=1):
                    copy_cell(source, ws.cell(row_index, col_index), None)
                ws.row_dimensions[row_index].height = source_height
            ws.merge_cells(start_row=row_index, start_column=1, end_row=row_index, end_column=7)
            row_index += 1
    return True


def build_weekly_excel(cards, cfg):
    if load_workbook is None or Alignment is None:
        sys.exit("Missing Python package: openpyxl. Run with the bundled Codex Python.")
    log.info("Building weekly Excel (%d row(s)) -> %s", len(cards), cfg["output_weekly_excel"])
    wb = load_workbook(cfg["weekly_excel_template"])
    ws = wb.active
    if not rebuild_weekly_sheet(ws, cards):
        sys.exit("Weekly Excel template must contain merged region blocks in column A.")
    ws["C2"] = "CVE编号"
    ws["D2"] = "厂商"
    ws["E2"] = "影响产品"
    style_weekly_sheet(ws, cards)
    wb.save(cfg["output_weekly_excel"])
    log.info("Weekly Excel saved: %s", cfg["output_weekly_excel"])


def style_weekly_sheet(ws, cards):
    """Keep regional review blocks while making the generated workbook readable."""
    navy, grid = "17324D", "D9E1EA"
    for column, width in zip("ABCDEFG", (18, 11, 24, 18, 27, 58, 12)):
        ws.column_dimensions[column].width = width
    ws.sheet_view.showGridLines = False
    ws.sheet_view.zoomScale = 90
    ws.freeze_panes = "C3"
    ws.auto_filter.ref = f"A2:G{ws.max_row}"
    ws.row_dimensions[1].height = 36
    ws.row_dimensions[2].height = 29
    ws["A1"].font = Font(name="Arial", size=16, bold=True, color="000000")
    ws["A1"].fill = PatternFill(fill_type="solid", fgColor="FFFFFF")
    ws["A1"].alignment = Alignment(horizontal="left", vertical="center")
    border = Border(left=Side(style="thin", color=grid), right=Side(style="thin", color=grid), top=Side(style="thin", color=grid), bottom=Side(style="thin", color=grid))
    for cell in ws[2]:
        cell.font = Font(name="Arial", size=11, bold=True, color="FFFFFF")
        cell.fill = PatternFill(fill_type="solid", fgColor=navy)
        cell.border = border
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    validation = DataValidation(type="list", formula1='"是,否,待确认"', allow_blank=True)
    validation.errorTitle, validation.error = "请选择是否涉及", "选择是、否或待确认，也可保留空白。"
    validation.showErrorMessage = True
    ws.add_data_validation(validation)
    colors = {"严重": ("FCE8E6", "9D211B"), "高危": ("FFF0DD", "9B4D00"), "中危": ("FFF8D6", "6E5C00"), "低危": ("EAF3EE", "32604B")}
    for start, end, _ in weekly_region_blocks(ws):
        validation.add(f"B{start}:B{end}")
        for row_index in range(start, end + 1):
            for cell in ws[row_index][:7]:
                cell.font = Font(name="Arial", size=11, color="1F2937")
                cell.fill = PatternFill(fill_type="solid", fgColor="F3F6FA" if (row_index - start) % 2 else "FFFFFF")
                cell.border = border
                cell.alignment = Alignment(horizontal="center" if cell.column in (2, 3, 7) else "left", vertical="center", wrap_text=True)
            ws.cell(row_index, 2).fill = PatternFill(fill_type="solid", fgColor="FFF9E8")
            level = ws.cell(row_index, 7)
            if level.value in colors:
                background, foreground = colors[level.value]
                level.fill = PatternFill(fill_type="solid", fgColor=background)
                level.font = Font(name="Arial", size=11, bold=True, color=foreground)
            values = [None] + [ws.cell(row_index, col).value for col in range(2, 8)]
            ws.row_dimensions[row_index].height = row_height(ws, values)
        region = ws.cell(start, 1)
        region.fill = PatternFill(fill_type="solid", fgColor="E7EEF5")
        region.font = Font(name="Arial", size=11, bold=True, color=navy)
        region.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    for merged in ws.merged_cells.ranges:
        if merged.min_row == merged.max_row and merged.min_row > 2:
            ws.row_dimensions[merged.min_row].height = 14
    ws.print_title_rows = "1:2"
    ws.print_area = f"A1:G{ws.max_row}"
    ws.page_setup.orientation = "landscape"
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
