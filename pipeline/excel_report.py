import logging
import math
import sys
from copy import copy

from pipeline.dependencies import Alignment, get_column_letter, load_workbook
from pipeline.formatting import excel_row, weekly_row

log = logging.getLogger(__name__)


def row_height(ws, values):
    lines = 1
    for col_index, value in enumerate(values, start=1):
        width = ws.column_dimensions[get_column_letter(col_index)].width or 12
        for part in str(value or "").splitlines() or [""]:
            lines = max(lines, math.ceil(len(part) / max(width * 0.9, 8)))
    return min(180, max(30, lines * 18))


def build_excel(cards, cfg):
    if load_workbook is None:
        sys.exit("Missing Python package: openpyxl. Run with the bundled Codex Python.")
    log.info("Building Excel (%d row(s)) -> %s", len(cards), cfg["output_excel"])
    wb = load_workbook(cfg["excel_template"])
    ws = wb.active
    ws.delete_cols(8)
    styles = []
    for cell in ws[2]:
        styles.append({"font": copy(cell.font), "fill": copy(cell.fill), "border": copy(cell.border), "alignment": copy(cell.alignment), "number_format": cell.number_format, "protection": copy(cell.protection)})
    if ws.max_row > 1:
        ws.delete_rows(2, ws.max_row - 1)
    for row_index, card in enumerate(cards, start=2):
        values = excel_row(card)
        ws.row_dimensions[row_index].height = row_height(ws, values)
        for col_index, value in enumerate(values, start=1):
            cell = ws.cell(row_index, col_index, value)
            style = styles[col_index - 1]
            cell.font = copy(style["font"])
            cell.fill = copy(style["fill"])
            cell.border = copy(style["border"])
            cell.number_format = style["number_format"]
            cell.protection = copy(style["protection"])
            cell.alignment = Alignment(horizontal=style["alignment"].horizontal, vertical=style["alignment"].vertical, wrap_text=True)
    wb.save(cfg["output_excel"])
    log.info("Excel saved: %s", cfg["output_excel"])


def build_weekly_excel(cards, cfg):
    if load_workbook is None or Alignment is None:
        sys.exit("Missing Python package: openpyxl. Run with the bundled Codex Python.")
    log.info("Building weekly Excel (%d row(s)) -> %s", len(cards), cfg["output_weekly_excel"])
    wb = load_workbook(cfg["weekly_excel_template"])
    ws = wb.active
    for merged in list(ws.merged_cells.ranges):
        if str(merged) != "A1:G1":
            ws.unmerge_cells(str(merged))
    styles = []
    for cell in ws[3]:
        styles.append({"font": copy(cell.font), "fill": copy(cell.fill), "border": copy(cell.border), "alignment": copy(cell.alignment), "number_format": cell.number_format, "protection": copy(cell.protection)})
    if ws.max_row > 2:
        ws.delete_rows(3, ws.max_row - 2)
    for row_index, card in enumerate(cards, start=3):
        values = weekly_row(card)
        ws.row_dimensions[row_index].height = row_height(ws, values)
        for col_index, value in enumerate(values, start=1):
            cell = ws.cell(row_index, col_index, value)
            style = styles[col_index - 1]
            cell.font = copy(style["font"])
            cell.fill = copy(style["fill"])
            cell.border = copy(style["border"])
            cell.number_format = style["number_format"]
            cell.protection = copy(style["protection"])
            cell.alignment = Alignment(horizontal=style["alignment"].horizontal, vertical=style["alignment"].vertical, wrap_text=True)
    wb.save(cfg["output_weekly_excel"])
    log.info("Weekly Excel saved: %s", cfg["output_weekly_excel"])
