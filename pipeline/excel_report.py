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


def copy_cell(src, dst, value=None):
    dst.value = value
    dst.font = copy(src.font)
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
                    horizontal=ws.cell(row_index, col_index).alignment.horizontal,
                    vertical=ws.cell(row_index, col_index).alignment.vertical,
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
    if not rebuild_weekly_sheet(ws, cards):
        sys.exit("Weekly Excel template must contain merged region blocks in column A.")
    wb.save(cfg["output_weekly_excel"])
    log.info("Weekly Excel saved: %s", cfg["output_weekly_excel"])
