import logging
import math
import sys
import unicodedata
from copy import copy

from pipeline.dependencies import get_column_letter, load_workbook
from pipeline.formatting import weekly_row

log = logging.getLogger(__name__)


def _text_lines(ws, col_index, value):
    dimension = ws.column_dimensions.get(get_column_letter(col_index))
    if dimension is None:
        dimension = next((item for item in ws.column_dimensions.values()
                          if (item.min or 0) <= col_index <= (item.max or 0)), None)
    width = dimension.width if dimension is not None else (ws.sheet_format.defaultColWidth or 12)
    lines = 0
    for part in str(value or "").splitlines() or [""]:
        characters = sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in part)
        lines += max(1, math.ceil(characters / max(width - 3, 8)))
    return lines


def row_height(ws, values):
    lines = max((_text_lines(ws, col, value) for col, value in enumerate(values, 1)), default=1)
    return min(409, lines * 18 + 3)


def copy_cell(src, dst, value=None):
    dst.value = value
    if isinstance(value, str):
        dst.data_type = "s"
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


def _fit_populated_row(ws, row_index, values):
    """Expand wrapped data only; short and empty rows keep their template heights."""
    height = ws.row_dimensions[row_index].height or ws.sheet_format.defaultRowHeight
    for col_index, value in enumerate(values[1:], start=2):
        if not value:
            continue
        lines = _text_lines(ws, col_index, value)
        if lines > 1:
            cell = ws.cell(row_index, col_index)
            alignment = copy(cell.alignment)
            alignment.wrap_text = True
            cell.alignment = alignment
            height = max(height, lines * (cell.font.sz or 11) * 1.25 + 3)
    ws.row_dimensions[row_index].height = min(409, height)


def rebuild_weekly_sheet(ws, cards):
    blocks = weekly_region_blocks(ws)
    if not blocks:
        return False
    original_merges = {str(merged) for merged in ws.merged_cells.ranges}
    block_styles = []
    for block_index, (start, end, label) in enumerate(blocks):
        next_start = blocks[block_index + 1][0] if block_index + 1 < len(blocks) else ws.max_row + 1
        block_styles.append({
            "label": label,
            "rows": [weekly_row_style(ws, row) for row in range(start, end + 1)],
            "dimensions": [copy(ws.row_dimensions[row]) for row in range(start, end + 1)],
            "separators": [(row, weekly_row_style(ws, row), copy(ws.row_dimensions[row]))
                           for row in range(end + 1, next_start)],
        })
    for merged in list(ws.merged_cells.ranges):
        if str(merged) != "A1:G1":
            ws.unmerge_cells(str(merged))
    if ws.max_row > 2:
        ws.delete_rows(3, ws.max_row - 2)
    for row in list(ws.row_dimensions):
        if row >= 3:
            del ws.row_dimensions[row]
    row_index = 3
    for block in block_styles:
        start = row_index
        data_cells, data_height = block["rows"][0]
        row_count = max(len(cards), len(block["rows"]))
        end = start + row_count - 1
        for offset in range(row_count):
            source_index = min(offset, len(block["rows"]) - 1)
            source_cells, _ = block["rows"][source_index]
            dimension = copy(block["dimensions"][source_index])
            dimension.index = row_index
            ws.row_dimensions[row_index] = dimension
            values = weekly_row(cards[offset]) if offset < len(cards) else [""] * 7
            values[0] = block["label"] if offset == 0 else None
            values[1] = ""
            for col_index, value in enumerate(values, start=1):
                cell = ws.cell(row_index, col_index)
                copy_cell(source_cells[col_index - 1], cell, value)
                if offset < len(cards) and col_index >= 2:
                    # Blank template rows have inconsistent typography; use the
                    # region's normal data formatting when those rows are filled.
                    cell.font = copy(data_cells[col_index - 1].font)
                    cell.alignment = copy(data_cells[col_index - 1].alignment)
            if offset < len(cards):
                if data_height is not None:
                    dimension.height = max(dimension.height or ws.sheet_format.defaultRowHeight, data_height)
                _fit_populated_row(ws, row_index, values)
            row_index += 1
        ws.merge_cells(start_row=start, start_column=1, end_row=end, end_column=1)
        for source_row, (source_cells, _), source_dimension in block["separators"]:
            dimension = copy(source_dimension)
            dimension.index = row_index
            ws.row_dimensions[row_index] = dimension
            for col_index, source in enumerate(source_cells, start=1):
                copy_cell(source, ws.cell(row_index, col_index), None)
            if f"A{source_row}:G{source_row}" in original_merges:
                ws.merge_cells(start_row=row_index, start_column=1, end_row=row_index, end_column=7)
            row_index += 1
    return True


def build_weekly_excel(cards, cfg):
    if load_workbook is None:
        sys.exit("Missing Python package: openpyxl. Run with the bundled Codex Python.")
    log.info("Building weekly Excel (%d row(s)) -> %s", len(cards), cfg["output_weekly_excel"])
    wb = load_workbook(cfg["weekly_excel_template"])
    ws = wb.active
    if not rebuild_weekly_sheet(ws, cards):
        sys.exit("Weekly Excel template must contain merged region blocks in column A.")
    ws["C2"] = "CVE编号"
    ws["D2"] = "厂商"
    ws["E2"] = "影响产品"
    wb.save(cfg["output_weekly_excel"])
    log.info("Weekly Excel saved: %s", cfg["output_weekly_excel"])
