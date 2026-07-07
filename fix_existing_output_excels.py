#!/usr/bin/env python3
import sys
from copy import copy
from pathlib import Path

from pipeline.dependencies import load_workbook
from pipeline.excel_report import row_height


SEVERITY_MAP = {"Critical": "严重", "Critical-risk": "严重"}


def weekly_files(root):
    seen = set()
    for pattern in ("*本周重要漏洞实例情况*.xlsx", "*weekly_disclosure*.xlsx"):
        for path in Path(root).rglob(pattern):
            if path.name.startswith("~$") or path in seen:
                continue
            seen.add(path)
            yield path


def fix_file(path):
    wb = load_workbook(path)
    ws = wb.active
    changed = False
    for row_index in range(3, ws.max_row + 1):
        if ws.cell(row_index, 7).value in SEVERITY_MAP:
            ws.cell(row_index, 7).value = SEVERITY_MAP[ws.cell(row_index, 7).value]
            changed = True
        values = [ws.cell(row_index, col).value for col in range(1, ws.max_column + 1)]
        height = row_height(ws, values)
        if ws.row_dimensions[row_index].height != height:
            ws.row_dimensions[row_index].height = height
            changed = True
        for cell in ws[row_index]:
            alignment = copy(cell.alignment)
            if not alignment.wrap_text:
                alignment.wrap_text = True
                cell.alignment = alignment
                changed = True
    if changed:
        wb.save(path)
    return changed


def main():
    if load_workbook is None:
        sys.exit("Missing Python package: openpyxl. Run: python3 -m pip install -r requirements.txt")
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "output")
    if not root.is_dir():
        sys.exit(f"Output folder not found: {root}")
    changed = 0
    for path in weekly_files(root):
        if fix_file(path):
            changed += 1
            print(f"updated {path}")
        else:
            print(f"ok {path}")
    print(f"done, updated {changed} file(s)")


if __name__ == "__main__":
    main()
