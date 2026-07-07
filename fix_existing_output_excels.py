#!/usr/bin/env python3
import sys
from pathlib import Path

from pipeline.dependencies import load_workbook
from pipeline.excel_report import rebuild_weekly_sheet


def weekly_files(root):
    seen = set()
    for pattern in ("*本周重要漏洞实例情况*.xlsx", "*weekly_disclosure*.xlsx"):
        for path in Path(root).rglob(pattern):
            if path.name.startswith("~$") or path in seen:
                continue
            seen.add(path)
            yield path


def cards_from_weekly(path):
    ws = load_workbook(path).active
    cards = []
    seen = set()
    for row_index in range(3, ws.max_row + 1):
        cve = ws.cell(row_index, 3).value
        cnvd = ws.cell(row_index, 4).value
        product = ws.cell(row_index, 5).value
        title = ws.cell(row_index, 6).value
        severity = ws.cell(row_index, 7).value
        if not any((cve, cnvd, product, title, severity)):
            continue
        key = (cve, cnvd, product, title, severity)
        if key in seen:
            continue
        seen.add(key)
        cards.append({
            "cve_id": None if cve == "-" else cve,
            "cnvd_id": cnvd or "-",
            "affected_products": [product] if product else [],
            "title": title or "",
            "severity": severity or "",
            "doc": {"details": {"cnvd": {}}},
        })
    return cards


def fix_file(path):
    cards = cards_from_weekly(path)
    wb = load_workbook("templates/weekly_disclosure.xlsx")
    ws = wb.active
    if not rebuild_weekly_sheet(ws, cards):
        raise RuntimeError("templates/weekly_disclosure.xlsx has no weekly region blocks")
    wb.save(path)
    return True


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
