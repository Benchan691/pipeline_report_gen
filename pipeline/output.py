import os
from datetime import datetime

from pipeline.constants import LOCALES
from pipeline.formatting import card_date


def card_publish_dates(cards):
    dates = []
    for card in cards:
        value = card_date(card)
        if value:
            dates.append(str(value)[:10])
    return sorted(dates)


def report_date_prefix(cards):
    dates = card_publish_dates(cards)
    if not dates:
        return datetime.now().strftime("%Y.%m.%d")
    start, end = dates[0], dates[-1]
    start_fmt = f"{start[:4]}.{start[5:7]}.{start[8:10]}"
    if start == end:
        return start_fmt
    return f"{start_fmt}-{end[5:7]}.{end[8:10]}"


def apply_dated_output_path(prefix, filename):
    stem, ext = os.path.splitext(filename)
    return f"{prefix}_{stem}{ext}"


def create_run_output_dir(root, now=None):
    now = now or datetime.now()
    path = os.path.join(root or "output", now.strftime("%Y%m%d_%H%M%S"))
    os.makedirs(path, exist_ok=True)
    return path


def apply_dated_output_paths(cfg, cards):
    if not cfg.get("output_date_prefix", True):
        return
    prefix = report_date_prefix(cards)
    for key in ("output_docx", "output_excel", "output_weekly_excel"):
        if cfg.get(key):
            cfg[key] = apply_dated_output_path(prefix, cfg[key])


def apply_run_output_paths(cfg, cards, now=None):
    output_dir = create_run_output_dir(cfg.get("output_root", "output"), now)
    apply_dated_output_paths(cfg, cards)
    for key in ("output_docx", "output_excel", "output_weekly_excel"):
        if cfg.get(key):
            cfg[key] = os.path.join(output_dir, os.path.basename(cfg[key]))
    cfg["output_dir"] = output_dir
    return output_dir


def title_date(cards, lang):
    locale = LOCALES[lang]
    dates = card_publish_dates(cards)
    if not dates:
        return datetime.now().strftime(locale["title_fallback"])
    start, end = dates[0], dates[-1]
    return locale["title_range"].format(y1=start[:4], m1=start[5:7], d1=start[8:10], m2=end[5:7], d2=end[8:10])


def resolve_output_folder(cfg, folder_path):
    folder_path = str(folder_path or "").strip()
    if not folder_path:
        raise ValueError("Output folder path is required")
    if os.path.isabs(folder_path):
        path = os.path.normpath(folder_path)
    else:
        root = os.path.normpath(cfg.get("output_root", "output"))
        norm_folder = os.path.normpath(folder_path)
        if norm_folder == root or norm_folder.startswith(root + os.sep):
            path = norm_folder
        else:
            path = os.path.join(root, norm_folder)
    if not os.path.isdir(path):
        raise ValueError(f"Output folder not found: {path}")
    return path


def list_report_paths(folder):
    paths = []
    for name in sorted(os.listdir(folder)):
        if name.startswith("~$"):
            continue
        if name.endswith((".docx", ".xlsx")):
            paths.append(os.path.join(folder, name))
    if not paths:
        raise ValueError(f"No report files found in {folder}")
    return paths


def email_subject_from_paths(paths, folder=None):
    for path in paths:
        stem, _ = os.path.splitext(os.path.basename(path))
        if "_" in stem:
            prefix = stem.split("_", 1)[0]
            if len(prefix) >= 10 and prefix[4] == "." and prefix[7] == ".":
                return f"CNVD report files: {prefix}"
    if folder:
        return f"CNVD report files: {os.path.basename(folder)}"
    return "CNVD report files"
