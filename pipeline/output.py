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


def docx_path_for_lang(base_path, lang):
    if lang == "zh":
        return base_path
    stem, ext = os.path.splitext(base_path)
    if stem.endswith("_en"):
        return base_path
    return f"{stem}_en{ext}"


def sync_docx_output_paths(cfg):
    if cfg.get("output_docx"):
        cfg["output_docx_en"] = docx_path_for_lang(cfg["output_docx"], "en")


def create_run_output_dir(root, now=None):
    now = now or datetime.now()
    path = os.path.join(root or "output", now.strftime("%Y%m%d_%H%M%S"))
    os.makedirs(path, exist_ok=True)
    return path


def apply_dated_output_paths(cfg, cards):
    if not cfg.get("output_date_prefix", True):
        return
    prefix = report_date_prefix(cards)
    for key in ("output_docx", "output_weekly_excel"):
        if cfg.get(key):
            cfg[key] = apply_dated_output_path(prefix, cfg[key])
    sync_docx_output_paths(cfg)


def apply_run_output_paths(cfg, cards, now=None):
    output_dir = create_run_output_dir(cfg.get("output_root", "output"), now)
    apply_dated_output_paths(cfg, cards)
    for key in ("output_docx", "output_weekly_excel"):
        if cfg.get(key):
            cfg[key] = os.path.join(output_dir, os.path.basename(cfg[key]))
    sync_docx_output_paths(cfg)
    cfg["output_dir"] = output_dir
    return output_dir


def title_date(cards, lang):
    locale = LOCALES[lang]
    dates = card_publish_dates(cards)
    if not dates:
        return datetime.now().strftime(locale["title_fallback"])
    start, end = dates[0], dates[-1]
    return locale["title_range"].format(y1=start[:4], m1=start[5:7], d1=start[8:10], m2=end[5:7], d2=end[8:10])


def _format_zh_date(value):
    dt = datetime.strptime(value, "%Y-%m-%d")
    return f"{dt.year}年{dt.month}月{dt.day}日"


def _format_zh_date_range(start, end=None):
    if not end or start == end:
        return _format_zh_date(start)
    start_dt = datetime.strptime(start, "%Y-%m-%d")
    end_dt = datetime.strptime(end, "%Y-%m-%d")
    if start_dt.year == end_dt.year:
        return f"{start_dt.year}年{start_dt.month}月{start_dt.day}日-{end_dt.month}月{end_dt.day}日"
    return f"{start_dt.year}年{start_dt.month}月{start_dt.day}日-{end_dt.year}年{end_dt.month}月{end_dt.day}日"


def email_date_range(cards):
    dates = card_publish_dates(cards)
    if not dates:
        return _format_zh_date(datetime.now().strftime("%Y-%m-%d"))
    start, end = dates[0], dates[-1]
    return _format_zh_date_range(start, end)


def email_date_range_from_paths(paths, folder=None):
    for path in paths:
        stem, _ = os.path.splitext(os.path.basename(path))
        if "_" not in stem:
            continue
        prefix = stem.split("_", 1)[0]
        if len(prefix) < 10 or prefix[4] != "." or prefix[7] != ".":
            continue
        try:
            start = f"{prefix[:4]}-{prefix[5:7]}-{prefix[8:10]}"
            suffix = prefix[10:]
            if suffix.startswith("-") and len(suffix) >= 6:
                end = f"{prefix[:4]}-{suffix[1:3]}-{suffix[4:6]}"
                return _format_zh_date_range(start, end)
            return _format_zh_date_range(start)
        except ValueError:
            continue
    if folder:
        return os.path.basename(folder)
    return _format_zh_date(datetime.now().strftime("%Y-%m-%d"))


def build_email_subject(cfg, cards=None, paths=None, folder=None):
    title = str(cfg.get("email_title") or "報告").strip()
    date_range = email_date_range(cards) if cards else email_date_range_from_paths(paths or [], folder)
    return f"{date_range}{title}"


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
    return build_email_subject({}, paths=paths, folder=folder)
