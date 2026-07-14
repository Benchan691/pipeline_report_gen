import logging
import posixpath
import zipfile
from email.utils import parseaddr
from io import BytesIO
from pathlib import Path

from plugin.zimbra import (
    download_attachment,
    require_zimbra_config,
    zimbra_delete_message,
    zimbra_email,
    zimbra_get_message,
    zimbra_host,
    zimbra_login,
    zimbra_search,
    zimbra_send_email,
)

log = logging.getLogger(__name__)

SUBJECT_PREFIX = "PIPELINE_UPLOAD:"


def transfer_subject(folder_name):
    return f"{SUBJECT_PREFIX}{folder_name}"


def parse_transfer_subject(subject):
    subject = str(subject or "").strip()
    if not subject.startswith(SUBJECT_PREFIX):
        return ""
    folder = subject[len(SUBJECT_PREFIX) :].strip()
    if not folder or "/" in folder or "\\" in folder or folder in (".", ".."):
        return ""
    return folder


def make_transfer_zip(folder_path):
    folder = Path(folder_path).expanduser().resolve()
    if not folder.is_dir():
        raise ValueError(f"Output folder not found: {folder}")

    files = [p for p in folder.rglob("*") if p.is_file() and not p.name.startswith("~$")]
    if not files:
        raise ValueError(f"No files to transfer in {folder}")

    data = BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            zf.write(path, Path(folder.name) / path.relative_to(folder))
    return data.getvalue()


def send_transfer_from_folder(cfg, folder_path):
    require_zimbra_config(cfg)
    folder = Path(folder_path).expanduser().resolve()
    to_addr = zimbra_email(cfg)
    folder_id = str(cfg.get("zimbra_folder_id") or "2")
    zimbra_send_email(
        cfg,
        to_addr,
        transfer_subject(folder.name),
        f"Pipeline upload bundle: {folder.name}",
        [
            {
                "filename": f"{folder.name}.zip",
                "data": make_transfer_zip(folder),
                "content_type": "application/zip",
            }
        ],
        folder_id=folder_id,
    )
    log.info("Transfer email sent to %s folder_id=%s for %s", to_addr, folder_id, folder)
    return folder.name

def _norm_email(value):
    return (parseaddr(str(value or ""))[1] or str(value or "")).strip().lower()


def matches_transfer_message(cfg, message):
    folder = parse_transfer_subject(message.get("subject"))
    address = _norm_email(zimbra_email(cfg))
    return bool(
        folder
        and address
        and address in {_norm_email(item) for item in message.get("to", [])}
    )


def _zip_attachment(message, folder):
    wanted = f"{folder}.zip".lower()
    attachments = message.get("attachments", [])
    exact = [a for a in attachments if a.get("filename", "").lower() == wanted and a.get("part")]
    if exact:
        return exact[0]
    return next((a for a in attachments if a.get("filename", "").lower().endswith(".zip") and a.get("part")), None)

def safe_extract_transfer_zip(zip_bytes, output_root, expected_folder):
    root = Path(output_root or "output").expanduser().resolve()
    target = (root / expected_folder).resolve()
    if target.exists() and not target.is_dir():
        raise ValueError(f"Output path exists and is not a folder: {target}")

    root.mkdir(parents=True, exist_ok=True)
    prefix = f"{expected_folder}/"
    has_file = False
    with zipfile.ZipFile(BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            raw = info.filename.replace("\\", "/")
            norm = posixpath.normpath(raw)
            if raw.startswith("/") or norm.startswith("../") or norm in ("", ".", ".."):
                raise ValueError(f"Unsafe zip path: {info.filename}")
            if norm != expected_folder and not norm.startswith(prefix):
                raise ValueError(f"Zip does not contain expected folder {expected_folder}: {info.filename}")
            has_file = has_file or not info.is_dir()
        if not has_file:
            raise ValueError("Transfer zip is empty")
        zf.extractall(root)
    return str(target)

def receive_transfer(cfg, deliver_folder):
    require_zimbra_config(cfg)
    host = zimbra_host(cfg)
    token = zimbra_login(cfg)
    folder_id = str(cfg.get("zimbra_folder_id") or "2")
    limit = int(cfg.get("zimbra_scan_limit") or 10)

    for message_id in zimbra_search(host, token, folder_id, limit):
        message = zimbra_get_message(host, token, message_id)
        if not message or not matches_transfer_message(cfg, message):
            continue
        folder = parse_transfer_subject(message["subject"])
        attachment = _zip_attachment(message, folder)
        if not attachment:
            continue

        safe_extract_transfer_zip(
            download_attachment(cfg, token, message_id, attachment["part"]),
            cfg.get("output_root", "output"),
            folder,
        )
        deliver_folder(folder)
        zimbra_delete_message(host, token, message_id)
        log.info("Transfer processed and deleted: message=%s folder=%s", message_id, folder)
        return folder

    log.info(
        "No transfer email received (no matching message in Inbox folder %s, latest %s)",
        folder_id,
        limit,
    )
    return None
