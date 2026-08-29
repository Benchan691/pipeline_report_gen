import logging
import posixpath
import shutil
import time
import zipfile
from datetime import datetime
from email.utils import parseaddr
from io import BytesIO
from pathlib import Path

from zimbra_client import Attachment, ZimbraClient

from pipeline.amqp import consume_transfer_requests, publish_transfer_request
from pipeline.edrive_upload import check_edrive_connectivity_or_exit

log = logging.getLogger(__name__)

SUBJECT_PREFIX = "PIPELINE_UPLOAD:"
ZIMBRA_LOOKUP_ATTEMPTS = 8
ZIMBRA_LOOKUP_DELAY_SECONDS = 0.5


def zimbra_email(cfg):
    return str(cfg.get("zimbra_email") or cfg.get("email") or "").strip()


def require_zimbra_config(cfg):
    missing = []
    if not str(cfg.get("zimbra_host") or cfg.get("host") or "").strip():
        missing.append("ZIMBRA_HOST")
    if not zimbra_email(cfg):
        missing.append("ZIMBRA_EMAIL")
    if not str(cfg.get("zimbra_password") or cfg.get("password") or "").strip():
        missing.append("ZIMBRA_PASSWORD")
    if missing:
        raise ValueError("Missing transfer config: " + ", ".join(missing))


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


def make_test_transfer_folder(output_root, when=None):
    stamp = (when or datetime.now()).strftime("%Y%m%d_%H%M%S")
    folder_name = f"test_transfer_{stamp}"
    root = Path(output_root or "output").expanduser().resolve()
    folder = root / folder_name
    folder.mkdir(parents=True, exist_ok=False)
    marker = folder / "TEST_TRANSFER.txt"
    marker.write_text(
        f"Synthetic pipeline transfer test bundle.\ncreated_at={stamp}\n",
        encoding="utf-8",
    )
    log.info("Created test transfer folder %s", folder)
    return folder


def send_test_transfer(cfg):
    folder = make_test_transfer_folder(cfg.get("output_root", "output"))
    return send_transfer_from_folder(cfg, folder)


def send_transfer_from_folder(cfg, folder_path):
    require_zimbra_config(cfg)
    folder = Path(folder_path).expanduser().resolve()
    to_addr = zimbra_email(cfg)
    folder_id = str(cfg.get("zimbra_folder_id") or "2")
    subject = transfer_subject(folder.name)
    with ZimbraClient(cfg) as client:
        client.send_message(
            to=to_addr,
            subject=subject,
            text=f"Pipeline upload bundle: {folder.name}",
            attachments=[
                Attachment(
                    filename=f"{folder.name}.zip",
                    data=make_transfer_zip(folder),
                    content_type="application/zip",
                )
            ],
        )
        _move_sent_message(client, subject, folder_id)
    log.info("Transfer email sent to %s folder_id=%s for %s", to_addr, folder_id, folder)
    publish_transfer_request(cfg, folder.name, subject=subject)
    log.info("Transfer wake-up published for %s", folder.name)
    return folder.name


def _move_sent_message(client, subject, folder_id):
    dest = str(folder_id or "").strip()
    if not dest or dest == "2":
        return

    subject_text = str(subject or "").strip()
    for attempt in range(ZIMBRA_LOOKUP_ATTEMPTS):
        for message in client.search_messages(folder_id="2", limit=20).messages:
            if str(message.subject or "").strip() == subject_text:
                client.move_message(message.id, dest)
                return
        if attempt + 1 < ZIMBRA_LOOKUP_ATTEMPTS:
            time.sleep(ZIMBRA_LOOKUP_DELAY_SECONDS * (attempt + 1))
    raise RuntimeError(f"Transfer sent but message not found in Inbox to move to folder {dest}")


def _norm_email(value):
    return (parseaddr(str(value or ""))[1] or str(value or "")).strip().lower()


def matches_transfer_message(cfg, message):
    folder = parse_transfer_subject(message.subject)
    address = _norm_email(zimbra_email(cfg))
    return bool(
        folder
        and address
        and address in {_norm_email(item.email) for item in message.to}
    )


def _zip_attachment(message, folder):
    wanted = f"{folder}.zip".lower()
    attachments = message.attachments
    exact = [a for a in attachments if a.filename.lower() == wanted and a.part]
    if exact:
        return exact[0]
    return next((a for a in attachments if a.filename.lower().endswith(".zip") and a.part), None)


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


def _find_transfer_message(client, cfg, folder, subject=None):
    folder_id = str(cfg.get("zimbra_folder_id") or "2")
    limit = int(cfg.get("zimbra_scan_limit") or 10)
    expected_subject = str(subject or transfer_subject(folder)).strip()

    for summary in client.search_messages(folder_id=folder_id, limit=limit).messages:
        message = client.get_message(summary.id, html=False)
        message_subject = str(message.subject or "").strip()
        if message_subject != expected_subject and not matches_transfer_message(cfg, message):
            continue
        parsed_folder = parse_transfer_subject(message_subject) or folder
        if parsed_folder != folder:
            continue
        attachment = _zip_attachment(message, folder)
        if not attachment:
            continue
        return message.id, message, attachment
    return None, None, None


def _process_transfer_message(cfg, folder, deliver_folder, subject=None):
    require_zimbra_config(cfg)
    with ZimbraClient(cfg) as client:
        message_id = None
        attachment = None
        for attempt in range(ZIMBRA_LOOKUP_ATTEMPTS):
            message_id, message, attachment = _find_transfer_message(client, cfg, folder, subject=subject)
            if message_id:
                break
            if attempt + 1 < ZIMBRA_LOOKUP_ATTEMPTS:
                delay = ZIMBRA_LOOKUP_DELAY_SECONDS * (attempt + 1)
                log.info(
                    "Transfer email not ready for folder=%s; retrying in %.1fs (%d/%d)",
                    folder,
                    delay,
                    attempt + 1,
                    ZIMBRA_LOOKUP_ATTEMPTS,
                )
                time.sleep(delay)

        if not message_id or not attachment:
            raise ValueError(f"No matching transfer email found for folder {folder}")

        safe_extract_transfer_zip(
            client.download_attachment(message_id, attachment.part),
            cfg.get("output_root", "output"),
            folder,
        )
        deliver_folder(folder)
        client.delete_message(message_id)
        log.info("Transfer processed and deleted: message=%s folder=%s", message_id, folder)
    return folder


def delete_received_output_folder(output_root, folder_name):
    folder = str(folder_name or "").strip()
    if not folder or "/" in folder or "\\" in folder or folder in (".", ".."):
        raise ValueError(f"Unsafe output folder name: {folder_name}")
    root = Path(output_root or "output").expanduser().resolve()
    target = (root / folder).resolve()
    if target == root or root not in target.parents:
        raise ValueError(f"Refusing to delete path outside output root: {target}")
    if not target.exists():
        log.info("Received output folder already absent: %s", target)
        return
    if not target.is_dir():
        raise ValueError(f"Output path is not a folder: {target}")
    shutil.rmtree(target)
    log.info("Deleted local output folder after eDrive upload: %s", target)


def receive_transfer(cfg, deliver_folder, fake=False):
    require_zimbra_config(cfg)

    def deliver(folder_name):
        if fake:
            check_edrive_connectivity_or_exit(required=True)
            log.info("Fake receive: skipped eDrive upload and notify email for %s", folder_name)
            return
        deliver_folder(folder_name)
        delete_received_output_folder(cfg.get("output_root", "output"), folder_name)

    def on_message(folder, subject):
        _process_transfer_message(cfg, folder, deliver, subject=subject)

    consume_transfer_requests(cfg, on_message)
    return None
