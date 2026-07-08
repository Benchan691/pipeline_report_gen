import html
import logging
import posixpath
import re
import urllib.parse
import urllib.request
import zipfile
from email.utils import parseaddr
from io import BytesIO
from pathlib import Path
import xml.etree.ElementTree as ET

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


def transfer_address(cfg):
    return _zimbra_email(cfg)


def _zimbra_host(cfg):
    return str(cfg.get("zimbra_host") or cfg.get("host") or "").strip()


def _zimbra_email(cfg):
    return str(cfg.get("zimbra_email") or cfg.get("email") or "").strip()


def _zimbra_password(cfg):
    return str(cfg.get("zimbra_password") or cfg.get("password") or "").strip()


def require_transfer_config(cfg, receive=False):
    missing = []
    if not _zimbra_host(cfg):
        missing.append("ZIMBRA_HOST")
    if not _zimbra_email(cfg):
        missing.append("ZIMBRA_EMAIL")
    if not _zimbra_password(cfg):
        missing.append("ZIMBRA_PASSWORD")
    if missing:
        raise ValueError("Missing transfer config: " + ", ".join(missing))


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


def _zimbra_upload(host, token, filename, data, content_type="application/octet-stream"):
    boundary = "----codex-zimbra-upload"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    request = urllib.request.Request(
        f"https://{host}/service/upload?fmt=raw",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"ZM_AUTH_TOKEN={token}",
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        text = response.read().decode("utf-8", errors="replace")
    match = re.search(r'["\']?aid["\']?\s*[:=]\s*["\']([^"\']+)["\']', text)
    if match:
        return match.group(1)
    quoted = re.findall(r"'([^']+)'", text)
    if len(quoted) >= 2:
        return quoted[-1]
    if not match:
        raise RuntimeError(f"Zimbra upload failed: attachment id not found in response {text[:300]}")


def zimbra_send_email(cfg, to, subject, body, attachments=None):
    require_transfer_config(cfg)
    host = _zimbra_host(cfg)
    token = zimbra_login(cfg)
    attach_ids = []
    for item in attachments or []:
        attach_ids.append(
            _zimbra_upload(
                host,
                token,
                item["filename"],
                item["data"],
                item.get("content_type", "application/octet-stream"),
            )
        )

    attach_xml = "".join(f'<attach aid="{html.escape(aid)}"/>' for aid in attach_ids)
    _soap_request(
        host,
        f"""<SendMsgRequest xmlns="urn:zimbraMail">
  <m>
    <e t="t" a="{html.escape(str(to).strip())}"/>
    <su>{html.escape(str(subject or "").strip())}</su>
    <mp ct="text/plain"><content>{html.escape(str(body or ""))}</content></mp>
    {attach_xml}
  </m>
</SendMsgRequest>""",
        token,
    )


def send_transfer_from_folder(cfg, folder_path):
    require_transfer_config(cfg)
    folder = Path(folder_path).expanduser().resolve()
    to_addr = transfer_address(cfg)
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
    )
    log.info("Transfer email sent to %s for %s", to_addr, folder)
    return folder.name


def _local_name(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _soap_request(host, body_xml, auth_token=""):
    header = f"<authToken>{html.escape(auth_token)}</authToken>" if auth_token else ""
    envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header><context xmlns="urn:zimbra">{header}</context></soap:Header>
  <soap:Body>{body_xml}</soap:Body>
</soap:Envelope>
"""
    request = urllib.request.Request(
        f"https://{host}/service/soap",
        data=envelope.encode("utf-8"),
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return ET.fromstring(response.read())


def zimbra_login(cfg):
    host = _zimbra_host(cfg)
    account = html.escape(_zimbra_email(cfg))
    password = html.escape(_zimbra_password(cfg))
    root = _soap_request(
        host,
        f"""<AuthRequest xmlns="urn:zimbraAccount">
  <account by="name">{account}</account>
  <password>{password}</password>
</AuthRequest>""",
    )
    token = next((elem.text for elem in root.iter() if _local_name(elem.tag) == "authToken"), "")
    if not token:
        raise RuntimeError("Zimbra login failed: auth token not found")
    return token


def zimbra_search(host, token, folder_id, limit):
    query = html.escape(f"inid:{folder_id}")
    root = _soap_request(
        host,
        f"""<SearchRequest xmlns="urn:zimbraMail" types="message" sortBy="dateDesc" limit="{int(limit)}">
  <query>{query}</query>
</SearchRequest>""",
        token,
    )
    return [elem.get("id", "") for elem in root.iter() if _local_name(elem.tag) == "m" and elem.get("id")]


def zimbra_get_message(host, token, message_id):
    root = _soap_request(
        host,
        f'<GetMsgRequest xmlns="urn:zimbraMail"><m id="{html.escape(message_id)}" html="0" needExp="1"/></GetMsgRequest>',
        token,
    )
    msg = next((elem for elem in root.iter() if _local_name(elem.tag) == "m" and elem.get("id") == message_id), None)
    if msg is None:
        return None

    subject_elem = next((elem for elem in msg.iter() if _local_name(elem.tag) == "su"), None)
    addresses = []
    attachments = []
    for elem in msg.iter():
        name = _local_name(elem.tag)
        if name == "e":
            addresses.append({"type": elem.get("t", ""), "email": elem.get("a", "")})
        elif name == "mp" and (elem.get("filename") or elem.get("cd") == "attachment"):
            attachments.append(
                {
                    "filename": elem.get("filename", ""),
                    "part": elem.get("part", ""),
                    "content_type": elem.get("ct", ""),
                }
            )

    return {
        "id": message_id,
        "subject": (subject_elem.text if subject_elem is not None else "") or "",
        "from": next((a["email"] for a in addresses if a["type"] == "f"), ""),
        "to": [a["email"] for a in addresses if a["type"] == "t"],
        "attachments": attachments,
    }


def _norm_email(value):
    return (parseaddr(str(value or ""))[1] or str(value or "")).strip().lower()


def matches_transfer_message(cfg, message):
    folder = parse_transfer_subject(message.get("subject"))
    address = _norm_email(transfer_address(cfg))
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


def download_attachment(cfg, token, message_id, part):
    host = _zimbra_host(cfg)
    account = urllib.parse.quote(_zimbra_email(cfg), safe="")
    query = urllib.parse.urlencode({"id": message_id, "part": part})
    request = urllib.request.Request(
        f"https://{host}/home/{account}/?{query}",
        headers={"Cookie": f"ZM_AUTH_TOKEN={token}"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


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


def zimbra_delete_message(host, token, message_id):
    _soap_request(
        host,
        f'<MsgActionRequest xmlns="urn:zimbraMail"><action id="{html.escape(message_id)}" op="delete"/></MsgActionRequest>',
        token,
    )


def receive_transfer(cfg, deliver_folder):
    require_transfer_config(cfg, receive=True)
    host = _zimbra_host(cfg)
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
