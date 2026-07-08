"""Reusable AnyShare (eDrive) client for login and folder upload."""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin

LANG = "en-us"
API_PREFIX = "/api/efast/v1"
SHARE_LINK_PREFIX = "/api/shared-link/v1"
PERMANENT_EXPIRES_AT = "1970-01-01T00:00:00Z"
LOGIN_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4E+eiWRwffhRIPQYvlXU
jf0b3HqCmosiCxbFCYI/gdfDBhrTUzbt3fL3o/gRQQBEPf69vhJMFH2ZMtaJM6oh
E3yQef331liPVM0YvqMOgvoID+zDa1NIZFObSsjOKhvZtv9esO0REeiVEPKNc+Dp
6il3x7TV9VKGEv0+iriNjqv7TGAexo2jVtLm50iVKTju2qmCDG83SnVHzsiNj70M
iviqiLpgz72IxjF+xN4bRw8I5dD0GwwO8kDoJUGWgTds+VckCwdtZA65oui9Osk5
t1a4pg6Xu9+HFcEuqwJTDxATvGAz1/YW0oUisjM0ObKTRDVSfnTYeaBsN6L+M+8g
CwIDAQAB
-----END PUBLIC KEY-----"""

ONDUP_OVERWRITE = 3
ONDUP_RENAME = 1

__all__ = [
    "EdriveSession",
    "UploadResult",
    "login",
    "upload_folder",
]


@dataclass
class EdriveSession:
    """Authenticated session backed by a curl cookie jar file."""

    cookiejar: str
    base_url: str
    lang: str = LANG
    username: str | None = None
    redirect: str | None = None
    final_url: str | None = None
    access_token: str | None = None
    _temp_files: list[str] = field(default_factory=list, repr=False)

    def close(self) -> None:
        for path in self._temp_files:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        self._temp_files.clear()
        if self.cookiejar:
            try:
                os.unlink(self.cookiejar)
            except FileNotFoundError:
                pass
            self.cookiejar = ""

    def __enter__(self) -> "EdriveSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class UploadResult:
    """Result of uploading a local folder, including the permanent share link."""

    share_url: str
    share_id: str
    share_link_created: bool
    local_path: str
    remote_path: str
    remote_folder_name: str
    remote_folder_docid: str
    remote_parent_docid: str
    uploaded_files: list[dict[str, Any]]
    created_dirs: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "local_path": self.local_path,
            "remote_path": self.remote_path,
            "remote_parent_docid": self.remote_parent_docid,
            "remote_folder_name": self.remote_folder_name,
            "remote_folder_docid": self.remote_folder_docid,
            "created_dirs": self.created_dirs,
            "uploaded_files": self.uploaded_files,
            "share_url": self.share_url,
            "share_id": self.share_id,
            "share_link_created": self.share_link_created,
        }
        if self.share_url:
            data["share_link"] = {
                "id": self.share_id,
                "url": self.share_url,
                "created": self.share_link_created,
            }
        return data


def _parse_status(headers_text: str) -> int | None:
    status_lines = [line for line in headers_text.splitlines() if line.startswith("HTTP/")]
    if not status_lines:
        return None
    parts = status_lines[-1].split()
    return int(parts[1]) if len(parts) > 1 else None


def _parse_location(headers_text: str) -> str | None:
    locations = re.findall(r"^location:\s*(.+)$", headers_text, re.IGNORECASE | re.MULTILINE)
    return locations[-1].strip() if locations else None


def _read_access_token(cookiejar: str) -> str | None:
    if not cookiejar or not os.path.exists(cookiejar):
        return None
    match = re.search(r"\tclient\.oauth2_token\t(.+)$", Path(cookiejar).read_text(encoding="utf-8"), re.MULTILINE)
    return match.group(1).strip() if match else None


def _complete_oauth_flow(session: EdriveSession) -> None:
    current_url = session.final_url
    if not current_url:
        return

    for _ in range(12):
        _, headers, _ = _curl_request(current_url, session.cookiejar)
        location = _parse_location(headers)
        if not location:
            break
        current_url = urljoin(current_url, location)

    session.final_url = current_url
    session.access_token = _read_access_token(session.cookiejar)


def _curl_request(
    url: str,
    cookiejar: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    form: list[tuple[str, Any]] | None = None,
) -> tuple[int | None, str, str]:
    headers = headers or {}
    with tempfile.NamedTemporaryFile(delete=False) as header_file, tempfile.NamedTemporaryFile(delete=False) as body_file:
        header_path = header_file.name
        body_path = body_file.name

    cmd = [
        "curl",
        "-sS",
        "-D",
        header_path,
        "-o",
        body_path,
        "-c",
        cookiejar,
        "-b",
        cookiejar,
        "-X",
        method,
        url,
    ]

    for key, value in headers.items():
        cmd.extend(["-H", f"{key}: {value}"])

    if form is not None:
        for key, value in form:
            if value is None:
                continue
            cmd.extend(["-F", f"{key}={value}"])
    elif body is not None:
        cmd.extend(["--data-raw", body if isinstance(body, str) else body.decode("latin-1")])

    result = subprocess.run(cmd, capture_output=True, text=not isinstance(body, bytes) and form is None)
    headers_text = Path(header_path).read_text(encoding="utf-8", errors="replace")
    body_text = Path(body_path).read_bytes()
    os.unlink(header_path)
    os.unlink(body_path)

    if result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else str(result.returncode)
        raise RuntimeError(f"curl failed for {url}: {stderr}")

    decoded_body = body_text.decode("utf-8", errors="replace")
    return _parse_status(headers_text), headers_text, decoded_body


def api_request(
    session: EdriveSession,
    method: str,
    path: str,
    *,
    json_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int | None, Any]:
    url = path if path.startswith("http") else f"{session.base_url}{path}"
    req_headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (edrive python client)",
        "Referer": f"{session.base_url}/anyshare/{session.lang}/homepage",
    }
    if session.access_token and "Authorization" not in (headers or {}):
        req_headers["Authorization"] = f"Bearer {session.access_token}"
    if headers:
        req_headers.update(headers)
    body = None
    if json_body is not None:
        req_headers["Content-Type"] = "application/json"
        body = json.dumps(json_body)

    status, _, text = _curl_request(url, session.cookiejar, method=method, headers=req_headers, body=body)
    if not text:
        return status, None
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, text


def _encrypt_password(password: str) -> str:
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as key_file:
        key_file.write(LOGIN_PUBLIC_KEY)
        key_path = key_file.name

    try:
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey",
                key_path,
                "-pkeyopt",
                "rsa_padding_mode:pkcs1",
            ],
            input=password.encode("utf-8"),
            capture_output=True,
        )
    finally:
        os.unlink(key_path)

    if result.returncode != 0:
        raise RuntimeError(f"openssl encryption failed: {result.stderr.decode('utf-8', errors='replace').strip()}")

    return base64.b64encode(result.stdout).decode("ascii")


def _extract_next_data(html: str) -> dict[str, Any]:
    match = re.search(r'<script id="__NEXT_DATA__" type="application/json">([\s\S]*?)</script>', html)
    if not match:
        raise RuntimeError("Could not find __NEXT_DATA__ in login page.")
    return json.loads(match.group(1))


def login(
    username: str,
    password: str,
    base_url: str,
    *,
    cookiejar: str | None = None,
) -> EdriveSession:
    """Authenticate to AnyShare and return a reusable session."""

    if not username or not password or not base_url:
        raise RuntimeError("Missing username/password/base_url.")

    temp_cookie = cookiejar is None
    if cookiejar is None:
        cookie_file = tempfile.NamedTemporaryFile(delete=False)
        cookiejar = cookie_file.name
        cookie_file.close()

    session = EdriveSession(cookiejar=cookiejar, base_url=base_url, lang=LANG, username=username)
    if temp_cookie:
        session._temp_files.append(cookiejar)

    redirect_target = f"/anyshare/{LANG}/homepage"
    login_url = f"{base_url}/anyshare/oauth2/login?lang={LANG}&redirect={quote(redirect_target, safe='')}"

    _, login_headers, _ = _curl_request(login_url, cookiejar)
    auth_location = _parse_location(login_headers)
    auth_url = urljoin(base_url, auth_location) if auth_location else login_url

    _, auth_headers, _ = _curl_request(auth_url, cookiejar)
    signin_location = _parse_location(auth_headers)
    signin_url = urljoin(base_url, signin_location) if signin_location else auth_url

    _, _, login_html = _curl_request(signin_url, cookiejar)
    page_props = _extract_next_data(login_html).get("props", {}).get("pageProps", {})

    if not page_props.get("csrftoken") or not page_props.get("challenge") or not page_props.get("device"):
        raise RuntimeError("Login page is missing csrftoken, challenge, or device data.")

    payload = {
        "_csrf": page_props["csrftoken"],
        "challenge": page_props["challenge"],
        "account": username,
        "password": _encrypt_password(password),
        "vcode": {"id": "", "content": ""},
        "dualfactorauthinfo": {"validcode": {"vcode": ""}, "OTP": {"OTP": ""}},
        "remember": False,
        "device": page_props["device"],
    }

    status, _, body_text = _curl_request(
        f"{base_url}/oauth2/signin",
        cookiejar,
        method="POST",
        headers={
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": base_url,
            "Referer": signin_url,
            "User-Agent": "Mozilla/5.0 (edrive python client)",
        },
        body=json.dumps(payload),
    )
    body = json.loads(body_text) if body_text else {}

    if status is None or status >= 400:
        raise RuntimeError(f"Login failed ({status}): {json.dumps(body)}")
    if not body.get("redirect"):
        raise RuntimeError(f"Login succeeded but no redirect was returned: {json.dumps(body)}")

    _, final_headers, _ = _curl_request(body["redirect"], cookiejar)
    session.redirect = body["redirect"]
    session.final_url = _parse_location(final_headers) or body["redirect"]
    _complete_oauth_flow(session)
    if not session.access_token:
        raise RuntimeError("Login completed but no OAuth access token was issued.")
    return session


def list_owned_doc_libs(session: EdriveSession) -> list[dict[str, Any]]:
    status, data = api_request(session, "GET", f"{API_PREFIX}/owned-doc-lib")
    if status is None or status >= 400:
        raise RuntimeError(f"Failed to list owned doc libs ({status}): {data}")
    return data or []


def list_dir(session: EdriveSession, docid: str) -> dict[str, Any]:
    status, data = api_request(session, "POST", f"{API_PREFIX}/dir/list", json_body={"docid": docid})
    if status is None or status >= 400:
        raise RuntimeError(f"Failed to list directory ({status}): {data}")
    return data or {"dirs": [], "files": []}


def create_dir(session: EdriveSession, parent_docid: str, name: str, ondup: int = ONDUP_RENAME) -> dict[str, Any]:
    status, data = api_request(
        session,
        "POST",
        f"{API_PREFIX}/dir/create",
        json_body={"docid": parent_docid, "name": name, "ondup": ondup},
    )
    if status is None or status >= 400:
        raise RuntimeError(f"Failed to create directory '{name}' ({status}): {data}")
    return data


def find_child_dir(session: EdriveSession, parent_docid: str, name: str) -> dict[str, Any] | None:
    listing = list_dir(session, parent_docid)
    for item in listing.get("dirs", []):
        if item.get("name") == name:
            return item
    return None


def resolve_docid_by_name(session: EdriveSession, name: str) -> str:
    for lib in list_owned_doc_libs(session):
        if lib.get("name") == name:
            return lib["id"]
    raise RuntimeError(f"Could not find document library named '{name}'.")


def _split_remote_path(path: str) -> list[str]:
    return [part for part in path.replace("\\", "/").split("/") if part]


def _find_folder(session: EdriveSession, path: str) -> dict[str, Any] | None:
    """Find an existing eDrive folder by path, e.g. ``Ben Chan/templates``."""

    parts = _split_remote_path(path)
    if not parts:
        return None

    try:
        current_docid = resolve_docid_by_name(session, parts[0])
    except RuntimeError:
        return None

    folder: dict[str, Any] = {"name": parts[0], "docid": current_docid}
    for part in parts[1:]:
        found = find_child_dir(session, current_docid, part)
        if not found:
            return None
        current_docid = found.get("docid") or found.get("id")
        folder = found

    return folder


def _parent_docid_from_docid(docid: str) -> str:
    if "/" not in docid:
        return docid
    return docid.rsplit("/", 1)[0]


def _resolve_upload_destination(
    session: EdriveSession,
    *,
    remote_path: str | None,
    remote_docid: str | None,
) -> tuple[str, str, list[dict[str, Any]], str, str]:
    if remote_docid:
        target_name = remote_docid.rsplit("/", 1)[-1]
        return (
            remote_docid,
            _parent_docid_from_docid(remote_docid),
            [],
            remote_path or remote_docid,
            target_name,
        )

    if not remote_path:
        raise ValueError("Either remote_path or remote_docid is required")

    parts = _split_remote_path(remote_path)
    if not parts:
        raise ValueError("remote_path cannot be empty")

    existing = _find_folder(session, remote_path)
    if existing:
        docid = existing.get("docid") or existing.get("id")
        if len(parts) > 1:
            parent = _find_folder(session, "/".join(parts[:-1]))
            parent_docid = (parent.get("docid") or parent.get("id")) if parent else docid
        else:
            parent_docid = docid
        return docid, parent_docid, [], remote_path, parts[-1]

    docid, parent_docid, created_dirs = resolve_folder_path(session, remote_path)
    return docid, parent_docid, created_dirs, remote_path, parts[-1]


def resolve_folder_path(
    session: EdriveSession,
    path: str,
    *,
    create: bool = True,
) -> tuple[str, str, list[dict[str, Any]]]:
    """Resolve an eDrive path to a folder docid, creating missing folders when needed."""

    parts = _split_remote_path(path)
    if not parts:
        raise ValueError("remote_path cannot be empty")

    current_docid = resolve_docid_by_name(session, parts[0])
    parent_docid = current_docid
    created_dirs: list[dict[str, Any]] = []

    for part in parts[1:]:
        parent_docid = current_docid
        found = find_child_dir(session, current_docid, part)
        if found:
            current_docid = found.get("docid") or found.get("id")
            continue
        if not create:
            raise RuntimeError(f"Remote folder not found: {path}")
        created = create_dir(session, current_docid, part)
        current_docid = created.get("docid") or created.get("id")
        created_dirs.append({"name": part, "docid": current_docid})

    return current_docid, parent_docid, created_dirs


def _language_header(session: EdriveSession) -> dict[str, str]:
    return {"X-Language": "en-US"}


def _is_permanent_link(link: dict[str, Any]) -> bool:
    expires_at = link.get("expires_at")
    if not expires_at:
        return False
    try:
        normalized = expires_at.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp()) == 0
    except ValueError:
        return False


def _share_link_url(session: EdriveSession, link_id: str) -> str:
    return f"{session.base_url}/link/{link_id}"


def list_share_links(
    session: EdriveSession,
    docid: str,
    *,
    item_type: str = "folder",
    link_type: str = "anonymous",
) -> list[dict[str, Any]]:
    encoded_docid = quote(docid, safe="")
    path = f"{SHARE_LINK_PREFIX}/document/{item_type}/{encoded_docid}?type={link_type}"
    status, data = api_request(session, "GET", path, headers=_language_header(session))
    if status is None or status >= 400:
        raise RuntimeError(f"Failed to list share links ({status}): {data}")
    return data if isinstance(data, list) else []


def create_anonymous_share_link(
    session: EdriveSession,
    docid: str,
    *,
    title: str,
    allow: list[str] | None = None,
) -> str:
    payload = {
        "item": {
            "id": docid,
            "type": "folder",
            "allow": allow or ["display", "preview", "download"],
        },
        "title": title,
        "expires_at": PERMANENT_EXPIRES_AT,
        "password": "",
        "limited_times": -1,
    }
    status, data = api_request(
        session,
        "POST",
        f"{SHARE_LINK_PREFIX}/document/anonymous",
        json_body=payload,
        headers=_language_header(session),
    )
    if status == 202:
        raise RuntimeError("Share link creation requires approval on this tenant. Contact your administrator.")
    if status is None or status >= 400:
        raise RuntimeError(f"Failed to create share link ({status}): {data}")
    link_id = data.get("id") if isinstance(data, dict) else None
    if not link_id:
        raise RuntimeError(f"Share link created but no id was returned: {data}")
    return link_id


def get_or_create_permanent_share_link(
    session: EdriveSession,
    docid: str,
    *,
    title: str,
) -> dict[str, Any]:
    existing_links = list_share_links(session, docid)
    for link in existing_links:
        if _is_permanent_link(link) and link.get("id"):
            return {
                "id": link["id"],
                "url": _share_link_url(session, link["id"]),
                "expires_at": link.get("expires_at", PERMANENT_EXPIRES_AT),
                "created": False,
            }

    link_id = create_anonymous_share_link(session, docid, title=title)
    return {
        "id": link_id,
        "url": _share_link_url(session, link_id),
        "expires_at": PERMANENT_EXPIRES_AT,
        "created": True,
    }


def _upload_file(session: EdriveSession, parent_docid: str, file_path: Path, ondup: int = ONDUP_OVERWRITE) -> dict[str, Any]:
    stat = file_path.stat()
    status, begin = api_request(
        session,
        "POST",
        f"{API_PREFIX}/file/osbeginupload",
        json_body={
            "client_mtime": int(stat.st_mtime * 1000),
            "docid": parent_docid,
            "length": stat.st_size,
            "name": file_path.name,
            "ondup": ondup,
            "reqmethod": "POST",
        },
    )
    if status is None or status >= 400:
        raise RuntimeError(f"Failed to begin upload for {file_path.name} ({status}): {begin}")

    authrequest = begin.get("authrequest") or []
    if len(authrequest) < 2:
        raise RuntimeError(f"Unexpected begin upload response for {file_path.name}: {begin}")

    method, upload_url = authrequest[0], authrequest[1]
    form_fields: list[tuple[str, Any]] = []
    for header_line in authrequest[2:]:
        key, value = header_line.split(": ", 1)
        form_fields.append((key, value))
    form_fields.append(("file", f"@{file_path}"))

    with tempfile.NamedTemporaryFile(delete=False) as header_file, tempfile.NamedTemporaryFile(delete=False) as body_file:
        header_path = header_file.name
        body_path = body_file.name

    cmd = ["curl", "-sS", "-D", header_path, "-o", body_path, "-X", method, upload_url]
    for key, value in form_fields:
        cmd.extend(["-F", f"{key}={value}"])

    result = subprocess.run(cmd, capture_output=True, text=True)
    upload_status = _parse_status(Path(header_path).read_text(encoding="utf-8", errors="replace"))
    os.unlink(header_path)
    os.unlink(body_path)

    if result.returncode != 0 or upload_status is None or upload_status >= 400:
        raise RuntimeError(
            f"Failed to upload file {file_path.name} ({upload_status}): {result.stderr.strip() or result.stdout.strip()}"
        )

    status, end = api_request(
        session,
        "POST",
        f"{API_PREFIX}/file/osendupload",
        json_body={"docid": begin["docid"], "rev": begin["rev"]},
    )
    if status is None or status >= 400:
        raise RuntimeError(f"Failed to end upload for {file_path.name} ({status}): {end}")

    return {"name": file_path.name, "docid": begin.get("docid"), "rev": begin.get("rev"), "size": stat.st_size}


def upload_folder(
    session: EdriveSession,
    local_path: str | Path,
    remote_path: str | None = None,
    *,
    remote_docid: str | None = None,
    ondup: int = ONDUP_OVERWRITE,
    create_share_link: bool = True,
) -> UploadResult:
    """Upload a local folder tree to eDrive by path or docid."""

    root = Path(local_path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Local path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Local path is not a directory: {root}")

    remote_root_docid, parent_docid, created_dirs, result_remote_path, target_name = _resolve_upload_destination(
        session,
        remote_path=remote_path,
        remote_docid=remote_docid,
    )

    uploaded_files: list[dict[str, Any]] = []

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        current_parent = remote_root_docid

        if rel_dir != Path("."):
            built = Path(".")
            current_parent = remote_root_docid
            for part in rel_dir.parts:
                built = built / part
                found = find_child_dir(session, current_parent, part)
                if found:
                    current_parent = found.get("docid") or found.get("id")
                else:
                    created = create_dir(session, current_parent, part)
                    current_parent = created.get("docid") or created.get("id")
                    created_dirs.append({"name": str(built), "docid": current_parent})

        for filename in filenames:
            file_path = Path(dirpath) / filename
            uploaded_files.append(_upload_file(session, current_parent, file_path, ondup=ondup))

    share: dict[str, Any] | None = None
    if create_share_link:
        share = get_or_create_permanent_share_link(
            session,
            remote_root_docid,
            title=target_name,
        )

    return UploadResult(
        share_url=share["url"] if share else "",
        share_id=share["id"] if share else "",
        share_link_created=share["created"] if share else False,
        local_path=str(root),
        remote_path=result_remote_path,
        remote_folder_name=target_name,
        remote_folder_docid=remote_root_docid,
        remote_parent_docid=parent_docid,
        uploaded_files=uploaded_files,
        created_dirs=created_dirs,
    )

