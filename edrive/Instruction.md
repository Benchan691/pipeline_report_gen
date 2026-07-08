# eDrive (AnyShare) Python Client

Import-only client for [AnyShare eDrive](https://edrive.citictel-cpc.com): log in, upload a local folder, and get a permanent share link.

**Requirements:** Python 3.9+, `curl`, `openssl`

## Install

```bash
pip install -e /path/to/edrive
```

## Quick start

```python
from edrive import login, upload_folder

with login("username", "password", "https://edrive.citictel-cpc.com") as session:
    result = upload_folder(session, "/path/to/folder", "Ben Chan/templates")
    print(result.share_url)
```

## Public API

```python
from edrive import EdriveSession, UploadResult, login, upload_folder
```

### `login(username, password, base_url, *, cookiejar=...) -> EdriveSession`

Authenticate to eDrive. **`username`, `password`, and `base_url` are required** — `login()` cannot be called with no arguments and does not read `.env`. Use as a context manager to clean up temporary session files.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `username` | `str` | — | AnyShare username |
| `password` | `str` | — | Password |
| `base_url` | `str` | — | Server URL, e.g. `https://edrive.citictel-cpc.com` |
| `cookiejar` | `str \| None` | auto | Cookie jar file path |

### `upload_folder(session, local_path, remote_path=None, *, remote_docid=None, ondup=3, create_share_link=True) -> UploadResult`

Upload a local folder tree to eDrive. **Provide at least one of** `remote_path` or `remote_docid` (`remote_docid` takes precedence).

```python
# by path (creates missing folders)
upload_folder(session, "/local/templates", "Ben Chan/templates")

# by docid (skips path lookup)
upload_folder(session, "/local/templates", remote_docid="gns://.../...")
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `session` | `EdriveSession` | — | Session from `login()` |
| `local_path` | `str \| Path` | — | Local folder to upload |
| `remote_path` | `str \| None` | `None` | eDrive path, e.g. `Ben Chan/templates` (required if `remote_docid` omitted) |
| `remote_docid` | `str \| None` | `None` | eDrive folder doc ID (required if `remote_path` omitted) |
| `ondup` | `int` | `3` | Duplicate handling (`3` = overwrite) |
| `create_share_link` | `bool` | `True` | Create/reuse permanent share link |

### `UploadResult`

| Field | Type | Description |
|-------|------|-------------|
| `share_url` | `str` | Permanent share link (`https://edrive.../link/<id>`) |
| `share_id` | `str` | Share link ID |
| `share_link_created` | `bool` | `True` if newly created, `False` if reused |
| `local_path` | `str` | Uploaded local path |
| `remote_path` | `str` | eDrive path or docid used |
| `remote_folder_name` | `str` | Final folder name |
| `remote_folder_docid` | `str` | Final folder doc ID |
| `remote_parent_docid` | `str` | Parent doc ID |
| `uploaded_files` | `list[dict]` | Per-file upload info |
| `created_dirs` | `list[dict]` | Subdirectories created during upload |

`result.to_dict()` returns a JSON-serializable dict.

### `EdriveSession`

Context manager returned by `login()`. Holds the authenticated session (`username`, `access_token`, etc.).
