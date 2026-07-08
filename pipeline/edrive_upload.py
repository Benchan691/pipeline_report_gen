import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class EdriveConfig:
    username: str
    password: str
    remote_path: str
    base_url: str


class EdriveConfigError(ValueError):
    pass


def load_edrive_config(project_root=None):
    root = Path(project_root or PROJECT_ROOT)
    load_dotenv(root / ".env")

    username = os.environ.get("EDRIVE_USERNAME", "").strip()
    password = os.environ.get("EDRIVE_PASSWORD", "").strip()
    remote_path = os.environ.get("EDRIVE_REMOTE_PATH", "").strip()
    base_url = os.environ.get("EDRIVE_BASE_URL", "").strip()
    if not username or not password or not remote_path or not base_url:
        return None
    return EdriveConfig(
        username=username,
        password=password,
        remote_path=remote_path,
        base_url=base_url,
    )


def upload_output_folder(output_dir, project_root=None, *, required=False):
    cfg = load_edrive_config(project_root)
    if cfg is None:
        if required:
            raise EdriveConfigError(
                "eDrive upload is required but not configured. "
                "Copy .env.example to .env and set EDRIVE_USERNAME, EDRIVE_PASSWORD, "
                "EDRIVE_REMOTE_PATH, and EDRIVE_BASE_URL."
            )
        log.info("eDrive upload skipped (not configured)")
        return None

    from edrive import login, upload_folder

    local_path = Path(output_dir).expanduser().resolve()
    remote_path = f"{cfg.remote_path.rstrip('/')}/{local_path.name}"
    log.info("Uploading %s to eDrive: %s", local_path, remote_path)
    with login(cfg.username, cfg.password, cfg.base_url) as session:
        result = upload_folder(session, local_path, remote_path)
    log.info("eDrive upload complete: %s share_url=%s", result.remote_path, result.share_url)
    return result


def upload_output_folder_or_exit(output_dir, project_root=None, *, required=False):
    try:
        return upload_output_folder(output_dir, project_root, required=required)
    except EdriveConfigError as exc:
        sys.exit(str(exc))
    except Exception as exc:
        log.error("eDrive upload failed: %s", exc)
        if required:
            sys.exit(f"eDrive upload failed: {exc}")
        raise
