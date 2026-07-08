import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from pipeline.constants import DEFAULT_CONFIG
from pipeline.utils import norm_cnvd

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env_or_cfg(cfg, env_key, cfg_key, default=""):
    value = os.environ.get(env_key)
    if value is not None and str(value).strip() != "":
        return str(value).strip()
    if cfg_key in cfg and cfg.get(cfg_key) not in (None, ""):
        return cfg.get(cfg_key)
    return default


def _env_int_or_cfg(cfg, env_key, cfg_key, default):
    value = os.environ.get(env_key)
    if value is not None and str(value).strip() != "":
        return int(value)
    if cfg_key in cfg and cfg.get(cfg_key) not in (None, ""):
        return int(cfg.get(cfg_key))
    return default


def _env_bool_or_cfg(cfg, env_key, cfg_key, default):
    value = os.environ.get(env_key)
    if value is not None and str(value).strip() != "":
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if cfg_key in cfg and cfg.get(cfg_key) is not None:
        return bool(cfg.get(cfg_key))
    return default


def _apply_env_overrides(cfg):
    cfg["firecrawl_api_key"] = _env_or_cfg(cfg, "FIRECRAWL_API_KEY", "firecrawl_api_key")
    cfg["email_receiver"] = _env_or_cfg(cfg, "EMAIL_RECEIVER", "email_receiver")
    cfg["zimbra_host"] = _env_or_cfg(cfg, "ZIMBRA_HOST", "zimbra_host")
    cfg["zimbra_email"] = _env_or_cfg(cfg, "ZIMBRA_EMAIL", "zimbra_email")
    cfg["zimbra_password"] = _env_or_cfg(cfg, "ZIMBRA_PASSWORD", "zimbra_password")


def normalize_search_provider(provider):
    provider = str(provider or "").strip()
    if provider == "firewcrawl":
        provider = "firecrawl"
    if provider not in ("searxng", "firecrawl"):
        sys.exit("search_provider must be searxng or firecrawl")
    return provider


def load_config(path, email_only=False):
    load_dotenv(PROJECT_ROOT / ".env")
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if not email_only:
        required = ["output_docx", "docx_template", "ai_base_url", "ai_model", "evidence_json"]
        for key in required:
            if key not in cfg:
                sys.exit(f"Missing config key: {key}")
        if cfg.get("cnvd_ids"):
            cfg["cnvd_ids"] = [norm_cnvd(i) for i in cfg["cnvd_ids"]]
        elif cfg.get("scrape_days") is not None:
            cfg["scrape_days"] = int(cfg["scrape_days"])
        else:
            sys.exit("Missing config key: scrape_days (or provide cnvd_ids)")
    cfg.setdefault("search_provider", "searxng")
    cfg.setdefault("searxng_base_url", "")
    cfg.setdefault("searxng_max_results", 5)
    cfg.setdefault("firecrawl_base_url", "https://api.firecrawl.dev")
    cfg.setdefault("firecrawl_max_results", cfg["searxng_max_results"])
    cfg.setdefault("search_fallback_firecrawl", True)
    cfg.setdefault("weekly_excel_template", "templates/weekly_disclosure.xlsx")
    cfg.setdefault("output_weekly_excel", "weekly_disclosure.xlsx")
    cfg.setdefault("results_per_task", 1)
    cfg.setdefault("use_existing_evidence_json", False)
    cfg.setdefault("use_filtered_vuln_ids", False)
    cfg.setdefault("output_date_prefix", True)
    cfg.setdefault("output_root", "output")
    cfg.setdefault("zimbra_folder_id", "2")
    cfg.setdefault("zimbra_scan_limit", 10)
    _apply_env_overrides(cfg)
    if not email_only:
        cfg["search_provider"] = normalize_search_provider(cfg["search_provider"])
    return cfg
