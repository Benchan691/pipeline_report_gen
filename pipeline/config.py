import json
import sys

from pipeline.constants import DEFAULT_CONFIG
from pipeline.utils import norm_cnvd


def normalize_search_provider(provider):
    provider = str(provider or "").strip()
    if provider == "firewcrawl":
        provider = "firecrawl"
    if provider not in ("searxng", "firecrawl"):
        sys.exit("search_provider must be searxng or firecrawl")
    return provider


def load_config(path, email_only=False):
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if not email_only:
        required = ["output_docx", "output_excel", "docx_template", "excel_template", "ai_base_url", "ai_model", "evidence_json"]
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
    cfg.setdefault("firecrawl_api_key", "")
    cfg.setdefault("firecrawl_max_results", cfg["searxng_max_results"])
    cfg.setdefault("search_fallback_firecrawl", True)
    cfg.setdefault("weekly_excel_template", "templates/weekly_disclosure.xlsx")
    cfg.setdefault("output_weekly_excel", "weekly_disclosure.xlsx")
    cfg.setdefault("results_per_task", 1)
    cfg.setdefault("use_existing_evidence_json", False)
    cfg.setdefault("use_filtered_vuln_ids", False)
    cfg.setdefault("output_date_prefix", True)
    cfg.setdefault("output_root", "output")
    cfg.setdefault("email_receiver", "")
    cfg.setdefault("email_title", "報告")
    cfg.setdefault("email_body", "Generated report files are attached.")
    cfg.setdefault("SMTP_HOST", "")
    cfg.setdefault("SMTP_PORT", 587)
    cfg.setdefault("SMTP_USERNAME", "")
    cfg.setdefault("SMTP_PASSWORD", "")
    cfg.setdefault("SMTP_FROM", "")
    cfg.setdefault("SMTP_USE_TLS", True)
    cfg.setdefault("SMTP_USE_SSL", False)
    if not email_only:
        cfg["search_provider"] = normalize_search_provider(cfg["search_provider"])
    return cfg
