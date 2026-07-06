import argparse
import json
import logging
import sys
import tempfile
from datetime import datetime

from pipeline.config import load_config, normalize_search_provider
from pipeline.constants import DEFAULT_CONFIG
from pipeline.dependencies import check_dependencies, setup_logging
from pipeline.docx_report import build_docx
from pipeline.evidence import (
    extract_evidence_cards,
    load_existing_evidence,
    merge_cards,
    write_evidence,
)
from pipeline.excel_report import build_excel, build_weekly_excel
from pipeline.formatting import category, excel_row, weekly_row, word_rows
from pipeline.mailer import require_email_config, send_report_email
from pipeline.mongo import candidate_from_cnnvd_doc, query_cnvd, query_cnvd_by_scrape_days
from pipeline.vuln_match import load_filtered_candidates, self_test as vuln_match_self_test
from pipeline.output import apply_dated_output_path, apply_dated_output_paths, apply_run_output_paths, report_date_prefix
from pipeline import search as search_mod
from pipeline.search import parse_firecrawl_results, queries_for_candidate, web_search
from pipeline.utils import norm_cnvd

log = logging.getLogger(__name__)


def self_test():
    assert norm_cnvd("cnvd:2026-24916") == "CNVD-2026-24916"
    c1 = {"cnvd_id": "CNVD-2026-1", "cve_id": "CVE-2026-1", "search_id": "CVE-2026-1", "title": "T"}
    c2 = {"cnvd_id": "CNVD-2026-2", "cve_id": None, "search_id": "CNVD-2026-2", "title": "T"}
    assert "CVE-2026-1" in queries_for_candidate(c1)["what_happened"][0]
    assert "CNVD-2026-2" in queries_for_candidate(c2)["how_to_respond"][0]
    card = {"cnvd_id": "CNVD-1", "cve_id": None, "title": "信息泄露", "what_happened": "敏感信息泄露", "how_to_respond": "修复", "affected_products": ["Microsoft Excel 2016"], "affected_versions": [], "doc": {"details": {"cnvd": {}}}}
    assert excel_row(card)[:4] == ["-", "Microsoft Excel 2016", "2016", "CNVD-1"]
    card["cluster_label"] = "Microsoft Excel"
    assert excel_row(card)[0] == "Microsoft Excel"
    assert word_rows(card, "zh")[2][1] == "Microsoft Excel"
    card["cluster_label"] = ""
    assert excel_row(card)[-1] == "修复"
    assert len(excel_row(card)) == 8
    assert weekly_row(card)[1] == ""
    cnnvd_doc = {"code": "2026-32651935", "severity": "High", "details": {"cnnvd": {"cnnvdId": "CNNVD-2026-32651935", "vulName": "T", "cveId": "CVE-2026-1", "vendorName": "V", "productName": "P", "publishDate": "2026-07-01"}}}
    cnnvd = candidate_from_cnnvd_doc(cnnvd_doc)
    assert cnnvd["cnvd_id"] == "CNNVD-2026-32651935" and cnnvd["cve_id"] == "CVE-2026-1"
    assert cnnvd["affected_products"] == ["V", "P"] and cnnvd["source"] == "cnnvd"
    assert word_rows({**cnnvd, "what_happened": "", "why_matters": "", "how_to_respond": ""}, "zh")[1][2] == "CNNVD编号"
    cfg = load_config(DEFAULT_CONFIG)
    assert cfg["search_provider"] in ("searxng", "firecrawl")
    assert normalize_search_provider("firewcrawl") == "firecrawl"
    try:
        normalize_search_provider("tavily")
        raise AssertionError("tavily should be rejected")
    except SystemExit:
        pass
    parsed = parse_firecrawl_results({"success": True, "data": {"web": [{"url": "https://example.com", "title": "T", "description": "D", "markdown": "M", "position": 2}]}})
    assert parsed[0]["source_api"] == "firecrawl" and parsed[0]["snippet"] == "D" and parsed[0]["page_content"] == "M"
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as f:
        json.dump({"vulnerability_cards": []}, f)
        f.flush()
        assert load_existing_evidence(f.name, []) is None
    original_searxng, original_firecrawl = search_mod.searxng_search, search_mod.firecrawl_search
    try:
        search_mod.searxng_search = lambda *args: []
        search_mod.firecrawl_search = lambda cfg, query: [{"url": "u", "title": query, "snippet": query, "page_content": query, "score": 0, "source_api": "firecrawl", "content_hash": "h"}]
        hit = web_search({"search_provider": "searxng", "searxng_base_url": "x", "searxng_max_results": 1, "search_fallback_firecrawl": True, "firecrawl_api_key": "fc-test"}, "CVE-1")
        assert hit[0]["source_api"] == "firecrawl"
    finally:
        search_mod.searxng_search, search_mod.firecrawl_search = original_searxng, original_firecrawl
    assert category(card) == "信息泄露"
    dated_cards = [
        {"source": "cnnvd", "doc": {"details": {"cnnvd": {"publishDate": "2026-06-30"}}}},
        {"source": "cnnvd", "doc": {"details": {"cnnvd": {"publishDate": "2026-07-06"}}}},
    ]
    assert report_date_prefix(dated_cards) == "2026.06.30-07.06"
    assert apply_dated_output_path("2026.06.30-07.06", "周報.docx") == "2026.06.30-07.06_周報.docx"
    dated_cfg = {
        "output_docx": "周報.docx",
        "output_excel": "周報.xlsx",
        "output_weekly_excel": "本周重要漏洞实例情况.xlsx",
        "output_date_prefix": True,
    }
    apply_dated_output_paths(dated_cfg, dated_cards)
    assert dated_cfg["output_weekly_excel"] == "2026.06.30-07.06_本周重要漏洞实例情况.xlsx"
    run_cfg = {
        "output_docx": "周報.docx",
        "output_excel": "周報.xlsx",
        "output_weekly_excel": "本周重要漏洞实例情况.xlsx",
        "output_date_prefix": True,
        "output_root": tempfile.mkdtemp(),
    }
    apply_run_output_paths(run_cfg, dated_cards, datetime(2026, 7, 6, 17, 30, 0))
    assert run_cfg["output_dir"].endswith("20260706_173000")
    assert run_cfg["output_docx"].endswith("20260706_173000/2026.06.30-07.06_周報.docx")
    try:
        require_email_config({"SMTP_HOST": "smtp.example.com", "SMTP_USERNAME": "sender@example.com"})
        raise AssertionError("missing email_receiver should be rejected")
    except ValueError as exc:
        assert "email_receiver" in str(exc)
    sent = {}
    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent["host"] = host
            sent["port"] = port
            sent["timeout"] = timeout
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def starttls(self):
            sent["tls"] = True
        def login(self, username, password):
            sent["login"] = (username, password)
        def send_message(self, message):
            sent["message"] = message
    with tempfile.NamedTemporaryFile("wb") as a, tempfile.NamedTemporaryFile("wb") as b, tempfile.NamedTemporaryFile("wb") as c:
        for f in (a, b, c):
            f.write(b"x")
            f.flush()
        send_report_email(
            {
                "email_receiver": "receiver@example.com",
                "SMTP_HOST": "smtp.example.com",
                "SMTP_PORT": 2525,
                "SMTP_USERNAME": "sender@example.com",
                "SMTP_PASSWORD": "secret",
                "SMTP_FROM": "",
                "SMTP_USE_TLS": True,
                "SMTP_USE_SSL": False,
            },
            [a.name, b.name, c.name],
            smtp_factory=FakeSMTP,
        )
    assert sent["message"]["To"] == "receiver@example.com"
    assert len(list(sent["message"].iter_attachments())) == 3
    vuln_match_self_test()
    print("self-test ok")


def main():
    parser = argparse.ArgumentParser(description="Generate CNVD-first evidence-card DOCX and XLSX reports.")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="config JSON path")
    parser.add_argument("--self-test", action="store_true", help="run local assertions without MongoDB, SearXNG, or AI")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return

    setup_logging()
    check_dependencies()
    log.info("Starting CNVD report pipeline (config=%s)", args.config)
    cfg = load_config(args.config)
    try:
        require_email_config(cfg)
    except ValueError as exc:
        sys.exit(str(exc))
    log.info(
        "Config: lang=%s, scrape_days=%s, cnvd_ids=%s, use_filtered_vuln_ids=%s, use_existing_evidence_json=%s",
        cfg["lang"],
        cfg.get("scrape_days"),
        len(cfg.get("cnvd_ids") or []),
        cfg.get("use_filtered_vuln_ids"),
        cfg.get("use_existing_evidence_json"),
    )

    if cfg.get("use_filtered_vuln_ids"):
        candidates, stats = load_filtered_candidates(cfg)
        log.info(
            "Shortlist: marked=%d, after_cluster_cap=%d, selected=%d",
            stats["marked"],
            stats["after_cluster_cap"],
            len(candidates),
        )
    elif cfg.get("cnvd_ids"):
        candidates = query_cnvd(cfg["cnvd_ids"])
    else:
        candidates = query_cnvd_by_scrape_days(cfg["scrape_days"])
    cards = load_existing_evidence(cfg["evidence_json"], candidates) if cfg.get("use_existing_evidence_json") else None
    if cards is None:
        search_results = search_mod.search_candidates(candidates, cfg)
        if not search_results:
            sys.exit("No relevant search results found.")
        evidence_cards = extract_evidence_cards(candidates, search_results, cfg)
        cards = merge_cards(candidates, evidence_cards)
        write_evidence(cfg["evidence_json"], candidates, search_results, evidence_cards, cards)

    output_dir = apply_run_output_paths(cfg, cards)
    log.info("Output folder: %s", output_dir)
    log.info("Output files: %s, %s, %s", cfg["output_docx"], cfg["output_excel"], cfg["output_weekly_excel"])
    build_docx(cards, cfg)
    build_excel(cards, cfg)
    build_weekly_excel(cards, cfg)
    paths = [cfg["output_docx"], cfg["output_excel"], cfg["output_weekly_excel"]]
    send_report_email(cfg, paths, f"CNVD report files: {report_date_prefix(cards)}")
    log.info("Email sent to %s", cfg["email_receiver"])
    log.info("Done. Outputs: %s, %s, %s", *paths)
