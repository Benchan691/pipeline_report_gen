import argparse
import json
import logging
import os
import smtplib
import sys
import tempfile
from datetime import datetime

from pipeline.config import load_config, normalize_search_provider
from pipeline.constants import DEFAULT_CONFIG, REPORT_LANGS
from pipeline.dependencies import check_dependencies, load_workbook, setup_logging
from pipeline.docx_report import build_docx
from pipeline.evidence import (
    add_english_translations,
    cards_missing_english,
    extract_evidence_cards,
    load_existing_evidence,
    merge_cards,
    pick_for_lang,
    update_vulnerability_cards,
    write_evidence,
)
from pipeline.excel_report import build_excel, build_weekly_excel, row_height
from pipeline.formatting import category, excel_row, format_severity, localized, weekly_row, word_rows
from pipeline.mailer import require_email_config, send_report_email
from pipeline.mongo import candidate_from_cnnvd_doc, query_cnvd, query_cnvd_by_scrape_days
from pipeline.vuln_match import load_filtered_candidates, self_test as vuln_match_self_test
from pipeline.output import (
    apply_dated_output_path,
    apply_dated_output_paths,
    apply_run_output_paths,
    build_email_subject,
    docx_path_for_lang,
    email_subject_from_paths,
    list_report_paths,
    report_date_prefix,
    resolve_output_folder,
)
from pipeline import search as search_mod
from pipeline.search import parse_firecrawl_results, queries_for_candidate, web_search
from pipeline.utils import norm_cnvd

log = logging.getLogger(__name__)


def load_candidates_for_config(cfg):
    if cfg.get("use_filtered_vuln_ids"):
        candidates, stats = load_filtered_candidates(cfg)
        log.info(
            "Shortlist: marked=%d, after_cluster_cap=%d, selected=%d",
            stats["marked"],
            stats["after_cluster_cap"],
            len(candidates),
        )
        return candidates
    if cfg.get("cnvd_ids"):
        return query_cnvd(cfg["cnvd_ids"])
    return query_cnvd_by_scrape_days(cfg["scrape_days"])


def load_existing_cards_or_exit(cfg, candidates):
    cards = load_existing_evidence(cfg["evidence_json"], candidates)
    if cards is None:
        sys.exit(f"Existing evidence is empty or missing usable cards: {cfg['evidence_json']}")
    return cards


def maybe_translate_cards(cards, cfg, write_back=False):
    if not cards_missing_english(cards):
        return cards
    log.info("English translations missing; translating %d card(s)", len(cards))
    cards = add_english_translations(cards, cfg)
    if write_back:
        update_vulnerability_cards(cfg["evidence_json"], cards)
    return cards


def build_report_outputs(cfg, cards):
    output_dir = apply_run_output_paths(cfg, cards)
    log.info("Output folder: %s", output_dir)
    log.info(
        "Output files: %s, %s, %s, %s",
        cfg["output_docx"],
        cfg["output_docx_en"],
        cfg["output_excel"],
        cfg["output_weekly_excel"],
    )
    for lang in REPORT_LANGS:
        output_path = cfg["output_docx"] if lang == "zh" else cfg["output_docx_en"]
        build_docx(cards, cfg, lang, output_path)
    build_excel(cards, cfg)
    build_weekly_excel(cards, cfg)
    return [cfg["output_docx"], cfg["output_docx_en"], cfg["output_excel"], cfg["output_weekly_excel"]]


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
    assert format_severity("Critical", "zh") == "严重"
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
    assert docx_path_for_lang("2026.06.30-07.06_周報.docx", "en") == "2026.06.30-07.06_周報_en.docx"
    bilingual_card = {
        "cnvd_id": "CNVD-1",
        "title": {"zh": "信息泄露", "en": "Information disclosure"},
        "what_happened": {"zh": "敏感信息泄露", "en": "Sensitive data was exposed"},
        "why_matters": {"zh": "", "en": ""},
        "how_to_respond": {"zh": "修复", "en": "Apply the patch"},
        "affected_products": ["Microsoft Excel 2016"],
        "affected_versions": [],
        "doc": {"details": {"cnvd": {}}},
    }
    assert localized(bilingual_card, "title", "en") == "Information disclosure"
    assert word_rows(bilingual_card, "en")[0][0].startswith("Title:")
    evidence_cards = [
        {"cnvd_id": "CNVD-1", "task_type": "what_happened", "what_happened": "中文描述", "confidence": "high", "references": []},
    ]
    candidate = {"cnvd_id": "CNVD-1", "search_id": "CNVD-1", "title": "T", "summary": "", "solution": "", "doc": {"details": {"cnvd": {}}}}
    merged = merge_cards([candidate], evidence_cards)[0]
    assert merged["what_happened"]["zh"] == "中文描述"
    assert merged["what_happened"]["en"] == ""
    assert pick_for_lang(evidence_cards, "what_happened", "en") == "中文描述"
    assert cards_missing_english([merged]) is True
    original_call_ai = __import__("pipeline.evidence", fromlist=["call_ai"]).call_ai
    try:
        import pipeline.evidence as evidence_mod
        evidence_mod.call_ai = lambda *args, **kwargs: json.dumps(
            {
                "title": "Information disclosure",
                "what_happened": "English description",
                "why_matters": "",
                "how_to_respond": "Apply the patch",
            },
            ensure_ascii=False,
        )
        translated_cards = add_english_translations(
            [merged],
            {"ai_base_url": "http://localhost:8080", "ai_model": "test-model"},
        )
    finally:
        evidence_mod.call_ai = original_call_ai
    assert translated_cards[0]["what_happened"]["en"] == "English description"
    assert cards_missing_english(translated_cards) is False
    dated_cfg = {
        "output_docx": "周報.docx",
        "output_excel": "周報.xlsx",
        "output_weekly_excel": "本周重要漏洞实例情况.xlsx",
        "output_date_prefix": True,
    }
    apply_dated_output_paths(dated_cfg, dated_cards)
    assert dated_cfg["output_weekly_excel"] == "2026.06.30-07.06_本周重要漏洞实例情况.xlsx"
    assert dated_cfg["output_docx_en"] == "2026.06.30-07.06_周報_en.docx"
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
    assert run_cfg["output_docx_en"].endswith("20260706_173000/2026.06.30-07.06_周報_en.docx")
    with tempfile.TemporaryDirectory() as output_root:
        run_dir = os.path.join(output_root, "20260706_173000")
        os.makedirs(run_dir)
        for name in ("2026.06.30-07.06_周報.docx", "2026.06.30-07.06_周報.xlsx", "2026.06.30-07.06_本周重要漏洞实例情况.xlsx"):
            with open(os.path.join(run_dir, name), "wb") as f:
                f.write(b"x")
        email_cfg = {"output_root": output_root}
        assert resolve_output_folder(email_cfg, "20260706_173000") == run_dir
        assert resolve_output_folder(email_cfg, run_dir) == run_dir
        paths = list_report_paths(run_dir)
        assert len(paths) == 3
        assert email_subject_from_paths(paths) == "2026年6月30日-7月6日報告"
    if load_workbook is not None:
        ws = load_workbook(cfg["weekly_excel_template"]).active
        long_weekly_values = ["", "", "CVE-1", "CNVD-1", "很长的影响产品文本" * 20, "漏洞", "严重"]
        assert row_height(ws, long_weekly_values) > 19.5
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
    class FakeNoAuthSMTP(FakeSMTP):
        def login(self, username, password):
            raise smtplib.SMTPNotSupportedError("SMTP AUTH extension not supported by server.")
    with tempfile.NamedTemporaryFile("wb") as a, tempfile.NamedTemporaryFile("wb") as b, tempfile.NamedTemporaryFile("wb") as c:
        for f in (a, b, c):
            f.write(b"x")
            f.flush()
        send_report_email(
            {
                "email_receiver": "receiver@example.com",
                "email_title": "報告",
                "email_body": "附件為本周報告。",
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
        send_report_email(
            {
                "email_receiver": "receiver@example.com",
                "email_title": "報告",
                "email_body": "附件為本周報告。",
                "SMTP_HOST": "smtp.example.com",
                "SMTP_PORT": 2525,
                "SMTP_USERNAME": "sender@example.com",
                "SMTP_PASSWORD": "secret",
                "SMTP_FROM": "",
                "SMTP_USE_TLS": False,
                "SMTP_USE_SSL": False,
            },
            [a.name, b.name, c.name],
            smtp_factory=FakeNoAuthSMTP,
        )
    assert sent["message"]["To"] == "receiver@example.com"
    assert sent["message"]["Subject"] == "報告"
    assert sent["message"].get_body().get_content().strip() == "附件為本周報告。"
    assert len(list(sent["message"].iter_attachments())) == 3
    vuln_match_self_test()
    print("self-test ok")


def send_email_from_folder(cfg, folder_path):
    try:
        require_email_config(cfg)
        folder = resolve_output_folder(cfg, folder_path)
        paths = list_report_paths(folder)
    except ValueError as exc:
        sys.exit(str(exc))
    subject = build_email_subject(cfg, paths=paths, folder=folder)
    send_report_email(cfg, paths, subject)
    log.info("Email sent to %s (%d files from %s)", cfg["email_receiver"], len(paths), folder)
    log.info("Attached: %s", ", ".join(os.path.basename(path) for path in paths))


def main():
    parser = argparse.ArgumentParser(description="Generate CNVD-first evidence-card DOCX and XLSX reports.")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="config JSON path")
    parser.add_argument("--self-test", action="store_true", help="run local assertions without MongoDB, SearXNG, or AI")
    parser.add_argument("--translate", action="store_true", help="translate existing evidence JSON to English fields only")
    parser.add_argument("--build-reports", action="store_true", help="build reports from existing evidence JSON without search or email")
    parser.add_argument(
        "--send-email",
        metavar="FOLDER",
        help="email .docx/.xlsx report files from an existing folder under output_root (e.g. 20260706_173000)",
    )
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.translate and args.build_reports:
        sys.exit("--translate and --build-reports cannot be used together")
    if args.translate and args.send_email:
        sys.exit("--translate cannot be used with --send-email")
    if args.build_reports and args.send_email:
        sys.exit("--build-reports cannot be used with --send-email")

    setup_logging()
    if args.send_email:
        log.info("Sending report email from folder %s (config=%s)", args.send_email, args.config)
        cfg = load_config(args.config, email_only=True)
        send_email_from_folder(cfg, args.send_email)
        return

    cfg = load_config(args.config)
    if args.translate:
        log.info("Translating evidence JSON (config=%s)", args.config)
    elif args.build_reports:
        check_dependencies()
        log.info("Building reports from existing evidence (config=%s)", args.config)
    else:
        check_dependencies()
        log.info("Starting CNVD report pipeline (config=%s)", args.config)
        try:
            require_email_config(cfg)
        except ValueError as exc:
            sys.exit(str(exc))
    log.info(
        "Config: scrape_days=%s, cnvd_ids=%s, use_filtered_vuln_ids=%s, use_existing_evidence_json=%s",
        cfg.get("scrape_days"),
        len(cfg.get("cnvd_ids") or []),
        cfg.get("use_filtered_vuln_ids"),
        cfg.get("use_existing_evidence_json"),
    )
    candidates = load_candidates_for_config(cfg)
    if args.translate:
        cards = load_existing_cards_or_exit(cfg, candidates)
        cards = maybe_translate_cards(cards, cfg, write_back=True)
        log.info("Evidence translation updated: %s", cfg["evidence_json"])
        return
    if args.build_reports:
        cards = load_existing_cards_or_exit(cfg, candidates)
        cards = maybe_translate_cards(cards, cfg, write_back=True)
        paths = build_report_outputs(cfg, cards)
        log.info("Done. Outputs: %s, %s, %s, %s", *paths)
        return

    cards = load_existing_evidence(cfg["evidence_json"], candidates) if cfg.get("use_existing_evidence_json") else None
    if cards is None:
        search_results = search_mod.search_candidates(candidates, cfg)
        if not search_results:
            sys.exit("No relevant search results found.")
        evidence_cards = extract_evidence_cards(candidates, search_results, cfg)
        cards = merge_cards(candidates, evidence_cards)
        cards = add_english_translations(cards, cfg)
        write_evidence(cfg["evidence_json"], candidates, search_results, evidence_cards, cards)
    else:
        cards = maybe_translate_cards(cards, cfg, write_back=True)

    paths = build_report_outputs(cfg, cards)
    send_report_email(cfg, paths, build_email_subject(cfg, cards=cards))
    log.info("Email sent to %s", cfg["email_receiver"])
    log.info("Done. Outputs: %s, %s, %s, %s", *paths)
