import argparse
import json
import logging
import os
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
from pipeline.excel_report import build_weekly_excel, row_height
from pipeline.formatting import category, excel_row, format_severity, localized, weekly_row, word_rows
from pipeline.edrive_upload import upload_output_folder_or_exit
from pipeline.email_send import require_email_config, send_report_email
from report_email import load_email_config
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
from pipeline.transfer import (
    make_transfer_zip,
    matches_transfer_message,
    parse_transfer_subject,
    receive_transfer,
    require_transfer_config,
    safe_extract_transfer_zip,
    send_transfer_from_folder,
    transfer_subject,
)
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
        "Output files: %s, %s, %s",
        cfg["output_docx"],
        cfg["output_docx_en"],
        cfg["output_weekly_excel"],
    )
    for lang in REPORT_LANGS:
        output_path = cfg["output_docx"] if lang == "zh" else cfg["output_docx_en"]
        build_docx(cards, cfg, lang, output_path)
    build_weekly_excel(cards, cfg)
    return [cfg["output_docx"], cfg["output_docx_en"], cfg["output_weekly_excel"]]


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
        "output_weekly_excel": "本周重要漏洞实例情况.xlsx",
        "output_date_prefix": True,
    }
    apply_dated_output_paths(dated_cfg, dated_cards)
    assert dated_cfg["output_weekly_excel"] == "2026.06.30-07.06_本周重要漏洞实例情况.xlsx"
    assert dated_cfg["output_docx_en"] == "2026.06.30-07.06_周報_en.docx"
    run_cfg = {
        "output_docx": "周報.docx",
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
        for name in ("2026.06.30-07.06_周報.docx", "2026.06.30-07.06_周報_en.docx", "2026.06.30-07.06_本周重要漏洞实例情况.xlsx"):
            with open(os.path.join(run_dir, name), "wb") as f:
                f.write(b"x")
        email_cfg = {"output_root": output_root}
        assert resolve_output_folder(email_cfg, "20260706_173000") == run_dir
        assert resolve_output_folder(email_cfg, run_dir) == run_dir
        paths = list_report_paths(run_dir)
        assert len(paths) == 3
        assert email_subject_from_paths(paths) == "2026年6月30日-7月6日漏洞報告文件"
    if load_workbook is not None:
        ws = load_workbook(cfg["weekly_excel_template"]).active
        long_weekly_values = ["", "", "CVE-1", "CNVD-1", "很长的影响产品文本" * 20, "漏洞", "严重"]
        assert row_height(ws, long_weekly_values) > 19.5
        with tempfile.TemporaryDirectory() as tmpdir:
            weekly_path = os.path.join(tmpdir, "weekly.xlsx")
            weekly_cards = [
                {"cnvd_id": "CNVD-1", "cve_id": "CVE-1", "affected_products": ["产品" * 60], "title": "漏洞一", "severity": "Critical", "doc": {"details": {"cnvd": {}}}},
                {"cnvd_id": "CNVD-2", "cve_id": "CVE-2", "affected_products": ["Product"], "title": "漏洞二", "severity": "High", "doc": {"details": {"cnvd": {}}}},
            ]
            build_weekly_excel(weekly_cards, {"weekly_excel_template": cfg["weekly_excel_template"], "output_weekly_excel": weekly_path})
            weekly_ws = load_workbook(weekly_path).active
            labels = [weekly_ws.cell(r.min_row, 1).value for r in sorted(weekly_ws.merged_cells.ranges, key=lambda item: item.min_row) if r.min_col == r.max_col == 1 and r.min_row >= 3]
            assert labels == ["CEC&CPC-infra", "TW", "EU", "IRD", "APP Team"]
            first_block = min((r for r in weekly_ws.merged_cells.ranges if r.min_col == r.max_col == 1 and r.min_row >= 3), key=lambda r: r.min_row)
            assert weekly_ws.cell(first_block.min_row, 2).value in (None, "")
            assert weekly_ws.cell(first_block.min_row, 3).value == "CVE-1"
            assert weekly_ws.cell(first_block.min_row + 1, 3).value == "CVE-2"
            assert weekly_ws.cell(first_block.min_row, 7).value == "严重"
            assert weekly_ws.row_dimensions[first_block.min_row].height > 19.5
    try:
        require_email_config(
            {
                "zimbra_host": "zmailbox.example.com",
                "zimbra_email": "sender@example.com",
                "zimbra_password": "secret",
            }
        )
        raise AssertionError("missing email_receiver should be rejected")
    except ValueError as exc:
        assert "EMAIL_RECEIVER" in str(exc)
    sent = []
    import pipeline.email_send as email_send_mod
    import pipeline.transfer as transfer_mod

    soap_calls = []
    original_login = transfer_mod.zimbra_login
    original_upload = transfer_mod._zimbra_upload
    original_soap = transfer_mod._soap_request
    try:
        transfer_mod.zimbra_login = lambda cfg: "token"
        transfer_mod._zimbra_upload = lambda host, token, filename, data, content_type="application/octet-stream": "aid-1"
        transfer_mod._soap_request = lambda host, body_xml, auth_token="": soap_calls.append((host, body_xml, auth_token))
        transfer_mod.zimbra_send_email(
            {"zimbra_host": "zmailbox.example.com", "zimbra_email": "sender@example.com", "zimbra_password": "secret"},
            "receiver@example.com",
            "Subject",
            "Body",
            [{"filename": "x.zip", "data": b"x", "content_type": "application/zip"}],
        )
    finally:
        transfer_mod.zimbra_login = original_login
        transfer_mod._zimbra_upload = original_upload
        transfer_mod._soap_request = original_soap
    assert "SendMsgRequest" in soap_calls[-1][1]
    assert 'attach aid="aid-1"' in soap_calls[-1][1]

    original_report_zimbra_send = email_send_mod.zimbra_send_email
    original_transfer_zimbra_send = transfer_mod.zimbra_send_email
    email_send_mod.zimbra_send_email = lambda cfg, to, subject, body, attachments=None: sent.append(
        {"to": to, "subject": subject, "body": body, "attachments": attachments or []}
    )
    transfer_mod.zimbra_send_email = email_send_mod.zimbra_send_email
    with tempfile.NamedTemporaryFile("wb") as a, tempfile.NamedTemporaryFile("wb") as b, tempfile.NamedTemporaryFile("wb") as c:
        for f in (a, b, c):
            f.write(b"x")
            f.flush()
        share_url = "https://edrive.example.com/share/abc123"
        try:
            send_report_email(
                {
                    "email_receiver": "receiver@example.com",
                    "zimbra_host": "zmailbox.example.com",
                    "zimbra_email": "sender@example.com",
                    "zimbra_password": "secret",
                },
                share_url,
            )
        finally:
            email_send_mod.zimbra_send_email = original_report_zimbra_send
    email_cfg = load_email_config()
    assert sent[-1]["to"] == "receiver@example.com"
    assert sent[-1]["subject"] == email_cfg.email_title
    body = sent[-1]["body"].strip()
    assert body.startswith(email_cfg.email_body.splitlines()[0])
    assert share_url in body
    assert len(sent[-1]["attachments"]) == 0
    assert parse_transfer_subject("PIPELINE_UPLOAD:20260706_173000") == "20260706_173000"
    assert matches_transfer_message(
        {"zimbra_email": "reports@example.com"},
        {"subject": transfer_subject("20260706_173000"), "from": "sender@example.com", "to": ["reports@example.com"]},
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        run_dir = os.path.join(tmpdir, "20260706_173000")
        os.makedirs(run_dir)
        with open(os.path.join(run_dir, "report.docx"), "wb") as f:
            f.write(b"x")
        zip_bytes = make_transfer_zip(run_dir)
        extracted = safe_extract_transfer_zip(zip_bytes, os.path.join(tmpdir, "output"), "20260706_173000")
        assert os.path.exists(os.path.join(extracted, "report.docx"))
        from io import BytesIO
        import zipfile

        bad_zip = BytesIO()
        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("../evil.txt", "x")
        try:
            safe_extract_transfer_zip(bad_zip.getvalue(), os.path.join(tmpdir, "bad"), "20260706_173000")
            raise AssertionError("unsafe transfer zip should be rejected")
        except ValueError:
            pass
        try:
            send_transfer_from_folder(
                {
                    "zimbra_host": "zmailbox.example.com",
                    "zimbra_email": "reports@example.com",
                    "zimbra_password": "secret",
                },
                run_dir,
            )
        finally:
            transfer_mod.zimbra_send_email = original_transfer_zimbra_send
        assert sent[-1]["to"] == "reports@example.com"
        assert sent[-1]["subject"] == "PIPELINE_UPLOAD:20260706_173000"
        assert len(sent[-1]["attachments"]) == 1
    vuln_match_self_test()
    print("self-test ok")


def send_email_from_folder(cfg, folder_path):
    try:
        require_email_config(cfg)
        folder = resolve_output_folder(cfg, folder_path)
        paths = list_report_paths(folder)
    except ValueError as exc:
        sys.exit(str(exc))
    subject = build_email_subject(paths=paths, folder=folder)
    result = upload_output_folder_or_exit(folder, required=True)
    send_report_email(cfg, result.share_url, subject)
    log.info("Email sent to %s with eDrive link (%s)", cfg["email_receiver"], folder)


def main():
    parser = argparse.ArgumentParser(description="Generate CNVD-first evidence-card DOCX and XLSX reports.")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="config JSON path")
    parser.add_argument("--self-test", action="store_true", help="run local assertions without MongoDB, SearXNG, or AI")
    parser.add_argument("--translate", action="store_true", help="translate existing evidence JSON to English fields only")
    parser.add_argument("--build-reports", action="store_true", help="build reports from existing evidence JSON without search or email")
    parser.add_argument(
        "--send-email",
        metavar="FOLDER",
        help="upload an existing folder to eDrive and email the share link (e.g. 20260706_173000)",
    )
    parser.add_argument(
        "--send-transfer",
        metavar="FOLDER",
        help="email an existing output folder zip to the configured Zimbra transfer mailbox",
    )
    parser.add_argument(
        "--receive-transfer",
        action="store_true",
        help="download the latest matching Zimbra transfer, upload to eDrive, email the share link, then delete it",
    )
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    actions = [args.translate, args.build_reports, bool(args.send_email), bool(args.send_transfer), args.receive_transfer]
    if sum(bool(action) for action in actions) > 1:
        sys.exit("Choose only one action: --translate, --build-reports, --send-email, --send-transfer, or --receive-transfer")

    setup_logging()
    if args.send_email:
        log.info("Sending report email from folder %s (config=%s)", args.send_email, args.config)
        cfg = load_config(args.config, email_only=True)
        send_email_from_folder(cfg, args.send_email)
        return
    if args.send_transfer:
        log.info("Sending transfer email from folder %s (config=%s)", args.send_transfer, args.config)
        cfg = load_config(args.config, email_only=True)
        try:
            send_transfer_from_folder(cfg, resolve_output_folder(cfg, args.send_transfer))
        except ValueError as exc:
            sys.exit(str(exc))
        return
    if args.receive_transfer:
        log.info("Receiving transfer email (config=%s)", args.config)
        cfg = load_config(args.config, email_only=True)
        try:
            folder = receive_transfer(cfg, lambda folder_name: send_email_from_folder(cfg, folder_name))
        except ValueError as exc:
            sys.exit(str(exc))
        if folder:
            log.info("Received transfer and sent eDrive notification for %s", folder)
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
            require_transfer_config(cfg)
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
        upload_output_folder_or_exit(cfg["output_dir"], required=False)
        log.info("Done. Outputs: %s, %s, %s", *paths)
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
    send_transfer_from_folder(cfg, cfg["output_dir"])
    log.info("Transfer email sent for output folder %s", cfg["output_dir"])
    log.info("Done. Outputs: %s, %s, %s", *paths)
