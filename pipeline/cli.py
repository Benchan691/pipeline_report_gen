import argparse
import json
import logging
import os
import sys
import tempfile
from datetime import datetime

from pipeline.config import load_config, normalize_search_provider, parse_email_list
from pipeline.constants import REPORT_LANGS
from pipeline.dependencies import check_dependencies, load_workbook, setup_logging
from pipeline.docx_report import build_docx
from pipeline.evidence import (
    add_english_translations,
    cached_card_is_usable,
    cards_missing_english,
    check_ai_connectivity,
    extract_evidence_cards,
    inspect_existing_evidence,
    load_existing_evidence,
    merge_cards,
    pick_for_lang,
    update_vulnerability_cards,
    write_evidence,
)
from pipeline.excel_report import build_weekly_excel, row_height
from pipeline.formatting import category, format_severity, localized, weekly_row, word_rows
from pipeline.edrive_upload import upload_output_folder_or_exit
from pipeline.mongo import candidate_from_cnnvd_doc, query_cnvd, query_cnvd_by_scrape_days
from pipeline.vuln_match import load_filtered_candidates
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
    title_date,
)
from pipeline import search as search_mod
from pipeline.search import parse_firecrawl_results, queries_for_candidate, web_search
from pipeline.transfer import (
    make_transfer_zip,
    matches_transfer_message,
    parse_transfer_subject,
    receive_transfer,
    require_zimbra_config,
    safe_extract_transfer_zip,
    send_transfer_from_folder,
    transfer_subject,
    zimbra_send_email,
)
from plugin.zimbra import zimbra as zimbra_mod
from pipeline.utils import norm_cnvd

log = logging.getLogger(__name__)


def load_candidates_for_config(cfg):
    if cfg.get("use_filtered_vuln_ids"):
        candidates, stats = load_filtered_candidates(cfg)
        log.info(
            "Shortlist: keyword_hits=%d, llm_rejected=%d, marked=%d, after_cluster_cap=%d, selected=%d",
            stats.get("keyword_hits", 0),
            stats.get("llm_rejected", 0),
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


def load_or_build_cards(cfg, candidates):
    if not cfg.get("use_existing_evidence_json"):
        search_results = search_mod.search_candidates(candidates, cfg)
        if not search_results:
            sys.exit("No relevant search results found.")
        evidence_cards = extract_evidence_cards(candidates, search_results, cfg)
        cards = merge_cards(candidates, evidence_cards)
        return cards, search_results, evidence_cards

    cache_state = inspect_existing_evidence(cfg["evidence_json"], candidates)
    cached_cards = list(cache_state["cached_cards"])
    missing_candidates = list(cache_state["missing_candidates"])
    search_results = list(cache_state["search_results"])
    evidence_cards = list(cache_state["source_evidence_cards"])
    if missing_candidates:
        new_search_results = search_mod.search_candidates(missing_candidates, cfg)
        if not new_search_results:
            sys.exit("No relevant search results found.")
        new_evidence_cards = extract_evidence_cards(missing_candidates, new_search_results, cfg)
        new_cards = merge_cards(missing_candidates, new_evidence_cards)
        cached_cards.extend(new_cards)
        search_results.extend(new_search_results)
        evidence_cards.extend(new_evidence_cards)
    cards_by_id = {card["cnvd_id"]: card for card in cached_cards}
    cards = [cards_by_id[candidate["cnvd_id"]] for candidate in candidates]
    return cards, search_results, evidence_cards


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


def build_link_body(body, link_url):
    text = str(body or "Report link below.").rstrip()
    link_url = str(link_url or "").strip()
    if not link_url:
        raise ValueError("Missing share URL for email")
    return f"{text}\n\n{link_url}"


def require_email_config(cfg):
    receivers = parse_email_list(cfg.get("email_receiver"))
    missing = []
    if not receivers:
        missing.append("EMAIL_RECEIVER in .env")
    try:
        require_zimbra_config(cfg)
    except ValueError as exc:
        missing.append(str(exc).replace("Missing transfer config: ", ""))
    if missing:
        raise ValueError("Missing email config: " + ", ".join(missing))


def send_report_email(cfg, share_url, subject=None):
    zimbra_send_email(
        cfg,
        parse_email_list(cfg.get("email_receiver")),
        subject or str(cfg.get("email_title") or "漏洞報告文件").strip(),
        build_link_body(cfg.get("email_body"), share_url),
    )


def send_email_from_folder(cfg, folder_path):
    try:
        require_email_config(cfg)
        folder = resolve_output_folder(cfg, folder_path)
        paths = list_report_paths(folder)
    except ValueError as exc:
        sys.exit(str(exc))
    subject = build_email_subject(paths=paths, folder=folder, cfg=cfg)
    result = upload_output_folder_or_exit(folder, required=True)
    send_report_email(cfg, result.share_url, subject)
    log.info(
        "Email sent to %s with eDrive link (%s)",
        ", ".join(parse_email_list(cfg.get("email_receiver"))),
        folder,
    )


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Generate CNVD-first evidence-card DOCX and XLSX reports.")
    parser.add_argument("--self-test", action="store_true", help="run the local test suite without MongoDB, SearXNG, or AI")
    parser.add_argument("--translate", action="store_true", help="translate existing evidence JSON to English fields only")
    parser.add_argument("--build-reports", action="store_true", help="build reports from existing evidence JSON without search or email")
    parser.add_argument(
        "--cluster-match",
        action="store_true",
        help="run software-cluster matching only (keyword + LLM); no search, evidence, or reports",
    )
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
    return parser


def exclusive_action_flags(args):
    return [
        args.translate,
        args.build_reports,
        args.cluster_match,
        bool(args.send_email),
        bool(args.send_transfer),
        args.receive_transfer,
    ]


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.self_test:
        from tests.run import main as run_tests

        run_tests()
        return
    actions = exclusive_action_flags(args)
    if sum(bool(action) for action in actions) > 1:
        sys.exit(
            "Choose only one action: --translate, --build-reports, --cluster-match, "
            "--send-email, --send-transfer, or --receive-transfer"
        )

    setup_logging()
    if args.send_email:
        log.info("Sending report email from folder %s", args.send_email)
        cfg = load_config(email_only=True)
        send_email_from_folder(cfg, args.send_email)
        return
    if args.send_transfer:
        log.info("Sending transfer email from folder %s", args.send_transfer)
        cfg = load_config(email_only=True)
        try:
            send_transfer_from_folder(cfg, resolve_output_folder(cfg, args.send_transfer))
        except ValueError as exc:
            sys.exit(str(exc))
        return
    if args.receive_transfer:
        log.info("Receiving transfer email")
        cfg = load_config(email_only=True)
        try:
            folder = receive_transfer(cfg, lambda folder_name: send_email_from_folder(cfg, folder_name))
        except ValueError as exc:
            sys.exit(str(exc))
        if folder:
            log.info("Received transfer and sent eDrive notification for %s", folder)
        return

    cfg = load_config()
    check_ai_connectivity(cfg)
    if args.translate:
        log.info("Translating evidence JSON")
    elif args.build_reports:
        check_dependencies()
        log.info("Building reports from existing evidence")
    elif args.cluster_match:
        log.info("Running cluster match only")
    else:
        check_dependencies()
        log.info("Starting CNVD report pipeline")
        try:
            require_zimbra_config(cfg)
        except ValueError as exc:
            sys.exit(str(exc))
    log.info(
        "Config: scrape_days=%s, cnvd_ids=%s, use_filtered_vuln_ids=%s, use_existing_evidence_json=%s",
        cfg.get("scrape_days"),
        len(cfg.get("cnvd_ids") or []),
        cfg.get("use_filtered_vuln_ids"),
        cfg.get("use_existing_evidence_json"),
    )
    if args.cluster_match:
        cfg["use_filtered_vuln_ids"] = True
        candidates, stats = load_filtered_candidates(cfg)
        log.info(
            "Shortlist: keyword_hits=%d, llm_rejected=%d, marked=%d, after_cluster_cap=%d, selected=%d",
            stats.get("keyword_hits", 0),
            stats.get("llm_rejected", 0),
            stats["marked"],
            stats["after_cluster_cap"],
            len(candidates),
        )
        log.info("Cluster match complete.")
        return
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

    cards, search_results, evidence_cards = load_or_build_cards(cfg, candidates)
    cards = maybe_translate_cards(cards, cfg)
    write_evidence(cfg["evidence_json"], candidates, search_results, evidence_cards, cards)

    paths = build_report_outputs(cfg, cards)
    send_transfer_from_folder(cfg, cfg["output_dir"])
    log.info("Transfer email sent for output folder %s", cfg["output_dir"])
    log.info("Done. Outputs: %s, %s, %s", *paths)
