import io
import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime
from unittest.mock import patch

from pipeline.cli import build_arg_parser, load_or_build_cards
from pipeline.evidence import inspect_existing_evidence, write_evidence
from pipeline.output import apply_run_output_paths, report_date_prefix
from pipeline.transfer import safe_extract_transfer_zip


class PipelineTests(unittest.TestCase):
    def candidate(self, identifier):
        return {"cnvd_id": identifier, "search_id": identifier, "title": identifier, "summary": "", "solution": "", "doc": {"details": {"cnvd": {}}}}

    def test_cli_always_uses_the_repository_config(self):
        parser = build_arg_parser()
        self.assertFalse(any(action.dest == "config" for action in parser._actions))
        with io.StringIO() as stderr, unittest.mock.patch("sys.stderr", stderr), self.assertRaises(SystemExit):
            parser.parse_args(["--config", "other.json"])

    def test_cache_reuses_valid_cards_and_filters_stale_data(self):
        candidate = self.candidate("CNVD-1")
        payload = {"search_results": [{"cnvd_id": "CNVD-1"}, {"cnvd_id": "CNVD-stale"}], "source_evidence_cards": [{"cnvd_id": "CNVD-1"}], "vulnerability_cards": [{"cnvd_id": "CNVD-1", "title": {"zh": "T", "en": ""}, "what_happened": {"zh": "description", "en": ""}, "why_matters": {"zh": "", "en": ""}, "how_to_respond": {"zh": "fix", "en": ""}}]}
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as evidence_file:
            json.dump(payload, evidence_file)
            evidence_file.flush()
            state = inspect_existing_evidence(evidence_file.name, [candidate])

        self.assertEqual([card["cnvd_id"] for card in state["cached_cards"]], ["CNVD-1"])
        self.assertFalse(state["missing_candidates"])
        self.assertEqual(state["search_results"], [{"cnvd_id": "CNVD-1"}])

    def test_cache_builds_only_missing_cards_and_rewrites_complete_payload(self):
        existing, missing = self.candidate("CNVD-1"), self.candidate("CNVD-2")
        payload = {"search_results": [], "source_evidence_cards": [], "vulnerability_cards": [{"cnvd_id": "CNVD-1", "title": {"zh": "CNVD-1", "en": ""}, "what_happened": {"zh": "cached", "en": ""}, "why_matters": {"zh": "", "en": ""}, "how_to_respond": {"zh": "fix", "en": ""}}]}
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as evidence_file:
            json.dump(payload, evidence_file)
            evidence_file.flush()
            result = [{"cnvd_id": "CNVD-2", "candidate_id": "CNVD-2"}]
            evidence = [{"cnvd_id": "CNVD-2", "task_type": "what_happened", "what_happened": "new", "confidence": "high", "references": []}]
            with patch("pipeline.cli.search_mod.search_candidates", return_value=result) as search, patch("pipeline.cli.extract_evidence_cards", return_value=evidence) as extract:
                cards, search_results, evidence_cards = load_or_build_cards({"use_existing_evidence_json": True, "evidence_json": evidence_file.name}, [existing, missing])
            write_evidence(evidence_file.name, [existing, missing], search_results, evidence_cards, cards)
            evidence_file.seek(0)
            rewritten = json.load(evidence_file)

        search.assert_called_once_with([missing], unittest.mock.ANY)
        extract.assert_called_once_with([missing], result, unittest.mock.ANY)
        self.assertEqual([card["cnvd_id"] for card in cards], ["CNVD-1", "CNVD-2"])
        self.assertEqual({card["cnvd_id"] for card in rewritten["vulnerability_cards"]}, {"CNVD-1", "CNVD-2"})

    def test_output_dates_and_transfer_extraction_are_safe(self):
        cards = [{"source": "cnnvd", "doc": {"details": {"cnnvd": {"publishDate": "2026-06-30"}}}}, {"source": "cnnvd", "doc": {"details": {"cnnvd": {"publishDate": "2026-07-06"}}}}]
        self.assertEqual(report_date_prefix(cards), "2026.06.30-07.06")
        with tempfile.TemporaryDirectory() as output_root:
            cfg = {"output_root": output_root, "output_docx": "report.docx", "output_weekly_excel": "weekly.xlsx", "output_date_prefix": True}
            apply_run_output_paths(cfg, cards, datetime(2026, 7, 6, 17, 30))
            self.assertTrue(cfg["output_docx"].endswith("20260706_173000/2026.06.30-07.06_report.docx"))
            bad_zip = io.BytesIO()
            with zipfile.ZipFile(bad_zip, "w") as archive:
                archive.writestr("../escape.txt", "bad")
            with self.assertRaises(ValueError):
                safe_extract_transfer_zip(bad_zip.getvalue(), output_root, "20260706_173000")
