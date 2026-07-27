import io
import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime
from unittest.mock import patch
from urllib.error import HTTPError

from pipeline.cli import build_arg_parser, load_or_build_cards
from pipeline.amqp import parse_transfer_request, transfer_request_payload
from pipeline.edrive_upload import check_edrive_connectivity
from pipeline.evidence import inspect_existing_evidence, write_evidence
from pipeline.output import apply_run_output_paths, report_date_prefix
from pipeline.transfer import make_test_transfer_folder, make_transfer_zip, safe_extract_transfer_zip
from plugin.zimbra.zimbra import soap_request


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
        cards = [
            {"source": "cnnvd", "doc": {"published_at": "2026-06-30T00:00:00Z", "details": {}}},
            {"source": "cnnvd", "doc": {"details": {"publishDate": "2026-07-06"}}},
        ]
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

    def test_soap_request_includes_zimbra_error_body(self):
        error = HTTPError("https://zimbra.example/service/soap", 500, "Server Error", None, io.BytesIO(b"<Fault>message too large</Fault>"))
        with patch("plugin.zimbra.zimbra.urllib.request.urlopen", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, r"500.*message too large"):
                soap_request("zimbra.example", "<SendMsgRequest/>")

    def test_transfer_request_payload_and_parser(self):
        payload = transfer_request_payload("20260706_173000")
        self.assertEqual(payload, {"folder": "20260706_173000", "subject": "PIPELINE_UPLOAD:20260706_173000"})
        folder, subject = parse_transfer_request(json.dumps(payload).encode("utf-8"))
        self.assertEqual(folder, "20260706_173000")
        self.assertEqual(subject, "PIPELINE_UPLOAD:20260706_173000")

    def test_check_edrive_connectivity_logs_in_without_upload(self):
        cfg = type("Cfg", (), {"username": "u", "password": "p", "remote_path": "Ben Chan/weekly-reports", "base_url": "https://edrive.example"})()
        with patch("pipeline.edrive_upload.load_edrive_config", return_value=cfg), patch("edrive.login") as login, patch(
            "edrive.list_owned_doc_libs", return_value=[{"name": "Ben Chan"}]
        ):
            login.return_value.__enter__.return_value = object()
            result = check_edrive_connectivity(required=True)
        self.assertEqual(result, cfg)
        login.assert_called_once_with("u", "p", "https://edrive.example")

    def test_fake_flag_requires_transfer_action(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--fake"])
        self.assertTrue(args.fake)
        with patch("pipeline.cli.setup_logging"), patch("sys.argv", ["main.py", "--fake"]):
            from pipeline.cli import main

            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertIn("--fake is only valid together with --receive-transfer or --send-transfer", str(ctx.exception))

        with patch("pipeline.cli.setup_logging"), patch("pipeline.cli.load_config"), patch("pipeline.cli.receive_transfer") as receive:
            with patch("sys.argv", ["main.py", "--receive-transfer", "--fake"]):
                from pipeline.cli import main

                main()
        receive.assert_called_once()
        self.assertTrue(receive.call_args.kwargs.get("fake"))

    def test_send_transfer_fake_builds_and_sends_test_zip(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--send-transfer", "--fake"])
        self.assertEqual(args.send_transfer, "")
        self.assertTrue(args.fake)

        with tempfile.TemporaryDirectory() as output_root:
            folder = make_test_transfer_folder(output_root, when=datetime(2026, 7, 27, 12, 0, 0))
            self.assertEqual(folder.name, "test_transfer_20260727_120000")
            self.assertTrue((folder / "TEST_TRANSFER.txt").is_file())
            zip_bytes = make_transfer_zip(folder)
            self.assertGreater(len(zip_bytes), 0)

        with patch("pipeline.cli.setup_logging"), patch("pipeline.cli.load_config", return_value={"output_root": "output"}), patch(
            "pipeline.cli.send_test_transfer", return_value="test_transfer_20260727_120000"
        ) as send_test:
            with patch("sys.argv", ["main.py", "--send-transfer", "--fake"]):
                from pipeline.cli import main

                main()
        send_test.assert_called_once()

        with patch("pipeline.cli.setup_logging"), patch("pipeline.cli.load_config", return_value={}), patch("sys.argv", ["main.py", "--send-transfer", "20260706_173000", "--fake"]):
            from pipeline.cli import main

            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertIn("does not take a folder", str(ctx.exception))

        with patch("pipeline.cli.setup_logging"), patch("pipeline.cli.load_config", return_value={}), patch("sys.argv", ["main.py", "--send-transfer"]):
            from pipeline.cli import main

            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertIn("requires a folder", str(ctx.exception))
