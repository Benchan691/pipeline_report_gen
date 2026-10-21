import io
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZipFile

from pipeline.cli import main, send_email_from_folder
from pipeline.transfer import make_transfer_zip, receive_transfer, transfer_subject
from zimbra_client import Attachment


class EmailDeliveryTests(unittest.TestCase):
    def config(self, output_root):
        return {
            "output_root": str(output_root),
            "zimbra_host": "zimbra.example",
            "zimbra_email": "sender@example.com",
            "zimbra_password": "secret",
            "email_receiver": "first@example.com, second@example.com",
            "email_title": "Weekly report",
            "email_body": "Report link below.",
        }

    def report_folder(self, root):
        folder = Path(root) / "20260706_173000"
        folder.mkdir(parents=True)
        (folder / "2026.06.30-07.06_report.docx").write_bytes(b"Word report")
        (folder / "weekly.xlsx").write_bytes(b"Excel report")
        (folder / "supplement").mkdir()
        (folder / "supplement" / "說明.txt").write_text("補充資料", encoding="utf-8")
        (folder / "~$report.docx").write_bytes(b"lock")
        (folder / "supplement" / "~$weekly.xlsx").write_bytes(b"lock")
        return folder

    def test_attachment_sends_complete_zip_to_recipients_without_edrive_or_bridge(self):
        with tempfile.TemporaryDirectory() as root:
            folder = self.report_folder(root)
            cfg = dict(self.config(root), email_delivery="attachment", email_cc="copy@example.com", email_bcc=["private@example.com"])
            with patch("pipeline.cli.ZimbraClient") as client_class, patch(
                "pipeline.cli.upload_output_folder_or_exit"
            ) as upload, patch("pipeline.transfer.publish_transfer_request") as publish:
                client = client_class.return_value.__enter__.return_value
                send_email_from_folder(cfg, folder.name)

            sent = client.send_message.call_args.kwargs
            self.assertEqual(sent["to"], ["first@example.com", "second@example.com"])
            self.assertEqual(sent["cc"], ["copy@example.com"])
            self.assertEqual(sent["bcc"], ["private@example.com"])
            self.assertEqual(sent["subject"], "2026年6月30日-7月6日Weekly report")
            self.assertIn("附件", sent["text"])
            self.assertNotIn("link", sent["text"])
            self.assertEqual(len(sent["attachments"]), 1)
            attachment = sent["attachments"][0]
            self.assertIsInstance(attachment, Attachment)
            self.assertEqual(attachment.filename, f"{folder.name}.zip")
            self.assertEqual(attachment.content_type, "application/zip")
            with ZipFile(io.BytesIO(attachment.data)) as archive:
                self.assertEqual(set(archive.namelist()), {
                    f"{folder.name}/2026.06.30-07.06_report.docx",
                    f"{folder.name}/weekly.xlsx",
                    f"{folder.name}/supplement/說明.txt",
                })
                self.assertEqual(archive.read(f"{folder.name}/supplement/說明.txt").decode(), "補充資料")
            self.assertTrue(folder.is_dir())
            upload.assert_not_called()
            publish.assert_not_called()

    def test_default_edrive_delivery_still_emails_share_link(self):
        with tempfile.TemporaryDirectory() as root:
            folder = self.report_folder(root)
            cfg = dict(self.config(root), email_cc=["copy@example.com"], email_bcc="private@example.com")
            with patch("pipeline.cli.ZimbraClient") as client_class, patch(
                "pipeline.cli.upload_output_folder_or_exit",
                return_value=SimpleNamespace(share_url="https://edrive.example/share"),
            ) as upload:
                send_email_from_folder(cfg, folder.name)
            upload.assert_called_once_with(str(folder), required=True)
            client_class.return_value.__enter__.return_value.send_message.assert_called_once_with(
                to=["first@example.com", "second@example.com"],
                cc=["copy@example.com"],
                bcc=["private@example.com"],
                subject="2026年6月30日-7月6日Weekly report",
                text="Report link below.\n\nhttps://edrive.example/share",
            )

    def test_cli_attachment_overrides_config_and_uses_custom_body(self):
        with tempfile.TemporaryDirectory() as root:
            folder = self.report_folder(root)
            cfg = dict(self.config(root), email_delivery="edrive", email_attachment_body="Reports attached.")
            with patch("pipeline.cli.setup_logging"), patch(
                "pipeline.cli.load_config", return_value=cfg
            ) as load, patch("pipeline.cli.ZimbraClient") as client_class, patch(
                "pipeline.cli.upload_output_folder_or_exit"
            ) as upload, patch("sys.argv", [
                "main.py", "--send-email", str(folder), "--email-delivery", "attachment",
            ]):
                main()
            load.assert_called_once_with(email_only=True)
            sent = client_class.return_value.__enter__.return_value.send_message.call_args.kwargs
            self.assertEqual(sent["text"], "Reports attached.")
            self.assertEqual(sent["attachments"][0].filename, f"{folder.name}.zip")
            upload.assert_not_called()

    def test_invalid_delivery_or_missing_recipient_fails_before_sending(self):
        for overrides, error in [
            ({"email_delivery": "invalid"}, "email_delivery must be"),
            ({"email_delivery": "attachment", "email_receiver": []}, "email_receiver"),
        ]:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as root:
                folder = self.report_folder(root)
                cfg = dict(self.config(root), **overrides)
                with patch("pipeline.cli.ZimbraClient") as client_class, patch(
                    "pipeline.cli.upload_output_folder_or_exit"
                ) as upload, self.assertRaisesRegex(SystemExit, error):
                    send_email_from_folder(cfg, folder.name)
                client_class.assert_not_called()
                upload.assert_not_called()

    def test_cc_or_bcc_only_delivery_is_supported_in_both_modes(self):
        for delivery in ("edrive", "attachment"):
            for recipient_key in ("email_cc", "email_bcc"):
                with self.subTest(delivery=delivery, recipient_key=recipient_key), tempfile.TemporaryDirectory() as root:
                    folder = self.report_folder(root)
                    cfg = dict(self.config(root), email_delivery=delivery, email_receiver=[])
                    cfg[recipient_key] = ["recipient@example.com"]
                    with patch("pipeline.cli.ZimbraClient") as client_class, patch(
                        "pipeline.cli.upload_output_folder_or_exit",
                        return_value=SimpleNamespace(share_url="https://edrive.example/share"),
                    ):
                        send_email_from_folder(cfg, folder.name)
                    sent = client_class.return_value.__enter__.return_value.send_message.call_args.kwargs
                    self.assertEqual(sent["to"], [])
                    self.assertEqual(sent["cc"], cfg.get("email_cc", []))
                    self.assertEqual(sent["bcc"], cfg.get("email_bcc", []))

    def test_full_pipeline_routes_config_cli_override_and_local_only(self):
        cases = [
            ({}, [], "transfer"),
            ({"email_delivery": "attachment"}, [], "attachment"),
            ({}, ["--email-delivery", "attachment"], "attachment"),
            ({"email_delivery": "attachment"}, ["--email-delivery", "edrive"], "transfer"),
            ({"email_delivery": "attachment", "email_receiver": []}, ["--local-only"], "local"),
        ]
        for overrides, args, expected in cases:
            with self.subTest(args=args, expected=expected), tempfile.TemporaryDirectory() as root, ExitStack() as stack:
                folder = self.report_folder(root)
                cfg = dict(self.config(root), evidence_json="unused.json", output_dir=str(folder), **overrides)
                stack.enter_context(patch("sys.argv", ["main.py", *args]))
                stack.enter_context(patch("pipeline.cli.load_config", return_value=cfg))
                for name in ("setup_logging", "check_ai_connectivity", "check_dependencies", "write_evidence"):
                    stack.enter_context(patch(f"pipeline.cli.{name}"))
                stack.enter_context(patch("pipeline.cli.load_candidates_for_config", return_value=[]))
                stack.enter_context(patch("pipeline.cli.load_or_build_cards", return_value=([], [], [])))
                stack.enter_context(patch("pipeline.cli.maybe_translate_cards", return_value=[]))
                stack.enter_context(patch("pipeline.cli.build_report_outputs", return_value=["zh.docx", "en.docx", "weekly.xlsx"]))
                transfer = stack.enter_context(patch("pipeline.cli.send_transfer_from_folder"))
                upload = stack.enter_context(patch("pipeline.cli.upload_output_folder_or_exit"))
                client_class = stack.enter_context(patch("pipeline.cli.ZimbraClient"))
                main()
                upload.assert_not_called()
                if expected == "transfer":
                    transfer.assert_called_once_with(cfg, str(folder))
                    client_class.assert_not_called()
                else:
                    transfer.assert_not_called()
                    if expected == "attachment":
                        client_class.return_value.__enter__.return_value.send_message.assert_called_once()
                    else:
                        client_class.assert_not_called()

    def test_received_attachment_is_cleaned_up_only_after_successful_send(self):
        for fail_send in (False, True):
            with self.subTest(fail_send=fail_send), tempfile.TemporaryDirectory() as root, ExitStack() as stack:
                folder = self.report_folder(Path(root) / "source")
                output_root = Path(root) / "received"
                cfg = dict(self.config(output_root), email_cc=["copy@example.com"], email_bcc=["private@example.com"])
                zip_bytes = make_transfer_zip(folder)
                stack.enter_context(patch("pipeline.cli.setup_logging"))
                stack.enter_context(patch("pipeline.cli.load_config", return_value=cfg))
                stack.enter_context(patch("sys.argv", ["main.py", "--receive-transfer", "--email-delivery", "attachment"]))
                client_class = stack.enter_context(patch("pipeline.cli.ZimbraClient"))
                client = client_class.return_value.__enter__.return_value
                if fail_send:
                    client.send_message.side_effect = RuntimeError("Send failed")
                transfer_class = stack.enter_context(patch("pipeline.transfer.ZimbraClient"))
                transfer_client = transfer_class.return_value.__enter__.return_value
                transfer_client.download_attachment.return_value = zip_bytes
                stack.enter_context(patch("pipeline.transfer._find_transfer_message", return_value=(
                    "message-1", None, Attachment(filename=f"{folder.name}.zip", part="2"),
                )))
                stack.enter_context(patch("pipeline.transfer.consume_transfer_requests", side_effect=(
                    lambda cfg, callback: callback(folder.name, transfer_subject(folder.name))
                )))
                upload = stack.enter_context(patch("pipeline.cli.upload_output_folder_or_exit"))
                if fail_send:
                    with self.assertRaisesRegex(RuntimeError, "Send failed"):
                        main()
                    self.assertTrue((output_root / folder.name).is_dir())
                    transfer_client.delete_message.assert_not_called()
                else:
                    main()
                    self.assertFalse((output_root / folder.name).exists())
                    transfer_client.delete_message.assert_called_once_with("message-1")
                    sent = client.send_message.call_args.kwargs
                    self.assertEqual(sent["attachments"][0].filename, f"{folder.name}.zip")
                    self.assertEqual(sent["cc"], ["copy@example.com"])
                    self.assertEqual(sent["bcc"], ["private@example.com"])
                upload.assert_not_called()

    def test_fake_receiver_checks_edrive_only_for_edrive_delivery(self):
        for delivery in ("edrive", "attachment"):
            with self.subTest(delivery=delivery), ExitStack() as stack:
                cfg = dict(self.config("output"), email_delivery=delivery)
                stack.enter_context(patch("pipeline.transfer.consume_transfer_requests", side_effect=(
                    lambda cfg, callback: callback("20260706_173000", "subject")
                )))
                stack.enter_context(patch("pipeline.transfer._process_transfer_message", side_effect=(
                    lambda cfg, folder, callback, subject: callback(folder)
                )))
                check = stack.enter_context(patch("pipeline.transfer.check_edrive_connectivity_or_exit"))
                delete = stack.enter_context(patch("pipeline.transfer.delete_received_output_folder"))
                deliver = unittest.mock.Mock()
                receive_transfer(cfg, deliver, fake=True)
                deliver.assert_not_called()
                delete.assert_not_called()
                if delivery == "edrive":
                    check.assert_called_once_with(required=True)
                else:
                    check.assert_not_called()
