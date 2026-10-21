import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.config import load_config


class EmailConfigTests(unittest.TestCase):
    def load_settings(self, settings, env=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config.json").write_text(json.dumps(settings), encoding="utf-8")
            (root / ".env").write_text("EMAIL_RECEIVER=legacy@example.com\n", encoding="utf-8")
            with patch("pipeline.config.PROJECT_ROOT", root), patch.dict(os.environ, env or {}, clear=True):
                return load_config(email_only=True)

    def test_json_recipients_override_environment_and_accept_lists_or_strings(self):
        for addresses in ([" first@example.com ", "", "second@example.com"], " first@example.com, , second@example.com "):
            with self.subTest(addresses=addresses):
                cfg = self.load_settings({
                    "email_receiver": addresses,
                    "email_cc": addresses,
                    "email_bcc": addresses,
                }, env={"EMAIL_RECEIVER": "exported@example.com"})
                for key in ("email_receiver", "email_cc", "email_bcc"):
                    self.assertEqual(cfg[key], ["first@example.com", "second@example.com"])

    def test_missing_json_receiver_uses_legacy_env_and_empty_cc_bcc(self):
        cfg = self.load_settings({})
        self.assertEqual(cfg["email_receiver"], ["legacy@example.com"])
        self.assertEqual(cfg["email_cc"], [])
        self.assertEqual(cfg["email_bcc"], [])

    def test_explicit_empty_json_recipients_disable_environment_fallback(self):
        for value in ([], "", None):
            with self.subTest(value=value):
                cfg = self.load_settings({"email_receiver": value, "email_cc": value, "email_bcc": value})
                self.assertEqual(cfg["email_receiver"], [])
                self.assertEqual(cfg["email_cc"], [])
                self.assertEqual(cfg["email_bcc"], [])
