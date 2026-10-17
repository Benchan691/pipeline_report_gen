import copy
import json
import unittest
from unittest.mock import patch

from pipeline.formatting import weekly_row
from pipeline.report_identity import clean_product_name, enrich_report_identities


class ReportIdentityTests(unittest.TestCase):
    def card(self):
        return {
            "record_id": "msrc:1", "source": "msrc", "cve_ids": ["CVE-2026-1", "CVE-2026-2"],
            "title": {"zh": "Microsoft Office vulnerability", "en": "Microsoft Office vulnerability"},
            "vendors": [], "affected_products": ["Microsoft Office 2019 for 32-bit editions", "Microsoft Office LTSC 2024"],
            "cluster_label": "Microsoft Office", "affected_versions": ["2019", "2024"],
        }

    def test_ai_labels_are_batched_cached_and_preserve_source_details(self):
        cards = [self.card(), self.card()]
        cards[1]["record_id"] = "msrc:2"
        original = copy.deepcopy(cards)
        cfg = {"ai_base_url": "http://test", "ai_model": "test"}
        result = json.dumps({"items": [{"key": "0", "vendor": "Microsoft", "product": "Microsoft Office"}]})
        with patch("pipeline.report_identity.call_ai", return_value=result) as ai:
            enrich_report_identities(cards, cfg)
            enrich_report_identities(cards, cfg)
            self.assertEqual(ai.call_count, 1)
            self.assertFalse(ai.call_args.kwargs["enable_thinking"])
            self.assertEqual(len(json.loads(ai.call_args.args[3])["items"]), 1)
            cards[0]["affected_products"].append("Microsoft Office 2021")
            enrich_report_identities(cards, cfg)
            self.assertEqual(ai.call_count, 2)
        for card, source in zip(cards, original):
            self.assertEqual(weekly_row(card)[2:5], ["CVE-2026-1\nCVE-2026-2", "Microsoft", "Microsoft Office"])
            self.assertEqual(card["affected_versions"], source["affected_versions"])
            self.assertEqual(card["vendors"], source["vendors"])
            self.assertEqual(card["report_identity"]["method"], "ai")

    def test_invalid_lists_and_unsupported_names_use_source_fallback(self):
        cfg = {"ai_base_url": "http://test", "ai_model": "test"}
        for vendor, product in (("Microsoft", "Microsoft Office\nMicrosoft Teams"), ("Invented Vendor", "Microsoft Office")):
            with self.subTest(vendor=vendor, product=product):
                card = self.card()
                answer = json.dumps({"items": [{"key": "0", "vendor": vendor, "product": product}]})
                with patch("pipeline.report_identity.call_ai", return_value=answer):
                    enrich_report_identities([card], cfg)
                self.assertEqual(card["report_identity"]["method"], "source")
                self.assertEqual(weekly_row(card)[4], "Microsoft Office")

    def test_release_numbers_are_removed_and_brand_digits_are_preserved(self):
        self.assertEqual(clean_product_name("Microsoft SQL Server 2017 (CU 31)"), "Microsoft SQL Server")
        self.assertEqual(clean_product_name("Google Chrome 140.0.1"), "Google Chrome")
        self.assertEqual(clean_product_name("Windows 11"), "Windows")
        for name in ("Microsoft 365", "3CX", "OAuth2 Proxy", ""):
            self.assertEqual(clean_product_name(name), name)
