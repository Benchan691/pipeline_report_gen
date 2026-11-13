import unittest
from copy import deepcopy

from pipeline.constants import LOCALES
from pipeline.formatting import cve_text, link_for, weekly_row, word_rows


class ReportFormattingTests(unittest.TestCase):
    def test_cve_selection_prefers_primary_then_list_then_source_document(self):
        cases = [
            ({"cve_id": "CVE-2026-3000", "cve_ids": ["CVE-2026-1000", "CVE-2026-2000"],
              "doc": {"cve_ids": ["CVE-2026-4000"]}}, "CVE-2026-3000"),
            ({"cve_id": "cve-2026-3000, CVE-2026-2000"}, "CVE-2026-3000"),
            ({"cve_id": "-", "cve_ids": ["unknown", "cve-2026-1000", "CVE-2026-2000"],
              "doc": {"cve_ids": ["CVE-2026-4000"]}}, "CVE-2026-1000"),
            ({"cve_id": None, "cve_ids": "CVE-2026-1000\nCVE-2026-2000"}, "CVE-2026-1000"),
            ({"cve_ids": [], "doc": {"cve_ids": ["CVE-2026-4000", "CVE-2026-5000"]}}, "CVE-2026-4000"),
            ({"cve_id": "not available", "cve_ids": ["-"],
              "doc": {"source": {"provider": "github_advisory"}, "details": {"github_advisory": {
                  "identifiers": [{"type": "CVE", "value": "CVE-2026-4000"},
                                  {"type": "CVE", "value": "CVE-2026-5000"}],
              }}}}, "CVE-2026-4000"),
        ]
        for card, expected in cases:
            with self.subTest(card=card):
                original = deepcopy(card)
                self.assertEqual(cve_text(card), expected)
                self.assertEqual(weekly_row(card)[2], expected)
                for lang in ("zh", "en"):
                    self.assertEqual(word_rows(card, lang)[1][1], expected)
                self.assertEqual(link_for(card), f"https://nvd.nist.gov/vuln/detail/{expected}")
                self.assertEqual(card, original)

    def test_missing_cve_keeps_placeholder_and_reference_link_fallback(self):
        for card in ({}, {"cve_id": "-", "cve_ids": ["unknown"], "doc": {"cve_id": "N/A"}}):
            with self.subTest(card=card):
                self.assertEqual(cve_text(card), "-")
                self.assertEqual(weekly_row(card)[2], "-")
                self.assertEqual(link_for(card), "-")
                for lang in ("zh", "en"):
                    self.assertEqual(word_rows(card, lang)[1][1], "-")
                with_reference = {**card, "references": ["https://example.test/advisory"]}
                self.assertEqual(link_for(with_reference), "https://example.test/advisory")

    def test_word_reference_limits_for_zero_one_five_and_more_links(self):
        urls = [f"https://example.test/security/advisory-{index}/complete-details" for index in range(7)]
        for count in (0, 1, 5, 6, 7):
            with self.subTest(count=count):
                card = {"references": urls[:count]}
                original = deepcopy(card)
                for lang in ("zh", "en"):
                    expected = "\n".join(urls[:min(count, 5)]) or "-"
                    self.assertEqual(word_rows(card, lang)[6][0], LOCALES[lang]["labels"]["ref"] + expected)
                self.assertEqual(card, original)

    def test_reference_deduplication_precedes_limit_and_keeps_full_urls_in_order(self):
        urls = [f"https://example.test/security/advisory-{index}/full-details-with-a-long-path" for index in range(7)]
        card = {
            "references": ["", urls[0], " " + urls[0] + " ", urls[1], urls[2], urls[1], *urls[3:]],
            "how_to_respond": {"zh": urls[6], "en": urls[6]},
        }
        original = deepcopy(card)
        for lang in ("zh", "en"):
            rows = word_rows(card, lang)
            self.assertEqual(rows[6][0], LOCALES[lang]["labels"]["ref"] + "\n".join(urls[:5]))
            self.assertEqual(rows[7][0], LOCALES[lang]["labels"]["patch"] + urls[6])
        self.assertEqual(card, original)


if __name__ == "__main__":
    unittest.main()
