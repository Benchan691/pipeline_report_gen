import unittest

from pipeline.formatting import card_date, card_raw, word_rows
from pipeline.mongo import candidate_from_cnnvd_doc, candidate_from_doc, doc_cve_ids, provider_details


class MongoSchemaV2Tests(unittest.TestCase):
    def test_provider_details_supports_flat_v2_and_wrapped_v1(self):
        v2 = {"details": {"description": "flat", "affected_products": ["Chrome"]}}
        v1 = {"details": {"cnvd": {"description": "wrapped", "affected_products": ["Java"]}}}
        self.assertEqual(provider_details(v2, "cnvd")["description"], "flat")
        self.assertEqual(provider_details(v1, "cnvd")["description"], "wrapped")

    def test_candidate_from_cnvd_v2_document(self):
        doc = {
            "_id": "cnvd:2026-1000",
            "schema_version": 2,
            "code": "2026-1000",
            "title": "Chrome vulnerability",
            "severity": "High",
            "cve_ids": ["CVE-2026-1000"],
            "published_at": "2026-07-01T00:00:00Z",
            "observed_at": "2026-07-02T01:00:00Z",
            "source": {"detail_url": "https://example.test/CNVD-2026-1000"},
            "details": {
                "description": "A Chrome bug",
                "solution": "Update Chrome",
                "affected_products": ["Google Chrome"],
                "reference_links": ["https://example.test/ref"],
            },
        }
        candidate = candidate_from_doc(doc)
        self.assertEqual(candidate["cnvd_id"], "CNVD-2026-1000")
        self.assertEqual(candidate["cve_id"], "CVE-2026-1000")
        self.assertEqual(candidate["title"], "Chrome vulnerability")
        self.assertEqual(candidate["summary"], "A Chrome bug")
        self.assertEqual(candidate["affected_products"], ["Google Chrome"])
        self.assertEqual(candidate["references"], ["https://example.test/CNVD-2026-1000"])
        self.assertEqual(doc_cve_ids(doc), ["CVE-2026-1000"])

    def test_candidate_from_cnnvd_v2_document(self):
        doc = {
            "_id": "cnnvd:2026-1000",
            "schema_version": 2,
            "code": "2026-1000",
            "title": "CNNVD Chrome issue",
            "severity": "Critical",
            "cve_ids": ["CVE-2026-2000"],
            "details": {
                "vulDesc": "detail text",
                "productName": "Google Chrome",
                "vendorName": "Google",
                "patch": "Apply vendor update",
            },
        }
        candidate = candidate_from_cnnvd_doc(doc)
        self.assertEqual(candidate["cnvd_id"], "CNNVD-2026-1000")
        self.assertEqual(candidate["cve_id"], "CVE-2026-2000")
        self.assertEqual(candidate["solution"], "Apply vendor update")
        self.assertIn("Google Chrome", candidate["affected_products"])

    def test_card_date_prefers_published_at(self):
        card = {
            "source": "cnvd",
            "doc": {
                "published_at": "2026-07-10T00:00:00Z",
                "observed_at": "2026-07-11T00:00:00Z",
                "details": {"description": "x"},
            },
        }
        self.assertEqual(card_date(card), "2026-07-10T00:00:00Z")
        self.assertEqual(card_raw(card)["description"], "x")

    def test_report_publish_date_hides_timestamp(self):
        card = {
            "source": "cnvd",
            "cnvd_id": "CNVD-2026-1000",
            "title": {"zh": "测试", "en": "Test"},
            "doc": {"published_at": "2026-07-20T16:00:00", "details": {}},
        }
        self.assertEqual(word_rows(card, "zh")[3][3], "2026-07-20")


if __name__ == "__main__":
    unittest.main()
