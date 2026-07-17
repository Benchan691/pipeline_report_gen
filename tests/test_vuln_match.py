import json
import unittest
from unittest.mock import patch

from pipeline.vuln_match import (
    cap_per_cluster,
    build_filtered_matches,
    clean_term,
    confirm_software_match,
    first_match,
    match_confirmation_prompt,
    norm_id,
    norm_severity,
    ranked_matches,
    searchable_text,
)


class VulnerabilityMatchTests(unittest.TestCase):
    def test_normalizes_terms_ids_and_severity(self):
        self.assertEqual(clean_term("Java 8 Update 202 (64-bit)"), "Java")
        self.assertEqual(norm_id("cnvd", "2026-24916"), "CNVD-2026-24916")
        self.assertEqual(norm_severity("中\n(AV:L)"), "Medium")

    def test_does_not_match_language_mentions_as_software(self):
        document = {"title": "Conductor vulnerability", "details": {"cnnvd": {"vulDesc": "An inline JavaScript or Python expression is evaluated.", "productName": "Conductor"}}}
        self.assertIsNone(first_match([{"term": "Python"}, {"term": "Java"}], searchable_text("cnnvd", document)))

    def test_ranking_and_cluster_cap_prioritize_highest_scored_items(self):
        items = [
            {"id": "C1", "cluster_id": "chrome", "severity": "Critical", "mark": 10},
            {"id": "C2", "cluster_id": "chrome", "severity": "High", "mark": 9},
            {"id": "J1", "cluster_id": "java", "severity": "High", "mark": 8},
        ]
        self.assertEqual([item["id"] for item in cap_per_cluster(items, 1)], ["C1", "J1"])
        self.assertEqual([item["id"] for item in ranked_matches(items, 2)], ["C1", "C2"])

    def test_confirmation_requests_thinking_and_uses_response(self):
        document = {"code": "CNNVD-1", "title": "Google Chrome vulnerability", "details": {"cnnvd": {"vulName": "Google Chrome vulnerability", "productName": "Google Chrome"}}}
        match = {"term": "Google Chrome", "cluster_label": "Google Chrome", "cluster_id": "C1", "cluster_size": 1, "term_kind": "label"}
        cfg = {"ai_base_url": "http://test", "ai_model": "test", "vuln_match_ai_max_tokens": 123, "vuln_match_thinking_budget_tokens": 45}
        with patch("pipeline.evidence.call_ai", return_value=json.dumps({"related": True, "confidence": "high", "reason": "direct match"})) as call_ai:
            result = confirm_software_match(document, "cnnvd", match, cfg)

        self.assertTrue(result["related"])
        self.assertEqual(call_ai.call_args.kwargs["max_tokens"], 123)
        self.assertTrue(call_ai.call_args.kwargs["enable_thinking"])
        self.assertEqual(call_ai.call_args.kwargs["thinking_budget_tokens"], 45)

    def test_confirmation_prompt_defaults_ambiguous_and_indirect_matches_to_false(self):
        document = {"code": "CNNVD-1", "details": {"cnnvd": {"vulName": "SDK vulnerability", "productName": "Snowflake Snowpark Python SDK"}}}
        match = {"term": "Python", "cluster_label": "Python"}

        system, user = match_confirmation_prompt(document, "cnnvd", match)

        self.assertIn("keyword match is an untrusted", system)
        self.assertIn("when evidence is missing, ambiguous, indirect, or conflicting, return related=false", system)
        self.assertIn("A medium- or low-confidence relationship must be related=false", system)
        self.assertIn("plugins, connectors, integrations", system)
        self.assertEqual(json.loads(user)["product"], "Snowflake Snowpark Python SDK")

    def test_confirmation_rejects_non_boolean_or_unavailable_responses(self):
        document = {"code": "CNNVD-1", "details": {"cnnvd": {}}}
        match = {"term": "Chrome", "cluster_label": "Chrome"}
        cfg = {"ai_base_url": "http://test", "ai_model": "test"}
        with patch("pipeline.evidence.call_ai", return_value=json.dumps({"related": "false"})):
            self.assertFalse(confirm_software_match(document, "cnnvd", match, cfg)["related"])
        with patch("pipeline.evidence.call_ai", return_value="not json"):
            self.assertFalse(confirm_software_match(document, "cnnvd", match, cfg)["related"])
        with patch("pipeline.evidence.call_ai", side_effect=SystemExit("offline")):
            self.assertEqual(confirm_software_match(document, "cnnvd", match, cfg)["reason"], "llm_unavailable")

    def test_post_selection_verification_backfills_and_respects_cluster_cap(self):
        terms = [
            {"term": "Chrome", "term_kind": "label", "cluster_id": "chrome", "cluster_label": "Chrome", "cluster_size": 1},
            {"term": "Java", "term_kind": "label", "cluster_id": "java", "cluster_label": "Java", "cluster_size": 1},
        ]
        docs = [
            {"code": "1", "title": "Chrome critical", "severity": "Critical", "details": {"cnvd": {}}},
            {"code": "2", "title": "Chrome high", "severity": "High", "details": {"cnvd": {}}},
            {"code": "3", "title": "Java high", "severity": "High", "details": {"cnvd": {}}},
            {"code": "4", "title": "Java medium", "severity": "Medium", "details": {"cnvd": {}}},
        ]
        cfg = {"vuln_match_top_n": 3, "vuln_match_max_per_cluster": 1}

        with patch("pipeline.vuln_match.software_terms", return_value=terms), \
             patch("pipeline.vuln_match.docs_for", side_effect=[docs, []]), \
             patch("pipeline.vuln_match.confirm_software_match", side_effect=[
                 {"related": False, "confidence": "low", "reason": "wrong product"},
                 {"related": True, "confidence": "high", "reason": "direct"},
                 {"related": True, "confidence": "high", "reason": "direct"},
             ]) as confirm:
            payload, stats = build_filtered_matches(cfg)

        self.assertEqual([item["id"] for item in payload["matches"]], ["CNVD-2", "CNVD-3"])
        self.assertEqual(confirm.call_count, 3)
        self.assertEqual(stats["llm_rejected"], 1)
        self.assertEqual(stats["cluster_cap_skipped"], 1)
        self.assertEqual(stats["shortfall"], 1)

    def test_post_selection_stops_verifying_once_full(self):
        term = {"term": "Chrome", "term_kind": "label", "cluster_id": "chrome", "cluster_label": "Chrome", "cluster_size": 1}
        docs = [
            {"code": str(index), "title": f"Chrome {index}", "severity": "High", "details": {"cnvd": {}}}
            for index in range(1, 4)
        ]
        cfg = {"vuln_match_top_n": 2}
        accepted = {"related": True, "confidence": "high", "reason": "direct"}

        with patch("pipeline.vuln_match.software_terms", return_value=[term]), \
             patch("pipeline.vuln_match.docs_for", side_effect=[docs, []]), \
             patch("pipeline.vuln_match.confirm_software_match", return_value=accepted) as confirm:
            payload, _ = build_filtered_matches(cfg)

        self.assertEqual(len(payload["matches"]), 2)
        self.assertEqual(confirm.call_count, 2)
