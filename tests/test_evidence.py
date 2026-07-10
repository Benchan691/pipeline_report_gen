import json
import unittest
from unittest.mock import patch

from pipeline.evidence import (
    add_english_translations,
    build_ai_payload,
    cards_missing_english,
    extract_json,
    evidence_prompt,
    merge_cards,
    strip_thinking,
    translation_prompt,
)


class EvidenceTests(unittest.TestCase):
    def test_strips_supported_thinking_tags_before_parsing_json(self):
        text = '<redacted_thinking>reasoning</redacted_thinking>\n{"related": false}'
        self.assertEqual(extract_json(strip_thinking(text)), {"related": False})
        self.assertEqual(strip_thinking("<think>x</think> answer"), "answer")

    def test_ai_payload_controls_thinking_and_budget(self):
        disabled = build_ai_payload("model", "system", "user", 100, enable_thinking=False)
        enabled = build_ai_payload("model", "system", "user", 4096, enable_thinking=True, thinking_budget_tokens=2048)

        self.assertEqual(disabled["chat_template_kwargs"], {"enable_thinking": False})
        self.assertNotIn("thinking_budget_tokens", disabled)
        self.assertEqual(enabled["chat_template_kwargs"], {"enable_thinking": True})
        self.assertEqual(enabled["thinking_budget_tokens"], 2048)

    def test_prompts_require_grounded_json_and_preserve_technical_values(self):
        result = {"task_type": "how_to_respond", "url": "https://vendor.example/advisory", "title": "Advisory", "snippet": "Update to 1.2.3", "page_content": ""}
        candidate = {"cnvd_id": "CNVD-1", "cve_id": "CVE-2026-1", "search_id": "CVE-2026-1", "title": "Product issue", "severity": "High", "summary": ""}
        evidence_system, evidence_user = evidence_prompt(result, candidate)
        translation_system, translation_user = translation_prompt({"title": "漏洞", "what_happened": "", "why_matters": "", "how_to_respond": "升级到 1.2.3"})

        self.assertIn("only facts explicitly supported", evidence_system)
        self.assertIn("how_to_respond", evidence_system)
        self.assertIn("supplied source URL", evidence_system)
        self.assertEqual(json.loads(evidence_user)["task_type"], "how_to_respond")
        self.assertIn("Do not translate CVE/CNVD IDs", translation_system)
        self.assertEqual(json.loads(translation_user)["how_to_respond"], "升级到 1.2.3")

    def test_merge_and_translate_cards_preserves_bilingual_fields(self):
        candidate = {"cnvd_id": "CNVD-1", "search_id": "CNVD-1", "title": "Title", "summary": "", "solution": "", "doc": {"details": {"cnvd": {}}}}
        evidence = [{"cnvd_id": "CNVD-1", "task_type": "what_happened", "what_happened": "中文描述", "confidence": "high", "references": []}]
        card = merge_cards([candidate], evidence)[0]

        self.assertTrue(cards_missing_english([card]))
        with patch("pipeline.evidence.call_ai", return_value=json.dumps({"title": "Title", "what_happened": "English description", "why_matters": "", "how_to_respond": "Apply patch"})):
            translated = add_english_translations([card], {"ai_base_url": "http://test", "ai_model": "test"})

        self.assertEqual(translated[0]["what_happened"]["zh"], "中文描述")
        self.assertEqual(translated[0]["what_happened"]["en"], "English description")
        self.assertFalse(cards_missing_english(translated))
