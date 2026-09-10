"""
Dashboard smoke test (Streamlit AppTest)
========================================

Runs app.py headlessly through streamlit.testing, drives the sidebar widgets
and asserts the page renders without exceptions for a Critical identity and
for an identity with no findings. Skipped when streamlit is not installed.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from streamlit.testing.v1 import AppTest
except ImportError:  # pragma: no cover
    AppTest = None


@unittest.skipIf(AppTest is None, "streamlit not installed")
class TestDashboard(unittest.TestCase):

    def setUp(self):
        self.at = AppTest.from_file(os.path.join(ROOT, "app.py"), default_timeout=60).run()

    def _metric(self, label: str) -> str:
        for m in self.at.metric:
            if m.label == label:
                return m.value
        raise AssertionError(f"metric {label!r} not found")

    def test_default_view_renders_top_identity(self):
        at = self.at
        self.assertEqual(at.exception, [])
        self.assertEqual(self._metric("Identities"), "500")
        self.assertEqual(self._metric("Flagged"), "130")
        self.assertEqual(self._metric("Critical"), "7")
        self.assertTrue(at.selectbox[0].value.startswith("100 · Huda Qureshi"))
        captions = " ".join(c.value for c in at.caption)
        self.assertIn("40 + 30 + 25 + 20 + 10 = 125", captions)   # score breakdown
        self.assertIn("capped at 100", captions)
        self.assertIn("Escalation capabilities", captions)
        self.assertGreaterEqual(len(at.dataframe), 2)             # identity table + capability matrix

    def test_unused_window_slider_changes_flagged_count(self):
        at = self.at
        at.slider[0].set_value(150).run()
        self.assertEqual(at.exception, [])
        self.assertEqual(self._metric("Flagged"), "109")

    def test_zero_finding_identity_renders_cleanly(self):
        at = self.at
        at.checkbox[0].set_value(False).run()            # show unflagged identities too
        at.text_input[0].set_value("noura.almarri").run()
        self.assertEqual(at.exception, [])
        self.assertIn("Noura Al Marri", at.selectbox[0].value)
        self.assertTrue(at.selectbox[0].value.startswith("  0 ·"))
        captions = " ".join(c.value for c in at.caption)
        self.assertIn("No rule triggered", captions)
        self.assertIn("No escalation capabilities", captions)
        self.assertTrue(any("No governance findings" in s.value for s in at.success))

    def test_filters_can_empty_the_table_without_crashing(self):
        at = self.at
        at.text_input[0].set_value("nobody-with-this-name").run()
        self.assertEqual(at.exception, [])
        self.assertTrue(any("No identities match" in i.value for i in at.info))


if __name__ == "__main__":
    unittest.main(verbosity=2)
