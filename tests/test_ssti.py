#!/usr/bin/env python3
"""Tests for WEB8 — SSTI Scanner.

Hosts the built-in vulnerable/clean template simulators on loopback and runs
the real detection engine through urllib against them.
"""

import os
import sys
import threading
import unittest
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ssti_scanner import (
    SSTIDetector,
    VulnSSTIHandler,
    CleanSSTIHandler,
    SSTIHelpers,
)


class SSTIHelpersTest(unittest.TestCase):
    def test_math_evaluation(self):
        self.assertEqual(SSTIHelpers.evaluate_math("{{7*7}}"), "49")
        self.assertEqual(SSTIHelpers.evaluate_math("[% 7 * 7 %]"), "49")
        self.assertIsNone(SSTIHelpers.evaluate_math("hello"))


def _start(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class SSTIDetectionTest(unittest.TestCase):
    def setUp(self):
        self.vuln = _start(VulnSSTIHandler)
        self.clean = _start(CleanSSTIHandler)
        self.addCleanup(self._close, self.vuln)
        self.addCleanup(self._close, self.clean)

    @staticmethod
    def _close(server):
        server.shutdown()
        server.server_close()

    def _scan(self, server):
        url = f"http://127.0.0.1:{server.server_port}/greet"
        detector = SSTIDetector(url, param="name", method="GET", timeout=5)
        return detector.full_scan()

    def test_math_eval_fires_on_vulnerable(self):
        results = self._scan(self.vuln)
        self.assertTrue(results["vulnerable"])
        self.assertTrue(any(r["vulnerable"] for r in results["math_eval"]))

    def test_engine_identified_on_vulnerable(self):
        results = self._scan(self.vuln)
        self.assertEqual(results["engine"], "jinja2")

    def test_engine_specific_fires_on_vulnerable(self):
        results = self._scan(self.vuln)
        self.assertTrue(results["engine_specific"]["jinja2"]["vulnerable"])

    def test_no_false_positive_on_clean(self):
        results = self._scan(self.clean)
        self.assertFalse(results["vulnerable"])
        self.assertIsNone(results["engine"])

    def test_no_engine_specific_on_clean(self):
        results = self._scan(self.clean)
        self.assertFalse(any(d["vulnerable"] for d in results["engine_specific"].values()))


class SSTIDemoTest(unittest.TestCase):
    def test_demo_vulnerable_returns_0(self):
        import ssti_scanner
        rc = ssti_scanner.run_demo(clean=False)
        self.assertEqual(rc, 0)

    def test_demo_clean_returns_0(self):
        import ssti_scanner
        rc = ssti_scanner.run_demo(clean=True)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()