from __future__ import annotations

import builtins
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from app import engine, statefp


class FingerprintTests(unittest.TestCase):
    def test_keyword_only_signature_changes_fingerprint(self) -> None:
        old = compile("def f(a, *, b): b = 2; return a", "fixture.py", "exec").co_consts[0]
        new = compile("def f(a): b = 2; return a", "fixture.py", "exec").co_consts[0]
        self.assertNotEqual(statefp.Fingerprinter().code(old), statefp.Fingerprinter().code(new))

    def test_positional_only_signature_changes_fingerprint(self) -> None:
        old = compile("def f(a): return a", "fixture.py", "exec").co_consts[0]
        new = compile("def f(a, /): return a", "fixture.py", "exec").co_consts[0]
        self.assertNotEqual(statefp.Fingerprinter().code(old), statefp.Fingerprinter().code(new))


class OpenOverlayTests(unittest.TestCase):
    def test_newline_matches_text_io_wrapper(self) -> None:
        root = str(ROOT)
        path = str(ROOT / "fixture.txt")
        for text in ("a\r\nb\rc\n", "甲\r\n乙\r丙\n"):
            for newline in (None, "", "\n", "\r", "\r\n"):
                with io.TextIOWrapper(io.BytesIO(text.encode("utf-8")), encoding="utf-8", newline=newline) as reference:
                    expected = reference.read()
                    reference.seek(0)
                    expected_lines = reference.readlines()
                for positional in (False, True):
                    with self.subTest(text=text, newline=newline, positional=positional):
                        with patch.object(builtins, "open"), patch.object(io, "open"), patch.object(io, "open_code"):
                            engine.install_open_overlay(root, {"fixture.txt": text})
                            if positional:
                                stream = open(path, "r", -1, "utf-8", None, newline)
                            else:
                                stream = open(path, "r", encoding="utf-8", newline=newline)
                            with stream:
                                self.assertEqual(stream.read(), expected)
                                stream.seek(0)
                                self.assertEqual(stream.readlines(), expected_lines)


if __name__ == "__main__":
    unittest.main()
