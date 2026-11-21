from __future__ import annotations

import ast
import hashlib
import io
import json
import marshal
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "app"))

from app import build_base_state, build_exec_cache, cone, infect, keymap, lazymods
from app import patchrules, pool, preload, reduce, runner, selector, stmtmap, tokcheck
from build import fetch_sqlglot
import score


class RewriteTests(unittest.TestCase):
    def test_build_base_state_serializes_snapshot(self) -> None:
        table: dict[str, int] = {"x": 1}
        key = ("G", "sqlglot", "table")
        fingerprint = types.SimpleNamespace(function_keys={key}, objects={key: table})
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "state.bin"
            with patch("preload.install_environment"), patch("preload.import_sqlglot"), \
                    patch("statefp.snapshot", return_value=({key: 1}, fingerprint)), \
                    patch("selector.base_state_header", return_value=("header",)), \
                    patch("selector.resolve_base_objects", return_value={key: table}):
                build_base_state.main(directory, str(target))
            data = marshal.loads(target.read_bytes())
        self.assertEqual(data, {"header": ("header",), "state": {key: 1}, "fkeys": [key], "okeys": [key]})

    def test_cache_rows_retain_types(self) -> None:
        self.assertNotEqual(build_exec_cache.typed([(1,)]), build_exec_cache.typed([(True,)]))
        self.assertEqual(build_exec_cache.typed([("x", None)]), [((str, "'x'"), (type(None), "None"))])

    def test_heap_walks_requested_modules_first(self) -> None:
        first = types.ModuleType("sqlglot.rewrite_first")
        second = types.ModuleType("sqlglot.rewrite_second")
        with patch.dict(sys.modules, {second.__name__: second, first.__name__: first}):
            heap = cone.Heap([first.__name__])
        owners = [rec[3] for rec in heap.recs if rec[0] == "n"]
        self.assertLess(owners.index(first.__name__), owners.index(second.__name__))

    def test_comments_and_holder_names(self) -> None:
        self.assertTrue(infect._blank_or_comment(["", "  # 註解"]))
        self.assertFalse(infect._blank_or_comment(["return 1"]))
        self.assertEqual(keymap.holder_name(("A", "module", 12)), "A|module|12")
        changes: list[tuple[ast.Compare, str, str]] = []
        self.assertTrue(infect._same(ast.parse("a == b"), ast.parse("a != b"), changes))
        self.assertEqual([(old, new) for _, old, new in changes], [("Eq", "NotEq")])
        self.assertFalse(infect._same(ast.parse("a == b; c == d"), ast.parse("a != b; c != d"), []))

    def test_lazy_loaded_uses_exact_module_type(self) -> None:
        lazy = lazymods._LazyModule("rewrite_lazy")
        with patch.dict(sys.modules, {"rewrite_lazy": lazy, "rewrite_loaded": types.ModuleType("rewrite_loaded")}):
            self.assertFalse(lazymods.loaded("rewrite_lazy"))
            self.assertTrue(lazymods.loaded("rewrite_loaded"))
            self.assertFalse(lazymods.loaded("rewrite_absent"))

    def test_test_files_group_parameterized_ids(self) -> None:
        maps = types.SimpleNamespace(meta={"test_ids": ["tests/a.py::A::test_one[x]", "tests/a.py::A::test_two"]})
        with patch.dict(patchrules._SRC, {}, clear=True):
            self.assertEqual(patchrules.test_files(maps), {"tests/a.py": [0, 1]})

    def test_inline_map_runs_when_consumed(self) -> None:
        executor = pool.InlinePool()
        results = executor.map(abs, [-2, -3])
        self.assertFalse(executor._started)
        self.assertEqual(list(results), [2, 3])
        self.assertTrue(executor._started)
        executor.shutdown()
        with self.assertRaises(RuntimeError):
            executor.submit(abs, -1)

    def test_csv_rows_use_first_row_types(self) -> None:
        mod = types.SimpleNamespace(open_file=lambda name: io.StringIO("a|b|c\n1|text|2.5\n|other|3.5\n"))
        self.assertEqual(preload.exec_rows_from_csv(mod, "rows"), [(1, "text", 2.5), (None, "other", 3.5)])

    def test_escape_scan(self) -> None:
        self.assertTrue(reduce._escapes(ast.parse("if ready:\n return 1").body[0]))
        self.assertFalse(reduce._escapes(ast.parse("value = 1").body[0]))

    def test_runner_reports_every_class_setup_failure(self) -> None:
        class Broken(unittest.TestCase):
            _br_number: int = 7

            @classmethod
            def setUpClass(cls) -> None:
                raise RuntimeError("fixture")

            def test_one(self) -> None:
                self.fail("不應執行")

        emitted: list[tuple[int, bool | None]] = []
        case = Broken("test_one")
        case._br_number = 7
        with patch.object(runner, "load_case", return_value=case):
            result = runner.run_tests([(7, "tests/a.py::Broken::test_one")], lambda n, failed: emitted.append((n, failed)))
        self.assertEqual(emitted, [(7, True)])
        self.assertEqual(len(result.class_errors), 1)

    def test_pack_preserves_stable_equal_cost_order(self) -> None:
        self.assertEqual(selector.pack([2, 0, 1], [0.1, 0.1, 0.1]), [[2, 0, 1]])
        self.assertEqual(selector.pack([], []), [])
        workers = selector.pack([0, 1, 2], [10, 9, 1])
        self.assertEqual(sorted(n for worker in workers for n in worker), [0, 1, 2])

    def test_statement_units_keep_future_annotations(self) -> None:
        units, flags, names = stmtmap.build_units("from __future__ import annotations\nimport os as path\nclass C:\n @classmethod\n def f(cls): pass\n")
        self.assertEqual(flags, 0x1000000)
        self.assertEqual(names, ["annotations", "path"])
        self.assertEqual(units[-1], [4, 5, ("C",), 0])

    def test_token_test_numbers_and_missing_maps(self) -> None:
        with patch.dict(tokcheck._MAP, {"mapped": {"tests": {3: [], 8: []}}, "missing": None}, clear=True):
            self.assertEqual(tokcheck.tests_of("mapped"), frozenset({3, 8}))
            self.assertEqual(tokcheck.tests_of("missing"), frozenset())

    def test_tree_digest_preserves_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "module.py"
            target.write_bytes(b"pass\n")
            for mode, label in ((0o644, "644"), (0o755, "755")):
                target.chmod(mode)
                row = f"module.py\0{label}\0{hashlib.sha256(b'pass\n').hexdigest()}\n"
                self.assertEqual(fetch_sqlglot.tree_digest(directory), (hashlib.sha256(row.encode()).hexdigest(), 1))

    def test_scorer_shape_and_penalties(self) -> None:
        tests = [{"number": 1, "seconds": 0.25}]
        answers = {"a": {"failing": [1]}}
        output = json.dumps({"commit": "a", "workers": [[1]]}).encode()
        self.assertEqual(score.score_run(output, tests, answers), {"ok": True, "simulated_milliseconds": 2250, "misses": 0})
        self.assertEqual(score.score_run(b'{"commit":"a","workers":[]}', tests, answers)["misses"], 1)
        self.assertEqual(score.score_run(b'{"commit":"a","workers":[],"extra":1}', tests, answers)["code"], "wrong_shape")

    def test_entry_point_noop_patch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            (data / "commits").mkdir()
            (data / "commits" / "empty.patch").write_text("")
            (data / "tests.json").write_text('{"tests":[]}')
            result = subprocess.run([sys.executable, str(ROOT / "app" / "main.py")],
                                    env={**os.environ, "BR_ROOT": directory, "BR_DATA": directory},
                                    capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), {"commit": "empty", "workers": []})
        self.assertNotIn("selector failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
