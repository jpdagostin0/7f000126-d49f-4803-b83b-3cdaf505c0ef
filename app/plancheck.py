"""What TestExecutor.test_execute_tpcds hands to the executor, compared with the pinned tree.

The test runs every TPC-DS query marked "execute" through sqlglot.executor.execute in a
process pool and compares the rows with DuckDB's (about 40 CPU seconds, so it never runs
here). Each query goes through two stages:

  1. parse_one(sql), find_tables, optimize(...) inside execute, and transpile(sql, "duckdb")
     for the DuckDB side;
  2. everything else: schema and table setup, Plan, PythonExecutor, the generators that
     execute calls, pickling between the processes, the pandas comparison.

build() runs at image build time on the pinned tree. It stores a digest of the stage 1
results of every query, and the line spans of every function that stage 2 runs
(sys.monitoring). When a patch only changes functions that stage 2 does not run
(eligible), stage 2 computes the same rows from the same stage 1 results;
changed_tasks(...) then runs stage 1 with the patched code and names the queries whose
results are not those of the pinned tree. Only these can end differently, so the test runs
with these pool tasks alone (reduce.py), or passes at once when there is none.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import importlib
import marshal
import os
import pickle
import signal
import sys

FIXTURE = "optimizer/tpc-ds/tpc-ds.sql"
TEST_ID = "tests/test_executor.py::TestExecutor::test_execute_tpcds"
NAME = "plancheck.marshal"


def queries():
    """(pool task index, sql) of the queries that the test executes."""
    helpers = importlib.import_module("tests.helpers")
    return [(i, sql) for i, (meta, sql, _) in enumerate(helpers.load_sql_fixture_pairs(FIXTURE)) if meta.get("execute")]


def _dump(node, out):
    """Every field of an expression tree that a reader of the tree can see."""
    expr = sys.modules["sqlglot.expressions"].Expr
    stack = [node]
    while stack:
        v = stack.pop()
        if isinstance(v, expr):
            out.append("<%s.%s %r %r" % (type(v).__module__, type(v).__qualname__, v.comments, v._meta))
            stack.append(">")
            stack.append(v._type)
            for k in reversed(list(v.args)):
                stack.append(v.args[k])
                stack.append("@" + k)
        elif isinstance(v, (list, tuple)):
            out.append("[%d" % len(v))
            stack.extend(reversed(v))
        elif isinstance(v, str) and v[:1] in "@>" and v is not node:
            out.append(v)
        else:
            out.append("%s:%r" % (type(v).__qualname__, v))


def stage_one(sql, schema):
    """Digest of the stage 1 results of one query (or of the exception that it raises)."""
    sqlglot = sys.modules["sqlglot"]
    executor = sys.modules["sqlglot.executor"]
    out = []
    try:
        out.append(sqlglot.transpile(sql, write="duckdb")[0])
        expression = pickle.loads(pickle.dumps(sqlglot.parse_one(sql)))
        _dump(expression, out)
        out.append(repr([t.name for t in sqlglot.find_tables(expression)]))
        _dump(executor.optimize(expression, schema, leave_tables_isolated=True, dialect=None), out)
    except _OutOfTime:
        raise
    except Exception as e:  # noqa: BLE001
        out.append("raised %s %s" % (type(e).__name__, e))
    return hashlib.sha1("\x00".join(out).encode("utf-8", "surrogatepass")).digest()


def _schema():
    helpers = importlib.import_module("tests.helpers")
    importlib.import_module("sqlglot.executor")
    return sys.modules["sqlglot.schema"].ensure_schema(helpers.TPCDS_SCHEMA, dialect=None)


class _OutOfTime(BaseException):
    pass


def _alarm(signum, frame):
    raise _OutOfTime()


def load(cache_dir):
    try:
        with open(os.path.join(cache_dir, NAME), "rb") as f:
            return marshal.load(f)
    except (OSError, ValueError, EOFError, TypeError):
        return None


def eligible(saved, changed):
    """True when the patch can reach the test through stage 1 only: it changes nothing but
    functions that stage 2 does not run. Meant for commits whose changed functions do not
    run at import time (the function-body commits of the selector).
    changed: {path: (pinned text, patched text)} of every file of the patch."""
    for rel, (old, new) in changed.items():
        if not (rel.startswith("sqlglot/") and rel.endswith(".py")) or old is None or new is None:
            return False
        spans = saved["spans"].get(rel, ())
        try:
            tree = ast.parse(old)
        except (SyntaxError, ValueError):
            return False
        # the outermost functions of the file (methods of a class are outermost too)
        defs = []
        todo = list(tree.body)
        while todo:
            node = todo.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                first = min([node.lineno] + [d.lineno for d in node.decorator_list])
                defs.append((first, node.end_lineno))
            elif isinstance(node, ast.ClassDef):
                todo.extend(node.body)
        matcher = difflib.SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False)
        for tag, i1, i2, _, _ in matcher.get_opcodes():
            if tag == "equal":
                continue
            lo, hi = (i1, i1 + 1) if i1 == i2 else (i1 + 1, i2)  # 1-based; an insertion: the lines around it
            inside = [d for d in defs if d[0] <= lo and hi <= d[1]]
            if not inside:
                return False  # code that runs at import time
            first, last = inside[0]
            if any(a <= last and first <= b for a, b in spans):
                return False  # stage 2 runs this function, or one defined inside it
    return True


def changed_tasks(cache_dir, budget, limit):
    """The pool tasks whose stage 1 results in this process are not those of the pinned tree,
    or None when there are more than limit, or no answer within budget CPU seconds."""
    saved = load(cache_dir)
    if not saved:
        return None
    out = []
    old = signal.signal(signal.SIGVTALRM, _alarm)
    signal.setitimer(signal.ITIMER_VIRTUAL, max(0.05, budget))
    try:
        todo = queries()
        if [i for i, _ in todo] != saved["tasks"]:
            return None
        schema = _schema()
        for (i, sql), digest in zip(todo, saved["digests"]):
            if stage_one(sql, schema) != digest:
                out.append(i)
                if len(out) > limit:
                    return None
        return out
    except _OutOfTime:
        return None
    except Exception:  # noqa: BLE001
        return None
    finally:
        signal.setitimer(signal.ITIMER_VIRTUAL, 0)
        signal.signal(signal.SIGVTALRM, old)


def build(root, tables):
    """(digests of stage 1, files with a function that stage 2 runs), on the pinned tree.
    tables: TestExecutor.tpcds_tables."""
    sqlglot = sys.modules["sqlglot"]
    executor = importlib.import_module("sqlglot.executor")
    helpers = importlib.import_module("tests.helpers")
    todo = queries()
    sqls = [sql for _, sql in todo]
    schema = _schema()
    digests = [stage_one(sql, schema) for sql in sqls]
    again = [stage_one(sql, schema) for sql in sqls]
    if digests != again:
        raise RuntimeError("stage 1 does not repeat")

    mon = sys.monitoring
    tool = mon.PROFILER_ID
    codes = set()

    def on_start(code, offset):
        codes.add(code)
        return mon.DISABLE

    real_optimize = executor.optimize

    def optimize(*args, **kwargs):  # stage 1: not recorded
        mon.set_events(tool, 0)
        try:
            return real_optimize(*args, **kwargs)
        finally:
            mon.set_events(tool, mon.events.PY_START)

    mon.use_tool_id(tool, "plancheck")
    mon.register_callback(tool, mon.events.PY_START, on_start)
    executor.optimize = optimize
    try:
        for sql in sqls:
            expression = sqlglot.parse_one(sql)
            names = [t.name for t in sqlglot.find_tables(expression)]
            mon.set_events(tool, mon.events.PY_START)
            expression = pickle.loads(pickle.dumps(expression))
            table = executor.execute(expression, schema=helpers.TPCDS_SCHEMA, tables={n: tables[n] for n in names})
            table = pickle.loads(pickle.dumps(table))
            list(table.rows), list(table.columns)
            mon.set_events(tool, 0)
    finally:
        executor.optimize = real_optimize
        mon.set_events(tool, 0)
        mon.register_callback(tool, mon.events.PY_START, None)
        mon.free_tool_id(tool)
    prefix = os.path.join(os.path.realpath(root), "")
    spans = {}
    for code in codes:
        path = os.path.realpath(code.co_filename)
        if os.path.isabs(code.co_filename) and path.startswith(prefix) and os.path.exists(path):
            last = max([code.co_firstlineno] + [line for _, _, line in code.co_lines() if line])
            spans.setdefault(path[len(prefix):], []).append((code.co_firstlineno, last))
    if "sqlglot/planner.py" not in spans:
        raise RuntimeError("stage 2 was not recorded")
    return {"tasks": [i for i, _ in todo], "digests": digests, "spans": {rel: sorted(v) for rel, v in spans.items()}}
