"""What TestExecutor.test_execute_tpcds hands to the executor, compared with the pinned tree.

The test runs every TPC-DS query marked "execute" through sqlglot.executor.execute in a
process pool and compares the rows with DuckDB's (about 40 CPU seconds, so it never runs
here). Each query goes through two stages:

  1. parse_one(sql), find_tables, optimize(...) and Plan(...) inside execute, and
     transpile(sql, "duckdb") for the DuckDB side;
  2. everything else: schema and table setup, PythonExecutor, the generators that execute
     calls, pickling between the processes, the pandas comparison.

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
import time

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


def _dump_plan(plan, out):
    """Every attribute of a plan and of its steps. A step is named by a digest of its own
    attributes and of the steps that it depends on, so that the order inside the sets of
    steps does not count; the dependents of each step follow at the end."""
    expr = sys.modules["sqlglot.expressions"].Expr
    names = {}  # id of a plan object -> its digest
    back = []

    def name(v):
        key = id(v)
        if key not in names:
            names[key] = "cycle"
            part = ["<" + type(v).__qualname__]
            for k in sorted(vars(v)):
                if k == "dependents" and isinstance(vars(v)[k], (set, frozenset)):
                    back.append((key, vars(v)[k]))
                    continue
                part.append("@" + k)
                walk(vars(v)[k], part)
            names[key] = hashlib.sha1("\x00".join(part).encode("utf-8", "surrogatepass")).hexdigest()
        return names[key]

    def walk(v, part):
        if isinstance(v, expr):
            _dump(v, part)
        elif isinstance(v, (list, tuple)):
            part.append("[%d" % len(v))
            for x in v:
                walk(x, part)
        elif isinstance(v, dict):
            part.append("{%d" % len(v))
            for k, x in v.items():
                walk(k, part)
                walk(x, part)
        elif isinstance(v, (set, frozenset)):
            members = []
            for x in v:
                one = []
                walk(x, one)
                members.append("\x01".join(one))
            part.append("(%d" % len(v))
            part.extend(sorted(members))
        elif hasattr(v, "__dict__") and type(v).__module__.startswith("sqlglot."):
            part.append(name(v))
        else:
            part.append("%s:%r" % (type(v).__qualname__, v))

    walk(plan, out)
    out.extend(sorted("%s<-%s" % (names[key], ",".join(sorted(name(x) for x in users))) for key, users in back))


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
        expression = executor.optimize(expression, schema, leave_tables_isolated=True, dialect=None)
        _dump(expression, out)
        _dump_plan(executor.Plan(expression), out)
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


def eligible(saved, changed, at_import=False):
    """True when the patch can reach the test through stage 1 only: it changes nothing but
    functions that stage 2 does not run. Meant for commits whose changed functions do not
    run at import time (the function-body commits of the selector).
    at_import: the patched tree is imported again, so changed lines outside functions are
    allowed too (never inside code that stage 2 runs, a lambda of a class table for
    instance); what they leave behind is for the caller to check (the import-state diff).
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
        # the lines that differ, without the equal lines before and after them (a one-line
        # edit of a long file is the usual case)
        a, b = old.splitlines(), new.splitlines()
        head = 0
        while head < len(a) and head < len(b) and a[head] == b[head]:
            head += 1
        tail = 0
        while tail < len(a) - head and tail < len(b) - head and a[-1 - tail] == b[-1 - tail]:
            tail += 1
        matcher = difflib.SequenceMatcher(None, a[head:len(a) - tail], b[head:len(b) - tail], autojunk=False)
        for tag, i1, i2, _, _ in matcher.get_opcodes():
            if tag == "equal":
                continue
            i1, i2 = i1 + head, i2 + head
            lo, hi = (i1, i1 + 1) if i1 == i2 else (i1 + 1, i2)  # 1-based; an insertion: the lines around it
            inside = [d for d in defs if d[0] <= lo and hi <= d[1]]
            if not inside:
                if not at_import or any(a <= hi and lo <= b for a, b in spans):
                    return False  # code that runs at import time
                continue
            first, last = inside[0]
            if any(a <= last and first <= b for a, b in spans):
                return False  # stage 2 runs this function, or one defined inside it
    return True


def changed_tasks(cache_dir, budget, max_share, only=None, partial=None):
    """The pool tasks whose stage 1 results in this process are not those of the pinned tree.
    None when a run of them would cost more than max_share of the whole test (by the times
    of the pinned tree, saved["share"]), or when there is no answer within budget CPU seconds.
    only: the pool tasks to look at (the others are known not to run the patched code).
    The queries whose run costs most next to their check come first, so that a patch that
    changes many of them is seen after a few."""
    saved = load(cache_dir)
    if not saved:
        return None
    out = []
    spent = 0.0
    old = signal.signal(signal.SIGVTALRM, _alarm)
    signal.setitimer(signal.ITIMER_VIRTUAL, max(0.05, budget))
    try:
        todo = queries()
        if [i for i, _ in todo] != saved["tasks"]:
            return None
        schema = _schema()
        for k in saved["order"]:
            i, sql = todo[k]
            if only is not None and i not in only:
                continue
            if stage_one(sql, schema) != saved["digests"][k]:
                out.append(i)
                spent += saved["share"][k]
                if spent > max_share:
                    if partial is not None:
                        partial.extend(out[:-1])  # the changed queries that still fit the limit
                    return None
        return sorted(out)
    except _OutOfTime:
        return None
    except Exception:  # noqa: BLE001
        return None
    finally:
        signal.setitimer(signal.ITIMER_VIRTUAL, 0)
        signal.signal(signal.SIGVTALRM, old)


def build(root, tables):
    """What the checks need from the pinned tree: the digests of stage 1, the files with a
    function that stage 2 runs, each query's share of the CPU time of all runs, the order of
    the checks and the two cheapest queries to run (the witnesses of the selector).
    tables: TestExecutor.tpcds_tables."""
    sqlglot = sys.modules["sqlglot"]
    executor = importlib.import_module("sqlglot.executor")
    helpers = importlib.import_module("tests.helpers")
    todo = queries()
    sqls = [sql for _, sql in todo]
    schema = _schema()
    digests = [stage_one(sql, schema) for sql in sqls]
    again = []
    check_cost = []
    for sql in sqls:
        t0 = time.process_time()
        again.append(stage_one(sql, schema))
        check_cost.append(time.process_time() - t0)
    if digests != again:
        raise RuntimeError("stage 1 does not repeat")
    run_cost = []

    mon = sys.monitoring
    tool = mon.PROFILER_ID
    codes = set()

    def on_start(code, offset):
        codes.add(code)
        return mon.DISABLE

    real = executor.optimize, executor.Plan

    def unrecorded(fn):  # stage 1
        def call(*args, **kwargs):
            mon.set_events(tool, 0)
            try:
                return fn(*args, **kwargs)
            finally:
                mon.set_events(tool, mon.events.PY_START)

        return call

    mon.use_tool_id(tool, "plancheck")
    mon.register_callback(tool, mon.events.PY_START, on_start)
    executor.optimize, executor.Plan = unrecorded(real[0]), unrecorded(real[1])
    try:
        for sql in sqls:
            expression = sqlglot.parse_one(sql)
            names = [t.name for t in sqlglot.find_tables(expression)]
            mon.set_events(tool, mon.events.PY_START)
            t0 = time.process_time()
            expression = pickle.loads(pickle.dumps(expression))
            table = executor.execute(expression, schema=helpers.TPCDS_SCHEMA, tables={n: tables[n] for n in names})
            table = pickle.loads(pickle.dumps(table))
            list(table.rows), list(table.columns)
            run_cost.append(time.process_time() - t0)
            mon.set_events(tool, 0)
    finally:
        executor.optimize, executor.Plan = real
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
    if "sqlglot/executor/python.py" not in spans:
        raise RuntimeError("stage 2 was not recorded")
    total = sum(run_cost)
    share = [c / total for c in run_cost]
    order = sorted(range(len(todo)), key=lambda k: -share[k] / max(check_cost[k], 1e-4))
    witness = sorted(todo[k][0] for k in sorted(range(len(todo)), key=run_cost.__getitem__)[:2])
    return {"tasks": [i for i, _ in todo], "digests": digests, "spans": {rel: sorted(v) for rel, v in spans.items()},
            "share": share, "order": order, "witness": witness}
