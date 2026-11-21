"""Planning rules for edits that the coverage maps of the pinned commit cannot see.

Facts read from the pinned source tree (only for the rare commits that need them): which test
files import a name, which files list directories, which conftest.py files can change a result,
which names a patch removes. Each rule follows from how Python and pytest load code.
"""
from __future__ import annotations

import ast
import os
import re
import sys
import types

import engine

ROOT = os.environ.get("BR_ROOT", "/repo")


def _indent(s):
    return len(s) - len(s.lstrip())


_SRC = {}


def test_files(maps):
    """{test file: [test numbers]} for the files of tests.json."""
    out = _SRC.get("test_files")
    if out is None:
        out = _SRC["test_files"] = {}
        for n, tid in enumerate(maps.meta["test_ids"]):
            out.setdefault(tid.split("::")[0], []).append(n)
    return out


def source(rel):
    text = _SRC.get(("src", rel))
    if text is None:
        try:
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            text = ""
        _SRC[("src", rel)] = text
    return text


def _tree_py_files():
    out = _SRC.get("tree")
    if out is None:
        out = _SRC["tree"] = []
        for top in ("sqlglot", "tests"):
            for d, _, names in os.walk(os.path.join(ROOT, top)):
                for name in names:
                    if name.endswith(".py"):
                        out.append(os.path.relpath(os.path.join(d, name), ROOT))
    return out


LISTING_WORDS = ("listdir", "scandir", "iterdir", "iter_modules", "walk_packages", "glob", "walk")


def _lists(text):
    # the substring test first: a regex that starts with \b scans slowly
    return any(w in text for w in LISTING_WORDS) and LISTING_RE.search(text) is not None


SCAN_RE = re.compile(r"\b(?:scandir|iterdir|r?glob)\s*\(|\bos\.walk\s*\(")


def install_listing_overlay(root, files):
    """Child side: os.listdir (which pkgutil.iter_modules uses) shows the files that the patch
    adds and hides the files that it deletes. The import system lists directories by itself."""
    adds, dels = {}, {}
    for rel, text in files.items():
        d, name = os.path.split(os.path.join(root, rel))
        (dels if text is None else adds).setdefault(d, set()).add(name)
    real = os.listdir

    def listdir(path="."):
        out = real(path)
        if isinstance(path, (str, os.PathLike)):
            key = os.path.abspath(os.fspath(path))
            if key in adds or key in dels:
                out = sorted((set(out) | adds.get(key, set())) - dels.get(key, set()))
        return out

    os.listdir = listdir


LISTING_RE = re.compile(r"\b(?:listdir|scandir|iterdir|iter_modules|walk_packages|r?glob)\s*\(|\bos\.walk\s*\(")


def listing_tests(maps):
    """Tests that can see a new or deleted file through a directory listing: the tests of the
    test files whose code calls a listing function. The 'listed' map also records the listings
    that the import system makes for itself, which do not depend on the files present.
    None when sqlglot's own code lists directories (then any test can)."""
    if "listers" not in _SRC:
        listers = set()
        for rel in _tree_py_files():
            if rel.startswith("sqlglot/") and _lists(source(rel)):
                listers = None
                break
        if listers is not None:
            for rel, numbers in test_files(maps).items():
                if _lists(source(rel)):
                    listers.update(numbers)
        _SRC["listers"] = listers
    return _SRC["listers"]


def referencing_tests(maps, word):
    """Tests that may load a module named 'word': tests of the test files that mention the
    name, and tests that import a sqlglot module that mentions it. Python imports a module
    only by its name, so a new module that no code names is never imported."""
    pat = re.compile(r"\b%s\b" % re.escape(word))
    found = set()
    files = test_files(maps)
    for rel in _tree_py_files():
        text = source(rel)
        if word not in text or not pat.search(text):
            continue
        if rel in files:
            found.update(files[rel])
        sid = maps.meta["importers"].get(rel)
        if sid:
            found.update(maps.tests(sid))
        elif rel.startswith("sqlglot/"):
            return None  # a module that mentions the name, with no known importers
    return found


def tests_under(maps, d):
    return {n for rel, numbers in test_files(maps).items() if not d or rel.startswith(d + "/") for n in numbers}


def _trivial_body(body):
    for st in body:
        if isinstance(st, ast.Pass) or (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant)):
            continue
        if isinstance(st, ast.Return) and (st.value is None or isinstance(st.value, ast.Constant)):
            continue
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Yield) and (st.value.value is None or isinstance(st.value.value, ast.Constant)):
            continue
        return False
    return True


def _conftest_harmless(text):
    """True when a conftest.py cannot change a test result. pytest imports a conftest.py
    before it runs the tests of its directory: a conftest that raises errors all of them, and
    hooks, autouse fixtures and top-level code can change any of them. Harmless here: a
    docstring, imports of existing standard library or pytest names, plain helper functions, fixtures
    that are not autouse (unittest test cases cannot request fixtures), hooks that do nothing."""
    import importlib

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and (node.level or not node.module):
                return False
            mods = [node.module] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
            for mod in mods:
                # only modules that cannot depend on the tree (and are safe to import here)
                top = mod.partition(".")[0]
                if top not in sys.stdlib_module_names and top != "pytest":
                    return False
                try:
                    m = importlib.import_module(mod)
                except Exception:  # noqa: BLE001
                    return False
                if isinstance(node, ast.ImportFrom):
                    for a in node.names:
                        if a.name == "*" or not hasattr(m, a.name):
                            return False
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                call = dec if isinstance(dec, ast.Call) else None
                target = call.func if call else dec
                name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
                if name != "fixture":
                    return False
                if call and any(k.arg == "autouse" and not (isinstance(k.value, ast.Constant) and not k.value.value)
                                for k in call.keywords) and not _trivial_body(node.body):
                    return False
            if node.name.startswith("pytest_") and not _trivial_body(node.body):
                return False
            continue
        return False
    return True


TOP_NAME_RE = re.compile(r"^(?:async\s+def|def|class)\s+(\w+)|^(\w+)\s*(?::[^=]*)?=(?!=)")
IMPORT_RE = re.compile(r"^(?:from\s+\S+\s+)?import\s+(.*)")


def _top_names(lines):
    """Names that lines at module or class level bind (with indentation, a line can also be
    in a function body; then the name is only a local one, and the extra candidates are
    only extra runs)."""
    names = set()
    for s in lines:
        s = s.strip()
        if not s:
            continue
        m = TOP_NAME_RE.match(s)
        if m:
            names.add(m.group(1) or m.group(2))
            continue
        m = IMPORT_RE.match(s)
        if m:
            for part in m.group(1).replace("(", " ").replace(")", " ").split(","):
                words = part.split()
                if words:
                    names.add(words[-1].split(".")[0])
    return names


def _name_importers(maps, module, names):
    """Tests of the test files that import one of 'names' from 'module' (from module import
    name): when the name is gone, the test file cannot be imported and all its tests fail."""
    pat = re.compile(r"^\s*from\s+%s\s+import\s+(\([^)]*\)|[^\n]*)" % re.escape(module), re.M)
    out = set()
    for rel, numbers in test_files(maps).items():
        text = source(rel)
        if module not in text:
            continue
        for m in pat.finditer(text):
            if any(re.search(r"\b%s\b" % re.escape(nm), m.group(1)) for nm in names):
                out.update(numbers)
                break
    return out


def _doc_consts(code):
    """Indexes of the constants that the code only stores into __doc__ (a class or module docstring)."""
    import dis

    doc, other = set(), set()
    ins = list(dis.get_instructions(code))
    for i, x in enumerate(ins):
        if x.opcode in dis.hasconst:
            nxt = ins[i + 1] if i + 1 < len(ins) else None
            if x.opname == "LOAD_CONST" and nxt is not None and nxt.opname == "STORE_NAME" and nxt.argval == "__doc__":
                doc.add(x.arg)
            else:
                other.add(x.arg)
    return doc - other


def equal_but_doc(a, b, pairs):
    """Like engine.deftime_equal, but a class or module docstring may differ. Nothing in the
    test files reads docstrings (checked by the caller), so such a change cannot change a result."""
    if (a.co_code != b.co_code or a.co_names != b.co_names or a.co_exceptiontable != b.co_exceptiontable
            or len(a.co_consts) != len(b.co_consts) or a.co_flags != b.co_flags):
        return False
    docs = None
    for i, (x, y) in enumerate(zip(a.co_consts, b.co_consts)):
        ix = isinstance(x, types.CodeType)
        if ix != isinstance(y, types.CodeType):
            return False
        if ix:
            fx = x.co_flags & engine.CO_OPTIMIZED
            if fx != (y.co_flags & engine.CO_OPTIMIZED):
                return False
            if fx:
                if x.co_name != y.co_name or x.co_qualname != y.co_qualname or len(x.co_freevars) != len(y.co_freevars):
                    return False
                pairs.append((x, y))
            elif not equal_but_doc(x, y, pairs):
                return False
        elif not engine._const_equal(x, y):
            if docs is None:
                docs = _doc_consts(a) & _doc_consts(b)
            if i not in docs or not (isinstance(x, str) and isinstance(y, str)):
                return False
    return True


def _name_reader_tests(maps, names, only=None, prefix=r"\b"):
    """Tests that run a line that mentions one of 'names' (coverage of the pinned commit):
    when a module or class attribute is renamed or removed, only such a line can fail.
    only: limit the search to these files. prefix: what must come before the name."""
    pat = re.compile(r"%s(?:%s)\b" % (prefix, "|".join(map(re.escape, sorted(names)))))
    out = set()
    files = test_files(maps)
    for rel in (only or _tree_py_files()):
        text = source(rel)
        if not any(nm in text for nm in names):
            continue
        hits = [i + 1 for i, s in enumerate(text.split("\n")) if any(nm in s for nm in names) and pat.search(s)]
        if not hits:
            continue
        rec = maps.file(rel)
        if rec is None:
            out.update(files.get(rel, ()))
            continue
        stmt_set = rec[3]
        for ln in hits:
            if ln < len(stmt_set) and stmt_set[ln]:
                out.update(maps.tests(stmt_set[ln]))
    return out


PYTEST_CONFIGS = frozenset(("tox.ini", "setup.cfg", "pyproject.toml"))  # with a pytest section
STD_BASES = frozenset((
    "Enum", "IntEnum", "StrEnum", "Flag", "IntFlag", "object", "str", "int", "float", "bytes", "dict",
    "list", "tuple", "set", "frozenset", "Exception", "BaseException", "ValueError", "TypeError",
    "KeyError", "RuntimeError", "NamedTuple", "TypedDict", "Protocol", "Generic", "ABC",
))
CLASS_RE = re.compile(r"\s*class\s+\w+\s*(?:\((.*)\))?\s*:")


def _enclosing_bases(lines, idx):
    """Base class names of the class whose body holds line idx (0-based) directly; None when
    the line is in a function body or at module level."""
    ind = _indent(lines[idx])
    for j in range(idx - 1, -1, -1):
        s = lines[j]
        if not s.strip() or _indent(s) >= ind or s.lstrip().startswith(("@", "#", ")")):
            continue
        if s.lstrip().startswith("class "):
            m = CLASS_RE.match(s)
            bases = (m.group(1) or "") if m else ""
            return [b.strip().split(".")[-1].split("[")[0] for b in bases.split(",") if b.strip() and "=" not in b]
        return None
    return None


def _defined_elsewhere(name, rel, line):
    """True when some class body in sqlglot (other than at rel:line) defines the attribute."""
    pat = re.compile(r"^\s+(?:async\s+def\s+|def\s+|class\s+)?%s\b\s*[(:=]" % re.escape(name), re.M)
    for other in _tree_py_files():
        if not other.startswith("sqlglot/"):
            continue
        text = source(other)
        if name not in text:
            continue
        for m in pat.finditer(text):
            if other != rel or text.count("\n", 0, m.start()) + 1 != line:
                return True
    return False


def gone_name_tests(maps, fp, old_text):
    """Candidates for an import-time edit that removes or renames names. A module-level name
    breaks 'from module import name' in test files and the lines of its module that use it. A
    class attribute or method breaks the lines that read it, unless a base class can still
    give one (then the coverage maps already cover the change). Returns (names, tests)."""
    old_lines = old_text.split("\n")
    added = set()
    for g in fp.groups:
        added |= _top_names(g[5])
    top, attrs = set(), set()
    for g in fp.groups:
        for k, s in enumerate(g[4]):
            names = _top_names([s]) - added
            if not names:
                continue
            if not s[:1].isspace():
                top |= names
                continue
            idx = g[0] - 1 + k
            bases = _enclosing_bases(old_lines, idx) if idx < len(old_lines) else None
            if bases is None:
                continue  # a local name of a function
            for nm in names:
                if all(b in STD_BASES for b in bases) or not _defined_elsewhere(nm, fp.old_path, idx + 1):
                    attrs.add(nm)
    out = set()
    if top:
        mod = fp.old_path[:-3].replace("/", ".")
        if mod.endswith(".__init__"):
            mod = mod[: -len(".__init__")]
        out |= _name_importers(maps, mod, top)
        out |= _name_reader_tests(maps, top, only=[fp.old_path])
        out |= _name_reader_tests(maps, top, prefix=r"\b%s\s*\.\s*" % re.escape(mod.rpartition(".")[2]))
    if attrs:
        out |= _name_reader_tests(maps, attrs)
    return top | attrs, out


DOC_READ_RE = re.compile(r"__doc__|getdoc|doctest")


def tests_read_docs(maps):
    if "docs" not in _SRC:
        _SRC["docs"] = any(DOC_READ_RE.search(source(rel)) for rel in test_files(maps))
    return _SRC["docs"]


def importer_tests(maps, names):
    """Tests that load one of the modules 'names' (dotted). pytest imports the package of
    every test file below it (the maps do not list package __init__ files as imported)."""
    out = set()
    for name in names:
        rel = name.replace(".", "/")
        for cand in (rel + ".py", rel + "/__init__.py"):
            sid = maps.meta["importers"].get(cand)
            if sid:
                out.update(maps.tests(sid))
        if rel.partition("/")[0] == "tests" and os.path.isdir(os.path.join(ROOT, rel)):
            out.update(tests_under(maps, rel))
    return out


# pytest reads its options from these files in the directory of the tests or above it; the
# direct runs here do not. pytest.ini (and pytest.toml) count even without a section.
PYTEST_OWN_CONFIGS = frozenset(("pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml"))
PYTEST_SECTION_RE = re.compile(r"^\s*\[(?:pytest|tool:pytest|tool\.pytest[^\]]*)\]", re.M)


def pytest_scope(maps, fp, path, old_text):
    """Tests that a pytest-only file in the patch can change, selected without a run:
    None when the file is not one that pytest reads.
    conftest.py: pytest imports it before the tests below its directory (see _conftest_harmless).
    Configuration files: every test (options such as filterwarnings, addopts, markers)."""
    base = os.path.basename(path)
    if "conftest.py" in (base, os.path.basename(fp.old_path or "")):
        if fp.status == "add" and _conftest_harmless(fp.new_text):
            return set()
        return tests_under(maps, os.path.dirname(path))
    if base in PYTEST_OWN_CONFIGS:
        return tests_under(maps, "")
    if base in PYTEST_CONFIGS:
        if any(PYTEST_SECTION_RE.search(t) for t in (old_text, fp.new_text) if t):
            return tests_under(maps, "")
    return None


def shadows_module(path):
    """True for a new top-level .py file whose name is that of a standard or installed module:
    the checkout is on sys.path ahead of them, so every import of that name gets the new file."""
    import importlib.util

    if "/" in path or not path.endswith(".py"):
        return False
    name = path[:-3]
    try:
        return name in sys.stdlib_module_names or importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return True


def statement_around_lambda(old_lines, start, end, line, old_line, new_line):
    """The coverage map gives a line that holds a lambda to the tests that run the lambda.
    When the edit on such a line is outside the lambda, it changes the statement around the
    lambda, and tests that never call the lambda can see it (for instance "a and f(lambda: x)"
    edited to "a or f(lambda: x)"). Returns (first, last) line of that statement, else None.
    old_lines[start - 1:end] is the top-level statement (function, method) that holds the line."""
    import ast

    text = old_lines[start - 1:end]
    if not any("lambda" in t for t in text):
        return None
    shift = start - 1
    src = "\n".join(text)
    if text and text[0][:1] in (" ", "\t"):
        src = "if 1:\n" + src
        shift = start - 2
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return (start, end)
    at = line - shift
    lambdas = [n for n in ast.walk(tree) if isinstance(n, ast.Lambda) and n.lineno <= at <= n.end_lineno]
    if not lambdas:
        return None
    # the changed columns of the old line, in bytes (ast columns are UTF-8 offsets)
    a = old_line.encode("utf-8", "surrogateescape")
    b = new_line.encode("utf-8", "surrogateescape")
    p = 0
    while p < len(a) and p < len(b) and a[p] == b[p]:
        p += 1
    s = 0
    while s < len(a) - p and s < len(b) - p and a[len(a) - 1 - s] == b[len(b) - 1 - s]:
        s += 1
    lo, hi = p, len(a) - s
    inner = min(lambdas, key=lambda n: (n.end_lineno - n.lineno, -n.col_offset))
    inside = (at > inner.lineno or lo > inner.col_offset) and (at < inner.end_lineno or hi < inner.end_col_offset)
    if inside:
        return None
    best = None
    for n in ast.walk(tree):
        if not isinstance(n, ast.stmt) or n is tree.body[0] and shift == start - 2:
            continue
        first = n.lineno
        decos = getattr(n, "decorator_list", None)
        if decos:
            first = min(first, min(d.lineno for d in decos))
        last = n.end_lineno
        body = getattr(n, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.AST):
            b0 = body[0].lineno
            fd = getattr(body[0], "decorator_list", None)
            if fd:
                b0 = min(b0, min(d.lineno for d in fd))
            if first <= at <= b0 - 1:
                last = b0 - 1  # the header of a compound statement
        if first <= at <= last and (best is None or last - first < best[1] - best[0]):
            best = (first, last)
    if best is None:
        return (start, end)
    return (best[0] + shift, best[1] + shift)
