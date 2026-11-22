# Base: pinned python image.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1 \
    SKIP_INTEGRATION=0 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    BR_ROOT=/repo \
    BR_DATA=/data \
    BR_MAPS=/app/maps

# 1. third-party packages (PyPI only, exact versions, no dependency resolution)
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-deps --no-compile --disable-pip-version-check --root-user-action=ignore \
        -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# 2. sqlglot at the pinned commit (GitHub archive of sqlglot's own repo; no git, no apt)
COPY build/fetch_sqlglot.py /tmp/fetch_sqlglot.py
RUN python /tmp/fetch_sqlglot.py /repo b5e23dd1faff7c2a14ef374d02be8bab60c9343d6d3140690cbad12dbcc7764e \
    && rm /tmp/fetch_sqlglot.py

# 3. bytecode for everything that can be imported (stdlib, site-packages, sqlglot, tests), as
#    unchecked-hash pycs: the run disk is read-only, so nothing may be compiled or stat-checked there.
#    The official image ships the stdlib without any .pyc; pip's own pycs are timestamp-based (-f redoes them).
RUN python -m compileall -f -q -j 0 --invalidation-mode unchecked-hash /usr/local/lib/python3.13 /repo \
    && chmod -R a+rX /repo /usr/local/lib/python3.13

# CPU settings for the run (see the selector notes): a fixed hash seed (the saved base state of
# the import fingerprint depends on it) and mimalloc with transparent huge pages (cheaper fork,
# exit and page faults; no effect where the host has THP off).
ENV PYTHONHASHSEED=0 \
    PYTHONMALLOC=mimalloc \
    MIMALLOC_LARGE_OS_PAGES=1 \
    MIMALLOC_RESERVE_OS_MEMORY=256MiB \
    MIMALLOC_ARENA_EAGER_COMMIT=1 \
    MIMALLOC_PURGE_DELAY=-1

# CPU limits of the test runs of one commit (see the constants of selector.py).
ENV BR_COMMIT=2 \
    BR_FRESH=0.75

# 4. our program and maps (last, so that a code change rebuilds only this). The TestExecutor row
#    cache (preload.py) is built from the pinned csv files and checked against the real
#    setUpClass; if the check fails, the cache is removed and the selector runs setUpClass as before.
COPY app /app
RUN (python /app/build_exec_cache.py /repo /app/cache --check \
     || (echo "exec cache check failed; running without it" >&2; rm -rf /app/cache)) \
    && mkdir -p /app/cache \
    && (python /app/build_base_state.py /repo /app/cache/base_state.bin \
     || (echo "no saved base state; the selector computes it" >&2; rm -f /app/cache/base_state.bin)) \
    && python -m compileall -f -q --invalidation-mode unchecked-hash /app \
    && chmod -R a+rX /app

WORKDIR /repo
CMD ["python", "/app/main.py"]
