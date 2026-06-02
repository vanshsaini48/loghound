"""Memory and throughput tests for the streaming pipeline.

Validates NFR-1.1 (throughput >= 100 MB / 30 s) and NFR-1.3 (constant memory).
Skipped by default — run with:
    LOGHOUND_PERF=1 PYTHONPATH=src pytest tests/test_memory_throughput.py -v
"""
import os
import resource
import sys
import time
from pathlib import Path

import pytest
import yaml

# Skip unless explicitly opted in — keeps the normal 48-test suite fast
pytestmark = pytest.mark.skipif(
    not os.environ.get("LOGHOUND_PERF"),
    reason="Set LOGHOUND_PERF=1 to run performance tests",
)

# Inline import of the generator (tests/ isn't on sys.path by default)
sys.path.insert(0, str(Path(__file__).parent))
from generate_large_log import generate_log

from loghound.parsers.detector import detect_and_parse
from loghound.engine import run_engine

TARGET_MB = 100
MAX_RSS_MB = 400
MIN_THROUGHPUT_MBS = 3.3  # 100 MB in 30 s


def _peak_rss_mb():
    """Current peak resident set size in MB."""
    ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return ru / (1024 * 1024)   # macOS: bytes
    return ru / 1024                # Linux: KB


@pytest.fixture(scope="module")
def large_log(tmp_path_factory):
    path = tmp_path_factory.mktemp("perf") / "large_auth.log"
    generate_log(str(path), target_mb=TARGET_MB)
    return path


@pytest.fixture(scope="module")
def config():
    cfg_path = Path(__file__).parent / "fixtures" / "test_config.yaml"
    with open(cfg_path) as f:
        return yaml.safe_load(f)


def test_memory_constant(large_log, config):
    """Peak RSS stays under MAX_RSS_MB when processing a large log."""
    _, events_iter = detect_and_parse(large_log)
    findings = run_engine(events_iter, config)

    peak = _peak_rss_mb()
    assert peak < MAX_RSS_MB, (
        f"Peak RSS {peak:.0f} MB exceeds {MAX_RSS_MB} MB "
        f"({TARGET_MB} MB log, {len(findings)} findings)"
    )


def test_throughput(large_log, config):
    """Throughput meets NFR-1.1: >= 3.3 MB/s."""
    file_mb = large_log.stat().st_size / (1024 * 1024)

    start = time.monotonic()
    _, events_iter = detect_and_parse(large_log)
    findings = run_engine(events_iter, config)
    elapsed = time.monotonic() - start

    throughput = file_mb / elapsed
    assert throughput >= MIN_THROUGHPUT_MBS, (
        f"Throughput {throughput:.1f} MB/s < {MIN_THROUGHPUT_MBS} MB/s "
        f"({file_mb:.0f} MB in {elapsed:.1f}s, {len(findings)} findings)"
    )
