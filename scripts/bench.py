#!/usr/bin/env python3
"""Measure SAFE-EXEC performance and record the numbers in the README.

Two workloads matter in practice:

* ``scan`` — static analysis throughput, bounded by the AST node budget;
* ``hash`` — streaming SHA-256 memory behaviour for large files.

Usage:
    python scripts/bench.py
    python scripts/bench.py --iterations 20 --json
    python scripts/bench.py --size 4096
"""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from safeexec.cli import hash_file  # noqa: E402
from safeexec.policy import PolicyRules, StaticPolicyEvaluator  # noqa: E402
from safeexec.resources import packaged_rules_path  # noqa: E402


def bench_scan(sample: bytes, iterations: int) -> dict[str, float]:
    rules = PolicyRules.load(packaged_rules_path())
    evaluator = StaticPolicyEvaluator(packaged_rules_path(), rules=rules)
    source = sample.decode("utf-8")
    evaluator.evaluate(source)  # warm-up
    start = time.perf_counter()
    for _ in range(iterations):
        evaluator.evaluate(source)
    elapsed = (time.perf_counter() - start) / iterations
    megabytes = len(sample) / 1_000_000
    return {
        "source_bytes": len(sample),
        "seconds_per_scan": round(elapsed, 6),
        "megabytes_per_second": round(megabytes / elapsed, 3) if elapsed else 0.0,
        "within_byte_limit": len(sample) <= rules.max_source_bytes,
    }


def bench_hash(size_mb: int) -> dict[str, float]:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "blob.py"
        chunk = b"# padding line for hashing\n" * 40_000
        written = 0
        with target.open("wb") as stream:
            while written < size_mb * 1_000_000:
                stream.write(chunk)
                written += len(chunk)
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        start = time.perf_counter()
        digest = hash_file(target)
        elapsed = time.perf_counter() - start
        after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        assert digest == hashlib.sha256(target.read_bytes()).hexdigest()
        return {
            "file_megabytes": round(target.stat().st_size / 1_000_000, 2),
            "seconds": round(elapsed, 4),
            "peak_rss_delta_mb": round(max(0, after - before) / 1024, 2),
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="bench.py",
        description="Benchmark static scanning and streaming hashing.",
    )
    parser.add_argument("--iterations", type=int, default=50, help="scan iterations (default 50)")
    parser.add_argument("--size", type=int, default=256, help="hash file size in MiB (default 256)")
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    args = parser.parse_args()

    sample = ("value = 1\nprint(value)\n" * 400).encode()
    results = {
        "scan_small": bench_scan(sample, args.iterations),
        "scan_python_3_11": sys.version.split()[0],
    }
    results["hash"] = bench_hash(args.size)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        scan = results["scan_small"]
        print(f"Python {sys.version.split()[0]}")
        print(f"scan  {scan['source_bytes']:>8} B  {scan['seconds_per_scan'] * 1000:>8.3f} ms  "
              f"{scan['megabytes_per_second']:>7.3f} MB/s")
        hashed = results["hash"]
        print(f"hash  {hashed['file_megabytes']:>8.2f} MB  {hashed['seconds']:>8.3f} s  "
              f"peak RSS delta {hashed['peak_rss_delta_mb']:.2f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
