"""Synthetic staged-index benchmark; never scans real user repositories."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tracemalloc
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secretlens.core import scan_index


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=10000)
    args = parser.parse_args()
    if not 1 <= args.files <= 10000:
        parser.error("files must be 1..10000")
    with tempfile.TemporaryDirectory() as temporary:
        repo = Path(temporary)
        subprocess.run(["git", "init", "--quiet", str(repo)], check=True, capture_output=True)
        for number in range(args.files):
            (repo / f"file-{number:05d}.txt").write_text(f"synthetic safe record {number}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
        original = subprocess.Popen
        count = 0
        def counting(*command, **kwargs):
            nonlocal count
            count += 1
            return original(*command, **kwargs)
        tracemalloc.start()
        start = time.perf_counter()
        with patch("secretlens.core.subprocess.Popen", side_effect=counting):
            report = scan_index(repo)
        elapsed = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert report["complete"] and report["clean"] and report["files_scanned"] == args.files
        assert count == 3
        print(json.dumps({"files": args.files, "indexed_bytes": report["bytes_scanned"],
                          "seconds": round(elapsed, 3), "git_processes": count,
                          "python_peak_bytes": peak,
                          "note": "One synthetic run; excludes setup and native Git RSS; not a production guarantee"}))


if __name__ == "__main__":
    main()
