import argparse
import json
from pathlib import Path
import sys

from .core import ScanError, scan_index
from .policy import apply_policy, load_policy


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline redacted secret gate for all indexed Git files")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--max-blob-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--max-total-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--max-files", type=int, default=10000)
    parser.add_argument("--approvals", type=Path, help="Explicit trusted exact approval policy (never auto-loaded)")
    args = parser.parse_args(argv)
    try:
        report = scan_index(args.repo, max_blob_bytes=args.max_blob_bytes,
                            max_total_bytes=args.max_total_bytes, max_files=args.max_files)
        if args.approvals:
            report = apply_policy(report, load_policy(args.approvals))
    except ScanError as exc:
        print(json.dumps({"version": 1, "complete": False, "clean": False,
                          "error": str(exc)}, ensure_ascii=True))
        return 2
    # ASCII JSON safely represents control characters and undecodable Git paths.
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report["clean"] else 1


if __name__ == "__main__":
    sys.exit(main())
