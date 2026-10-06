import argparse
import json
from pathlib import Path
import sys

from .core import DEFAULT_MAX_FINDINGS, ScanError, scan_index
from .policy import apply_policy, load_policy
from .hooks import install_hook, uninstall_hook


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline redacted secret gate for all indexed Git files")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--max-blob-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--max-total-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--max-files", type=int, default=10000)
    parser.add_argument("--max-findings", type=int, default=DEFAULT_MAX_FINDINGS,
                        help="total candidate occurrences; overflow fails closed, never truncates")
    parser.add_argument("--approvals", type=Path, help="Explicit trusted exact approval policy (never auto-loaded)")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--install-hook', action='store_true', help='Opt-in pre-commit gate; never overwrite an existing hook')
    actions.add_argument('--uninstall-hook', action='store_true', help='Remove only an unchanged generated hook')
    parser.add_argument('--python', type=Path, help='Installed isolated Python runtime for --install-hook')
    args = parser.parse_args(argv)
    try:
        if args.python is not None and not args.install_hook:
            raise ScanError('--python is only valid with --install-hook')
        if args.install_hook:
            report = install_hook(args.repo, python=args.python, approvals=args.approvals,
                                  max_blob_bytes=args.max_blob_bytes, max_total_bytes=args.max_total_bytes,
                                  max_files=args.max_files, max_findings=args.max_findings)
            print(json.dumps(report, ensure_ascii=True))
            return 0
        if args.uninstall_hook:
            report = uninstall_hook(args.repo)
            print(json.dumps(report, ensure_ascii=True))
            return 0
        report = scan_index(args.repo, max_blob_bytes=args.max_blob_bytes,
                            max_total_bytes=args.max_total_bytes, max_files=args.max_files,
                            max_findings=args.max_findings)
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
