from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .redactor import redact_identifiers
from .scanner import DPDPScanner, format_markdown, format_table

DEMO_CORPUS = [
    (
        "Employee onboarding record: Ramesh Kumar, PAN: ABCDE1234F, Aadhaar: 2345 6789 0124. Contact: 9876543210.",
        {"consent_verified": True, "purpose": "payroll"},
    ),
    (
        "Quarterly AWS architecture documentation: Ingress controller routing via Traefik service mesh.",
        {"consent_verified": True, "purpose": "technical_docs"},
    ),
    (
        "Support request from user ankit@upi: Transaction failed for GSTIN 27AAAAA0000A1Z5.",
        None,  # missing consent and purpose metadata
    ),
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dpdp-rag-audit",
        description="Automated compliance linter and privacy scanner for RAG knowledge bases under India DPDP Act 2023.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan document(s) or vector chunks for privacy violations")
    scan_parser.add_argument("target", nargs="?", default="", help="File path or directory path to scan")
    scan_parser.add_argument("--demo", action="store_true", help="Run scan on built-in demo RAG corpus")
    scan_parser.add_argument("--format", choices=["table", "markdown", "json"], default="table", help="Output format")

    # redact
    redact_parser = subparsers.add_parser("redact", help="Sanitize and mask Indian identifiers in a file")
    redact_parser.add_argument("target", help="File to redact")
    redact_parser.add_argument("-o", "--output", help="Output path (default: stdout)")
    redact_parser.add_argument("--in-place", action="store_true", help="Modify file in-place")

    return parser


def handle_scan(args: argparse.Namespace) -> int:
    scanner = DPDPScanner()

    if args.demo or not args.target:
        report = scanner.scan_corpus(DEMO_CORPUS)
    else:
        p = Path(args.target)
        if not p.exists():
            print(f"Error: Target '{args.target}' does not exist.", file=sys.stderr)
            return 2

        items: list[tuple[str, dict | None]] = []
        files = [p] if p.is_file() else list(p.rglob("*.txt")) + list(p.rglob("*.md")) + list(p.rglob("*.json"))

        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                items.append((content, None))
            except Exception as e:
                print(f"Skipping {f}: {e}", file=sys.stderr)

        report = scanner.scan_corpus(items)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif args.format == "markdown":
        print(format_markdown(report))
    else:
        print(format_table(report))

    return 1 if report.status == "NON_COMPLIANT" else 0


def handle_redact(args: argparse.Namespace) -> int:
    p = Path(args.target)
    if not p.is_file():
        print(f"Error: '{args.target}' is not a valid file.", file=sys.stderr)
        return 2

    content = p.read_text(encoding="utf-8", errors="replace")
    cleaned, count = redact_identifiers(content)

    if args.in_place:
        p.write_text(cleaned, encoding="utf-8")
        print(f"Redacted {count} personal identifiers in '{args.target}' (in-place).")
    elif args.output:
        Path(args.output).write_text(cleaned, encoding="utf-8")
        print(f"Wrote sanitized content to '{args.output}' ({count} identifiers redacted).")
    else:
        sys.stdout.write(cleaned)

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return handle_scan(args)
    elif args.command == "redact":
        return handle_redact(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
