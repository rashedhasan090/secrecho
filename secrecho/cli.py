"""CLI entry point for secrecho."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence

from . import __version__
from .detect import (
    SEVERITY_RANK,
    audit,
    filter_by_fail_on,
    format_json,
    format_md,
    format_text,
    load_trace,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secrecho",
        description=(
            "Find secrets that first appear in tool results and later echo into "
            "tool-call arguments, assistant replies, or memory writes."
        ),
    )
    p.add_argument("trace", help="Agent transcript (JSONL or JSON array)")
    p.add_argument(
        "--format",
        choices=("text", "json", "md"),
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "info"),
        default=None,
        help="Exit 1 if any finding meets or exceeds this severity",
    )
    p.add_argument(
        "--ignore-kind",
        action="append",
        default=[],
        metavar="KIND",
        help="Secret kind to ignore (repeatable), e.g. jwt",
    )
    p.add_argument(
        "--min-len",
        type=int,
        default=12,
        help="Minimum secret length to track (default: 12)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"secrecho {__version__}",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        messages = load_trace(args.trace)
    except (OSError, ValueError) as e:
        print(f"secrecho: {e}", file=sys.stderr)
        return 2

    findings = audit(
        messages,
        ignore_kinds=set(args.ignore_kind or []),
        min_len=args.min_len,
    )

    if args.format == "json":
        print(format_json(messages, findings))
    elif args.format == "md":
        print(format_md(messages, findings))
    else:
        print(format_text(messages, findings))

    if args.fail_on:
        gated = filter_by_fail_on(findings, args.fail_on)
        if gated:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
