#!/usr/bin/env python3
"""Decode URL-encoded Lumma Stealer HTTP POST exfiltration payloads."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import unquote_plus


def decode_payload(raw: str) -> str:
    lines: list[str] = []
    for field in raw.split("&"):
        if "=" not in field:
            continue
        key, _, value = field.partition("=")
        decoded = unquote_plus(value)
        lines.append(f"\n=== {key} ===")
        try:
            lines.append(json.dumps(json.loads(decoded), indent=2))
        except json.JSONDecodeError:
            lines.append(decoded)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode Lumma Stealer URL-encoded POST bodies exported from Wireshark."
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        help="Exported HTTP object file (reads stdin if omitted)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write decoded output to this file instead of stdout",
    )
    args = parser.parse_args()

    raw = args.input.read_text(encoding="utf-8", errors="replace") if args.input else sys.stdin.read()
    result = decode_payload(raw)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result, encoding="utf-8")
    else:
        sys.stdout.write(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
