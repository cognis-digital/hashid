"""Command-line interface for HASHID.

Subcommands:
  identify   classify hash type(s) only
  estimate   identify + brute-force feasibility estimate

Exit codes:
  0  no actionable finding (unknown / unidentifiable input)
  1  a hash type was identified (a "finding")
  2  usage / runtime error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import analyze


def _read_inputs(args) -> list[str]:
    values: list[str] = list(args.value or [])
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    values.append(line)
    return values


def _print_table(results: list[dict], with_estimate: bool) -> None:
    for r in results:
        best = r["analysis"]["best_guess"]
        print(f"input: {r['value']!r}  (len={r['analysis']['input_length']})")
        print(f"  best guess : {best['name']} "
              f"[mode={best['hashcat_mode']}] "
              f"conf={best['confidence']:.2f} ({best['category']})")
        print(f"  reason     : {best['reason']}")
        others = r["analysis"]["candidates"][1:4]
        if others:
            alt = ", ".join(f"{c['name']}({c['confidence']:.2f})"
                            for c in others)
            print(f"  also maybe : {alt}")
        if with_estimate and r["analysis"]["crack_estimate"]:
            est = r["analysis"]["crack_estimate"]
            print(f"  crack est  : {est['feasibility'].upper()} — "
                  f"~{est['human_time']} avg "
                  f"(brute {est['assumed_charset_size']}^"
                  f"{est['assumed_password_len']} @ "
                  f"{est['ref_guesses_per_sec']:.1e} g/s)")
            for note in est["notes"]:
                print(f"    - {note}")
        print()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Identify hash types and estimate crack feasibility "
                    "(defensive/authorized triage only — no cracking).")
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=["table", "json"],
                        default="table", help="output format")

    sub = parser.add_subparsers(dest="command", required=True)

    def _add_common(p):
        p.add_argument("value", nargs="*", help="hash string(s)")
        p.add_argument("-f", "--file", help="file with one hash per line")

    p_id = sub.add_parser("identify", help="classify hash type(s)")
    _add_common(p_id)

    p_est = sub.add_parser("estimate",
                           help="identify + crack-cost feasibility")
    _add_common(p_est)
    p_est.add_argument("--charset", type=int, default=95,
                       help="assumed charset size (default 95 printable)")
    p_est.add_argument("--length", type=int, default=8,
                       help="assumed password length (default 8)")

    args = parser.parse_args(argv)

    # Validate numeric parameters before doing any I/O.
    charset = getattr(args, "charset", 95)
    length = getattr(args, "length", 8)
    if charset < 2:
        print(
            f"error: --charset must be >= 2, got {charset}",
            file=sys.stderr)
        return 2
    if length < 1:
        print(
            f"error: --length must be >= 1, got {length}",
            file=sys.stderr)
        return 2

    try:
        values = _read_inputs(args)
    except OSError as exc:
        print(f"error: cannot read file: {exc}", file=sys.stderr)
        return 2

    if not values:
        print("error: no hash input provided", file=sys.stderr)
        return 2

    with_estimate = args.command == "estimate"

    results = []
    any_identified = False
    try:
        for v in values:
            a = analyze(v, charset_size=charset, password_len=length)
            if not with_estimate:
                a["crack_estimate"] = None
            best = a.get("best_guess")
            if best and best["name"] != "unknown":
                any_identified = True
            results.append({"value": v, "analysis": a})
    except (TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps({
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "command": args.command,
            "results": results,
        }, indent=2))
    else:
        _print_table(results, with_estimate)

    # Non-zero exit when something was identified (a finding to act on).
    return 1 if any_identified else 0


if __name__ == "__main__":
    sys.exit(main())
