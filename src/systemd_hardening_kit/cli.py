"""systemd-hardening-kit: ranked report of ``systemd-analyze security`` exposure."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .analyze import AnalyzeError, UnitScore, load_dropins, overview, parse_overview, unit_details
from .banner import maybe_print_banner, maybe_print_banner_for_info

EPILOG = """\
examples:
  systemd-hardening-kit                         rank all services on this host
  systemd-hardening-kit --details --top 5       top 5 with their biggest gaps
  systemd-hardening-kit --unit nginx.service    one unit in detail
  systemd-hardening-kit --unit-file units/example-webapp.service   offline, no systemd needed
  systemd-analyze security > scores.txt; systemd-hardening-kit --input scores.txt

exit codes: 0 OK, 1 a unit is above --fail-above, 3 error
"""


def _exposure(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        number = -1.0
    if not 0 <= number <= 10:
        raise argparse.ArgumentTypeError("must be between 0 and 10")
    return number


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="systemd-hardening-kit",
        description="Rank services by systemd-analyze security exposure and suggest hardening drop-ins.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--unit", action="append", default=[], metavar="NAME.service", help="analyse unit(s)")
    src.add_argument(
        "--unit-file",
        action="append",
        default=[],
        type=Path,
        metavar="FILE",
        help="analyse unit file offline",
    )
    src.add_argument(
        "--input", type=Path, metavar="FILE", help="parse saved 'systemd-analyze security' output"
    )
    p.add_argument("--details", action="store_true", help="fetch per-setting details for the listed units")
    p.add_argument("--top", type=int, default=0, metavar="N", help="only the N most exposed units")
    p.add_argument("--min-exposure", type=_exposure, default=0.0, metavar="X", help="hide units below X")
    p.add_argument("--fail-above", type=_exposure, metavar="X", help="exit 1 if any unit is above X")
    p.add_argument("--issues", type=int, default=5, metavar="N", help="issues shown per unit (default 5)")
    p.add_argument("--list-dropins", action="store_true", help="list the shipped drop-in profiles and exit")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--no-banner", action="store_true", help="do not print the banner (or set NO_BANNER=1)")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def collect(args: argparse.Namespace) -> list[UnitScore]:
    if args.unit_file:
        return rank(
            [unit_details(f.name, offline_file=f) for f in args.unit_file], args.min_exposure, args.top
        )
    if args.unit:
        return rank([unit_details(u) for u in args.unit], args.min_exposure, args.top)
    if args.input:
        scores = parse_overview(args.input.read_text(encoding="utf-8"))
        if not scores:
            raise AnalyzeError(f"no unit scores found in {args.input}")
    else:
        scores = overview()
        if not scores:
            raise AnalyzeError("systemd-analyze returned no services (is systemd running?)")
    scores = rank(scores, args.min_exposure, args.top)
    if args.details and not args.input:
        scores = [unit_details(s.unit) for s in scores]
    return scores


def rank(scores: list[UnitScore], min_exposure: float = 0.0, top: int = 0) -> list[UnitScore]:
    ranked = sorted((s for s in scores if s.exposure >= min_exposure), key=lambda s: (-s.exposure, s.unit))
    return ranked[:top] if top > 0 else ranked


def to_dict(scores: list[UnitScore], issues: int) -> dict:
    return {
        "tool": "systemd-hardening-kit",
        "version": __version__,
        "units": [
            {
                "rank": n,
                "unit": s.unit,
                "exposure": s.exposure,
                "predicate": s.predicate,
                "recommended_dropins": s.recommended,
                "issues": [
                    {"setting": i.name, "exposure": i.exposure, "description": i.description}
                    for i in s.top_issues[:issues]
                ],
            }
            for n, s in enumerate(scores, 1)
        ],
    }


def _clean(text: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def render_text(scores: list[UnitScore], issues: int) -> str:
    lines = [f"{'#':>3}  {'UNIT':<44} {'EXPOSURE':>8}  PREDICATE"]
    for n, s in enumerate(scores, 1):
        lines.append(f"{n:>3}  {_clean(s.unit):<44} {s.exposure:>8.1f}  {s.predicate}")
        for i in s.top_issues[:issues]:
            lines.append(f"       - {_clean(i.name):<40} +{i.exposure:.1f}  {_clean(i.description)}")
        if s.recommended:
            lines.append(f"       > suggested drop-ins: {', '.join(s.recommended)}")
    if scores:
        avg = sum(s.exposure for s in scores) / len(scores)
        worst = scores[0]
        summary = f"{len(scores)} unit(s), average exposure {avg:.1f}"
        lines += ["", f"{summary}, worst {_clean(worst.unit)} ({worst.exposure:.1f})"]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    maybe_print_banner_for_info(argv)
    args = build_parser().parse_args(argv)
    if args.format != "json":
        maybe_print_banner(args.no_banner)

    if args.list_dropins:
        profiles = load_dropins()
        if args.format == "json":
            print(json.dumps({k: sorted(v) for k, v in profiles.items()}, indent=2))
        else:
            for name, keys in profiles.items():
                print(f"{name:<14} {', '.join(sorted(keys))}")
        return 0

    try:
        scores = collect(args)
    except (AnalyzeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.format == "json":
        print(json.dumps(to_dict(scores, args.issues), indent=2))
    else:
        print(render_text(scores, args.issues))
    if args.fail_above is not None and any(s.exposure > args.fail_above for s in scores):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
