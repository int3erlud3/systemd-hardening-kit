"""Run and parse ``systemd-analyze security`` (read-only)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

SAFE_ENV = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LANG": "C",
    "LC_ALL": "C",
    "SYSTEMD_COLORS": "0",
    "SYSTEMD_PAGER": "",
    "SYSTEMD_LESS": "",
}
UNIT_RE = re.compile(r"^[A-Za-z0-9:_.\\@-]{1,250}\.service$")
_OVERVIEW_RE = re.compile(r"^(?P<unit>\S+\.service)\s+(?P<exposure>\d+(?:\.\d+)?)\s+(?P<predicate>[A-Z]+)\b")
_OVERALL_RE = re.compile(
    r"Overall exposure level for (?P<unit>\S+): (?P<exposure>\d+(?:\.\d+)?) (?P<predicate>[A-Z]+)"
)


class AnalyzeError(RuntimeError):
    pass


@dataclass
class Item:
    name: str
    json_field: str
    description: str
    exposure: float | None
    set: bool | None

    @property
    def failing(self) -> bool:
        return self.set is False and bool(self.exposure)

    @property
    def directives(self) -> list[str]:
        # "User=/DynamicUser=" -> [User, DynamicUser]; "CapabilityBoundingSet=~CAP_SYS_ADMIN" -> [...]
        return re.findall(r"([A-Za-z]+)=", self.name)


@dataclass
class UnitScore:
    unit: str
    exposure: float
    predicate: str
    items: list[Item] = field(default_factory=list)
    recommended: list[str] = field(default_factory=list)

    @property
    def top_issues(self) -> list[Item]:
        failing = [i for i in self.items if i.failing]
        return sorted(failing, key=lambda i: (-(i.exposure or 0), i.name))


# ---- parsing -------------------------------------------------------------------
def parse_overview(text: str) -> list[UnitScore]:
    scores = []
    for line in text.splitlines():
        m = _OVERVIEW_RE.match(line.strip())
        if m:
            scores.append(UnitScore(m["unit"], float(m["exposure"]), m["predicate"]))
    return scores


def parse_overall(text: str) -> tuple[float, str]:
    m = _OVERALL_RE.search(text)
    if not m:
        raise AnalyzeError("no 'Overall exposure level' line in systemd-analyze output")
    return float(m["exposure"]), m["predicate"]


def parse_details(text: str) -> list[Item]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalyzeError(f"invalid JSON from systemd-analyze: {exc}") from exc
    if not isinstance(data, list):
        raise AnalyzeError("unexpected JSON structure from systemd-analyze")
    items = []
    for entry in data:
        exposure = entry.get("exposure")
        items.append(
            Item(
                name=str(entry.get("name", "")),
                json_field=str(entry.get("json_field", "")),
                description=str(entry.get("description", "")),
                exposure=float(exposure) if exposure not in (None, "") else None,
                set=entry.get("set"),
            )
        )
    return items


# ---- drop-in recommendations -----------------------------------------------------
def load_dropins() -> dict[str, set[str]]:
    """Profile name -> directive names set by the shipped drop-in."""
    profiles: dict[str, set[str]] = {}
    for res in sorted(resources.files("systemd_hardening_kit").joinpath("dropins").iterdir(), key=str):
        if not res.name.endswith(".conf"):
            continue
        keys = set()
        for raw in res.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith(("#", "[")) and "=" in line:
                keys.add(line.split("=", 1)[0].strip())
        profiles[res.name.removesuffix(".conf")] = keys
    return profiles


# Network exposure depends on what the service does; it is covered by the opt-in
# no-network profile and never triggers a generic recommendation.
NETWORK_DIRECTIVES = {"RestrictAddressFamilies", "PrivateNetwork", "IPAddressDeny", "IPAddressAllow"}


def recommend(items: list[Item], profiles: dict[str, set[str]] | None = None) -> list[str]:
    """Profiles (in apply order) that fix at least one failing setting.

    ``no-network`` and ``bind-low-port`` change behaviour, so they are never suggested
    automatically; only the generic baseline/strict profiles are.
    """
    profiles = load_dropins() if profiles is None else profiles
    failing = {d for i in items if i.failing for d in i.directives} - NETWORK_DIRECTIVES
    out = []
    for name in ("baseline", "strict"):
        if failing & profiles.get(name, set()):
            out.append(name)
    return out


# ---- running systemd-analyze -------------------------------------------------------
def _systemd_analyze() -> str:
    exe = shutil.which("systemd-analyze", path=SAFE_ENV["PATH"])
    if not exe:
        raise AnalyzeError("systemd-analyze not found (systemd >= 250 required)")
    return exe


def run(args: list[str], timeout: int = 60) -> str:
    cmd = [_systemd_analyze(), "security", "--no-pager", *args]
    try:
        proc = subprocess.run(  # noqa: S603  # nosec B603
            cmd, capture_output=True, text=True, timeout=timeout, env=SAFE_ENV, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalyzeError(f"systemd-analyze timed out after {timeout}s") from exc
    if proc.returncode != 0 and not proc.stdout.strip():
        msg = (proc.stderr.strip().splitlines() or ["unknown error"])[-1]
        raise AnalyzeError(f"systemd-analyze failed: {msg}")
    return proc.stdout


def validate_unit(unit: str) -> str:
    if not UNIT_RE.match(unit):
        raise AnalyzeError(f"invalid unit name: {unit!r} (expected NAME.service)")
    return unit


def overview() -> list[UnitScore]:
    return parse_overview(run([]))


def unit_details(unit: str, offline_file: Path | None = None) -> UnitScore:
    """Score + item list for one loaded unit, or for a unit file analysed offline."""
    if offline_file is not None:
        target = str(offline_file)
        extra = ["--offline=true"]
        if not offline_file.is_file():
            raise AnalyzeError(f"unit file not found: {offline_file}")
    else:
        target = validate_unit(unit)
        extra = []
    exposure, predicate = parse_overall(run([*extra, target]))
    items = parse_details(run([*extra, "--json=short", target]))
    score = UnitScore(unit, exposure, predicate, items)
    score.recommended = recommend(items)
    return score
