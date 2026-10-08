import shutil
import subprocess
from pathlib import Path

import pytest

from systemd_hardening_kit import analyze
from systemd_hardening_kit.analyze import AnalyzeError, Item


def test_parse_overview(fixtures):
    scores = analyze.parse_overview((fixtures / "overview.txt").read_text())
    assert len(scores) == 17
    first = scores[0]
    assert (first.unit, first.exposure, first.predicate) == ("ModemManager.service", 6.3, "MEDIUM")
    assert "getty@tty1.service" in {s.unit for s in scores}


def test_parse_overview_ignores_noise():
    assert analyze.parse_overview("UNIT EXPOSURE PREDICATE HAPPY\ngarbage line\n\n") == []


def test_parse_overall(fixtures):
    assert analyze.parse_overall((fixtures / "demo_security.txt").read_text()) == (9.0, "UNSAFE")
    assert analyze.parse_overall("-> Overall exposure level for x.service: 1.6 OK :-)") == (1.6, "OK")
    with pytest.raises(AnalyzeError):
        analyze.parse_overall("nothing here")


def test_parse_details(fixtures):
    items = analyze.parse_details((fixtures / "demo_details.json").read_text())
    by_field = {i.json_field: i for i in items}
    user = by_field["UserOrDynamicUser"]
    assert user.failing and user.exposure == 0.4
    assert user.directives == ["User", "DynamicUser"]
    assert not by_field["NoNewPrivileges"].failing
    assert by_field["SupplementaryGroups"].exposure is None


@pytest.mark.parametrize("bad", ["{not json", '{"a": 1}'])
def test_parse_details_rejects_garbage(bad):
    with pytest.raises(AnalyzeError):
        analyze.parse_details(bad)


def test_directives_of_complex_names():
    item = Item("CapabilityBoundingSet=~CAP_SET(UID|GID|PCAP)", "x", "", 0.3, False)
    assert item.directives == ["CapabilityBoundingSet"]


def test_top_issues_sorted_by_exposure(fixtures):
    score = analyze.UnitScore(
        "demo.service", 9.0, "UNSAFE", analyze.parse_details((fixtures / "demo_details.json").read_text())
    )
    exposures = [i.exposure for i in score.top_issues]
    assert exposures == sorted(exposures, reverse=True)
    assert all(i.failing for i in score.top_issues)


def test_load_dropins_profiles():
    profiles = analyze.load_dropins()
    assert set(profiles) == {"baseline", "strict", "no-network", "bind-low-port"}
    assert "NoNewPrivileges" in profiles["baseline"]
    assert "SystemCallFilter" in profiles["strict"]
    assert profiles["no-network"] >= {"PrivateNetwork", "IPAddressDeny"}


def test_recommend():
    root = Item("User=/DynamicUser=", "u", "", 0.4, False)
    nnp = Item("NoNewPrivileges=", "n", "", 0.2, False)
    caps = Item("CapabilityBoundingSet=~CAP_SYS_ADMIN", "c", "", 0.3, False)
    net = Item("RestrictAddressFamilies=~AF_(INET|INET6)", "r", "", 0.3, False)
    ok = Item("PrivateTmp=", "p", "", 0.0, True)
    assert analyze.recommend([nnp, caps]) == ["baseline", "strict"]
    assert analyze.recommend([caps]) == ["strict"]
    assert analyze.recommend([net, ok, root]) == []  # network policy is opt-in, User= is not in a profile


def test_validate_unit():
    assert analyze.validate_unit("getty@tty1.service") == "getty@tty1.service"
    for bad in ["nginx", "a b.service", "../x.service", "-h.service;rm", "x.socket"]:
        with pytest.raises(AnalyzeError):
            analyze.validate_unit(bad)


def test_run_uses_safe_env_and_no_shell(fake_analyze):
    analyze.overview()
    assert fake_analyze[0][:3] == ["/usr/bin/systemd-analyze", "security", "--no-pager"]


def test_unit_details(fake_analyze):
    score = analyze.unit_details("nginx.service")
    assert (score.unit, score.exposure, score.predicate) == ("nginx.service", 9.0, "UNSAFE")
    assert score.recommended == ["baseline", "strict"]
    assert fake_analyze[-1][3:] == ["--json=short", "nginx.service"]


def test_unit_details_offline(fake_analyze, tmp_path):
    unit = tmp_path / "app.service"
    unit.write_text("[Service]\nExecStart=/bin/true\n")
    score = analyze.unit_details(unit.name, offline_file=unit)
    assert fake_analyze[0][3:] == ["--offline=true", str(unit)]
    assert score.unit == "app.service"
    with pytest.raises(AnalyzeError, match="not found"):
        analyze.unit_details("x.service", offline_file=tmp_path / "missing.service")


def test_run_errors(monkeypatch):
    monkeypatch.setattr(analyze.shutil, "which", lambda *a, **k: None)
    with pytest.raises(AnalyzeError, match="not found"):
        analyze.run([])
    monkeypatch.setattr(analyze.shutil, "which", lambda *a, **k: "/usr/bin/systemd-analyze")

    def failing(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, "", "Failed to connect to bus: Host is down\n")

    monkeypatch.setattr(analyze.subprocess, "run", failing)
    with pytest.raises(AnalyzeError, match="Host is down"):
        analyze.run([])

    def slow(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(analyze.subprocess, "run", slow)
    with pytest.raises(AnalyzeError, match="timed out"):
        analyze.run([])


needs_systemd = pytest.mark.skipif(
    shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed"
)


@needs_systemd
def test_real_offline_analysis_of_template(fixtures):
    """Runs the real systemd-analyze in offline mode (no running systemd required)."""
    unit = Path(__file__).resolve().parents[1] / "units" / "example-webapp.service"
    try:
        score = analyze.unit_details(unit.name, offline_file=unit)
    except AnalyzeError as exc:  # pragma: no cover - very old systemd without --offline
        pytest.skip(str(exc))
    assert score.exposure <= 2.0
    assert score.predicate == "OK"
