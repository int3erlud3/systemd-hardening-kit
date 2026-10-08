from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def fake_analyze(monkeypatch):
    """Replace subprocess.run for systemd-analyze with canned outputs."""
    calls: list[list[str]] = []
    overview = (FIXTURES / "overview.txt").read_text()
    text = (FIXTURES / "demo_security.txt").read_text()
    details = (FIXTURES / "demo_details.json").read_text()

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        assert kwargs["env"]["LC_ALL"] == "C"
        assert kwargs.get("shell") is not True
        args = cmd[3:]
        if any(a.startswith("--json") for a in args):
            out = details
        elif args:
            out = text.replace("demo.service", Path(args[-1]).name)
        else:
            out = overview
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(
        "systemd_hardening_kit.analyze.shutil.which", lambda *a, **k: "/usr/bin/systemd-analyze"
    )
    monkeypatch.setattr("systemd_hardening_kit.analyze.subprocess.run", fake_run)
    return calls
