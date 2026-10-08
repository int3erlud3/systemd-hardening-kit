import json

import pytest

from systemd_hardening_kit import cli


def test_input_file_ranked_text(fixtures, capsys):
    rc = cli.main(["--input", str(fixtures / "overview.txt"), "--top", "3", "--no-banner"])
    out = capsys.readouterr().out
    assert rc == 0
    lines = out.splitlines()
    assert "user@1000.service" in lines[1] and "9.8" in lines[1]
    assert "accounts-daemon.service" in lines[2]  # ties sorted by name
    assert "3 unit(s), average exposure" in out


def test_input_min_exposure_and_fail_above(fixtures, capsys):
    rc = cli.main(["--input", str(fixtures / "overview.txt"), "--min-exposure", "9.5", "--fail-above", "9.0"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "nginx.service" not in out and "ssh.service" in out


def test_fail_above_not_exceeded(fixtures, capsys):
    assert cli.main(["--input", str(fixtures / "overview.txt"), "--fail-above", "9.9"]) == 0


def test_json_output(fake_analyze, capsys):
    rc = cli.main(["--format", "json", "--details", "--top", "2"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert [u["rank"] for u in data["units"]] == [1, 2]
    assert data["units"][0]["unit"] == "user@1000.service"
    assert data["units"][0]["recommended_dropins"] == ["baseline", "strict"]
    assert len(data["units"][0]["issues"]) == 5
    assert {"setting", "exposure", "description"} == set(data["units"][0]["issues"][0])


def test_unit_details_text(fake_analyze, capsys):
    rc = cli.main(["--unit", "nginx.service", "--issues", "2"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "nginx.service" in out and "PrivateNetwork=" in out
    assert "suggested drop-ins: baseline, strict" in out


def test_errors_exit_3(fixtures, tmp_path, capsys, fake_analyze):
    empty = tmp_path / "empty.txt"
    empty.write_text("nothing\n")
    assert cli.main(["--input", str(empty)]) == 3
    assert cli.main(["--input", str(tmp_path / "missing.txt")]) == 3
    assert cli.main(["--unit", "bad name"]) == 3
    assert "error:" in capsys.readouterr().err


def test_list_dropins(capsys):
    assert cli.main(["--list-dropins", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "NoNewPrivileges" in data["baseline"]


def test_control_characters_are_neutralised(tmp_path, capsys):
    f = tmp_path / "o.txt"
    f.write_text("evil\x1b[31m.service 9.0 UNSAFE x\n")
    cli.main(["--input", str(f)])
    assert "\x1b" not in capsys.readouterr().out


@pytest.mark.parametrize("argv", [["--min-exposure", "11"], ["--unit", "a.service", "--input", "x"]])
def test_bad_arguments(argv):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2
