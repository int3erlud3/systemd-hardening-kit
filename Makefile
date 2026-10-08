VENV ?= .venv
PY := $(VENV)/bin/python
GITLEAKS_IMAGE := ghcr.io/gitleaks/gitleaks:v8.30.1

.PHONY: all venv lint test security scan shell verify
all: lint test shell verify security

venv:
	python3 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -e ".[dev]" pip-audit

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

test:
	$(PY) -m pytest --cov=src --cov-report=term-missing

security:
	$(PY) -m bandit -c pyproject.toml -r src
	$(PY) -m pip_audit --skip-editable

scan:
	docker run --rm -v "$(CURDIR):/repo:ro" $(GITLEAKS_IMAGE) git /repo --redact --no-banner

SHELL_FILES := scripts/apply-dropin tests/mocks/systemctl tests/mocks/systemd-analyze tests/apply-dropin.bats tests/verify-units.sh

shell:
	shellcheck -x -S style $(SHELL_FILES)
	bats tests/apply-dropin.bats

verify:
	bash tests/verify-units.sh
