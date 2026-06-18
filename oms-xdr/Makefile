VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

.PHONY: install test lint run-once scan-quick scan-full clean

install:
	python3 -m venv $(VENV)
	$(PIP) install -U pip
	$(PIP) install -e ".[dev]"

test:
	$(VENV)/bin/pytest

lint:
	$(VENV)/bin/ruff check oms_xdr tests

run-once:
	$(PY) -m oms_xdr.engine --once --config $(or $(CONFIG),config.yaml)

scan-quick:
	$(PY) -m oms_xdr.netscan --mode quick --config $(or $(CONFIG),config.yaml)

scan-full:
	$(PY) -m oms_xdr.netscan --mode full --config $(or $(CONFIG),config.yaml)

clean:
	rm -rf $(VENV) **/__pycache__ .pytest_cache .ruff_cache *.egg-info
