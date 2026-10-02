SHELL := /bin/bash

UV ?= uv
PYTHON_VERSION ?= 3.12
VENV_PYTHON := .venv/bin/python
UV_RUN := $(UV) run --frozen

.PHONY: install start test smoke lint check-venv

install:
	$(UV) sync --frozen --python $(PYTHON_VERSION)

check-venv:
	@test -x $(VENV_PYTHON) || (echo "Missing .venv. Run 'make install' first."; exit 1)

start: check-venv
	$(UV_RUN) -m server

test: check-venv
	$(UV_RUN) pytest -q

smoke: check-venv
	$(UV_RUN) scripts/smoke_test.py

lint: check-venv
	$(UV_RUN) ruff check .
