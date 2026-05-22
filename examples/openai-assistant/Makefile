.PHONY: setup run scan

PYTHON ?= python3

setup:
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -q -e ../..
	.venv/bin/pip install -q -r requirements.txt

run:
	.venv/bin/python main.py

scan:
	.venv/bin/ancilis scan --config ancilis.yaml
