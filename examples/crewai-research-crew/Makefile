.PHONY: setup run scan

setup:
	python -m venv .venv
	.venv/bin/pip install -r requirements.txt

run:
	.venv/bin/python main.py

scan:
	.venv/bin/ancilis scan --config ancilis.yaml
