PYTHON ?= python3
NODE ?= node
NPM ?= npm

.PHONY: test-python test-typescript release-check

test-python:
	$(PYTHON) -m pytest python/tests -v

test-typescript:
	$(NPM) test

release-check:
	$(PYTHON) scripts/release_check.py
