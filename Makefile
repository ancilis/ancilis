PYTHON ?= python3
NODE ?= node
NPM ?= npm

DEMO_DIR := examples/demo

.PHONY: help test-python test-typescript release-check demo demo-hosted demo-local demo-platform demo-discovery

help: ## Show all available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

test-python: ## Run Python test suite
	$(PYTHON) -m pytest python/tests -v

test-typescript: ## Run TypeScript test suite
	$(NPM) test

release-check: ## Run release pre-flight checks
	$(PYTHON) scripts/release_check.py

demo: ## Run the 30-second SDK demo
	@$(PYTHON) -c "import sys; v=sys.version_info; exit(0 if v>=(3,10) else 1)" 2>/dev/null || \
		{ echo "\033[31mError: Python 3.10+ required (found: $$($(PYTHON) --version 2>&1))\033[0m"; exit 1; }
	@bash $(DEMO_DIR)/setup.sh

demo-platform: ## Run the full SDK + Platform walkthrough
	@bash $(DEMO_DIR)/run-all.sh

demo-hosted: ## 30-second hosted demo (SDK -> Railway dashboard, no Docker required)
	@bash $(DEMO_DIR)/run-hosted.sh

demo-local: ## Self-contained local demo (no Docker, no Railway — SDK + local dashboard)
	@bash $(DEMO_DIR)/run-local.sh

demo-discovery: ## Run the multi-agent discovery demo
	@bash $(DEMO_DIR)/run-discovery.sh
