.PHONY: setup run scan

# Build the SDK tarball first if it doesn't exist
../../../ancilis-0.1.0.tgz:
	@echo "Building SDK tarball..."
	cd ../../../ && npm install --include=dev --prefer-offline && npm run build && npm pack

setup: ../../../ancilis-0.1.0.tgz
	npm install --include=dev

run:
	npx tsx index.ts

scan:
	npx tsx index.ts
	npx ancilis scan --config ancilis.yaml
