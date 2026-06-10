.PHONY: setup run scan

# Build the SDK tarball first if it doesn't exist.
../../../ancilis-local.tgz:
	@echo "Building SDK tarball..."
	cd ../../../ && npm install --include=dev --prefer-offline && npm run build && npm pack && cp "ancilis-$$(node -p "require('./package.json').version").tgz" ancilis-local.tgz

setup: ../../../ancilis-local.tgz
	npm install --include=dev

run:
	npx tsx index.ts

scan:
	npx tsx index.ts
	npx ancilis scan --config ancilis.yaml
