# Red-team evasion toolkit Makefile
# Modular PE obfuscation with specialized components

PYTHON ?= python
SRC_MODULE ?= src
OUT_DIR ?= out
INPUT ?= samples/sample.bin
INPUT_DIR ?= samples
OUTPUT ?= $(OUT_DIR)/out.bin
OUTPUT_DIR ?= $(OUT_DIR)
CUSTOM_OUTPUT_DIR ?= $(OUTPUT_DIR)
DECODE_KEY ?= secret
LOG_LEVEL ?= INFO
UPX ?= 1
UPX_ARGS ?=

# Common env vars
ENV_REDTEAM = REDTEAM_MODE=true
ENV_ACTIONS = ALLOW_ACTIONS=true
ENV_KEY = DECODE_KEY=$(DECODE_KEY)
ENV_LOG = LOG_LEVEL=$(LOG_LEVEL)
ENV_PYTHONPATH = PYTHONPATH=src
ENV_UPX = USE_UPX=$(UPX)
ENV_UPX_ARGS = UPX_ARGS=$(UPX_ARGS)
ENV_RUST_CRYPTER = RUST_CRYPTER_PATH=$(PWD)/rust-crypter

.PHONY: help init run run-pe run-crypt dry-run clean test dropper embed bundle single test-modules test-compression test-encryption test-strings test-sections test-rust-crypter batch-obfuscate batch-crypt batch-dry-run docker-build docker-run docker-clean

help:
	@echo "=== PE Evasion Toolkit - Modular Components ==="
	@echo ""
	@echo "Main Targets:"
	@echo "  run              - Basic PE obfuscation (mimicry + strings + imports) [UPX on by default]"
	@echo "  run-pe           - Full PE obfuscation (all modules enabled) [UPX on by default]"
	@echo "                     Disable packing with UPX=0. Extra flags via UPX_ARGS=\"--best --lzma\""
	@echo "  run-crypt        - PE obfuscation + Rust-Crypter encryption (no packing/compression)"
	@echo "  dry-run          - Show obfuscation plan without file writes"
	@echo "  single           - One-shot: embed + bundle to standalone dropper"
	@echo "  batch-obfuscate  - Obfuscate all binaries in a folder"
	@echo "  batch-crypt      - Obfuscate + Rust-Crypter encrypt all binaries in a folder"
	@echo "  batch-dry-run    - Show what would be obfuscated without doing it"
	@echo ""
	@echo "Specialized Module Targets:"
	@echo "  test-compression - Test compression module only"
	@echo "  test-encryption  - Test encryption module only"
	@echo "  test-strings     - Test string obfuscation module only"
	@echo "  test-sections    - Test section manipulation module only"
	@echo "  test-rust-crypter- Test Rust-Crypter integration module only"
	@echo "  test-modules     - Test all specialized modules"
	@echo ""
	@echo "Utility Targets:"
	@echo "  test             - Run all tests (134 tests)"
	@echo "  dropper          - Execute obfuscated PE via dropper"
	@echo "  embed            - Embed PE into Python module"
	@echo "  bundle           - Create standalone executable"
	@echo "  clean            - Remove all build artifacts"
	@echo ""
	@echo "Docker Targets:"
	@echo "  docker-build     - Build Docker image for PE evasion toolkit"
	@echo "  docker-run       - Run PE obfuscation in Docker container"
	@echo "  docker-clean     - Remove Docker images and containers"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make run INPUT=payload.exe"
	@echo "  make run-pe INPUT=payload.exe OUTPUT=out/obfuscated.exe"
	@echo "  make run-crypt INPUT=payload.exe OUTPUT=out/encrypted.exe"
	@echo "  make single INPUT=payload.exe DECODE_KEY=mykey"
	@echo "  make batch-obfuscate INPUT_DIR=samples/"
	@echo "  make batch-crypt INPUT_DIR=samples/"
	@echo "  make test-compression"
	@echo "  make test-rust-crypter"
	@echo "  make docker-build"
	@echo "  make docker-run INPUT=payload.exe"

init:
	@mkdir -p $(OUT_DIR)

# Main obfuscation targets
run: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) $(ENV_UPX) $(ENV_UPX_ARGS) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) \
	--pe-obfuscate --pe-mimicry --pe-strings --pe-imports \
	$$( [ "$(UPX)" = "1" ] && echo --pe-packer || true ) \
	--output $(OUTPUT)

run-pe: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) $(ENV_UPX) $(ENV_UPX_ARGS) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) \
	--pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding --pe-compression --pe-encryption \
	$$( [ "$(UPX)" = "1" ] && echo --pe-packer || true ) \
	--output $(OUTPUT)

run-crypt: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) $(ENV_RUST_CRYPTER) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) \
	--pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding --pe-encryption \
	--pe-rust-crypter \
	--output $(OUTPUT)

dry-run:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_UPX) $(ENV_UPX_ARGS) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) \
	--pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding --pe-compression --pe-encryption \
	$$( [ "$(UPX)" = "1" ] && echo --pe-packer || true )

# Specialized module testing
test-modules: test-compression test-encryption test-strings test-sections test-rust-crypter
	@echo "All specialized modules tested successfully!"

test-compression:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest tests/test_pe_compression.py -v

test-encryption:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest tests/test_pe_encryption.py -v

test-strings:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest tests/test_pe_string_obfuscation.py -v

test-sections:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest tests/test_pe_section_manipulation.py -v

test-rust-crypter:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest tests/test_rust_crypter_integration.py -v

# Integration and utility targets
test:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest -v

dropper:
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_KEY) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) dropper $(INPUT) --xor

embed: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) embed $(INPUT) \
	--pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding --pe-compression --pe-encryption \
	$$( [ "$(UPX)" = "1" ] && echo --pe-packer || true ) \
	--output $(OUT_DIR)/embedded_payload.py

bundle: embed
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) \
	$(PYTHON) -m PyInstaller --onefile --name dropper \
	--add-data "$(OUT_DIR)/embedded_payload.py:." \
	src/rt_evade/dropper/standalone.py --distpath $(OUT_DIR)

single: clean
	$(MAKE) embed INPUT=$(INPUT) DECODE_KEY=$(DECODE_KEY) LOG_LEVEL=$(LOG_LEVEL)
	$(MAKE) bundle LOG_LEVEL=$(LOG_LEVEL)

# Batch obfuscation target
batch-obfuscate: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) $(ENV_PYTHONPATH) \
	$(PYTHON) -m src.batch_obfuscate $(INPUT_DIR) \
	--output-dir $(OUTPUT_DIR) \
	--pe-mimicry --pe-strings --pe-imports --pe-padding --pe-compression --pe-encryption

# Batch Rust-Crypter encryption target
batch-crypt: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) $(ENV_PYTHONPATH) $(ENV_RUST_CRYPTER) \
	$(PYTHON) -m src.batch_obfuscate $(INPUT_DIR) \
	--output-dir $(OUTPUT_DIR) \
	--pe-mimicry --pe-strings --pe-imports --pe-padding --pe-encryption \
	--pe-rust-crypter

# Batch obfuscation dry run
batch-dry-run:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) \
	$(PYTHON) -m src.batch_obfuscate $(INPUT_DIR) \
	--output-dir $(OUTPUT_DIR) \
	--pe-mimicry --pe-strings --pe-imports --pe-padding --pe-compression --pe-encryption \
	--dry-run

clean:
	@rm -rf $(OUT_DIR) build dist *.spec __pycache__ .pytest_cache
	@echo "Cleaned all build artifacts"

# Docker targets
docker-build:
	@echo "Building Docker image for PE evasion toolkit..."
	docker build -t pe-evasion .
	@echo "Docker image 'pe-evasion' built successfully"

docker-run: docker-build
	@echo "Running PE obfuscation in Docker container..."
	@if [ -z "$(INPUT)" ]; then \
		echo "Error: INPUT is required for docker-run"; \
		echo "Usage: make docker-run INPUT=path/to/file"; \
		exit 1; \
	fi
	@if [ ! -e "$(INPUT)" ]; then \
		echo "Error: Input file '$(INPUT)' does not exist"; \
		exit 1; \
	fi
	@mkdir -p $(OUT_DIR)
	docker run --rm \
		-v "$(PWD)/$(INPUT):/input/$(INPUT)" \
		-v "$(PWD)/$(OUTPUT_DIR):/output" \
		pe-evasion \
		--input "/input/$(INPUT)" \
		--output-dir /output \
		--log-level $(LOG_LEVEL)
	@echo "Docker processing complete. Check $(OUTPUT_DIR) for output files."

docker-clean:
	@echo "Cleaning Docker images and containers..."
	docker rmi pe-evasion 2>/dev/null || true
	docker container prune -f
	@echo "Docker cleanup complete"
