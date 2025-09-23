# Red-team evasion toolkit Makefile
# Modular PE obfuscation with specialized components

PYTHON ?= python
SRC_MODULE ?= src
OUT_DIR ?= out
INPUT ?= samples/sample.bin
OUTPUT ?= $(OUT_DIR)/out.bin
DECODE_KEY ?= secret
LOG_LEVEL ?= INFO

# Common env vars
ENV_REDTEAM = REDTEAM_MODE=true
ENV_ACTIONS = ALLOW_ACTIONS=true
ENV_KEY = DECODE_KEY=$(DECODE_KEY)
ENV_LOG = LOG_LEVEL=$(LOG_LEVEL)
ENV_PYTHONPATH = PYTHONPATH=src

.PHONY: help init run run-pe dry-run clean test dropper embed bundle single test-modules test-compression test-encryption test-strings test-sections

help:
	@echo "=== PE Evasion Toolkit - Modular Components ==="
	@echo ""
	@echo "Main Targets:"
	@echo "  run              - Basic PE obfuscation (mimicry + strings + imports)"
	@echo "  run-pe           - Full PE obfuscation (all modules enabled)"
	@echo "  dry-run          - Show obfuscation plan without file writes"
	@echo "  single           - One-shot: embed + bundle to standalone dropper"
	@echo ""
	@echo "Specialized Module Targets:"
	@echo "  test-compression - Test compression module only"
	@echo "  test-encryption  - Test encryption module only"
	@echo "  test-strings     - Test string obfuscation module only"
	@echo "  test-sections    - Test section manipulation module only"
	@echo "  test-modules     - Test all specialized modules"
	@echo ""
	@echo "Utility Targets:"
	@echo "  test             - Run all tests (134 tests)"
	@echo "  dropper          - Execute obfuscated PE via dropper"
	@echo "  embed            - Embed PE into Python module"
	@echo "  bundle           - Create standalone executable"
	@echo "  clean            - Remove all build artifacts"
	@echo ""
	@echo "Usage Examples:"
	@echo "  make run INPUT=payload.exe"
	@echo "  make run-pe INPUT=payload.exe OUTPUT=out/obfuscated.exe"
	@echo "  make single INPUT=payload.exe DECODE_KEY=mykey"
	@echo "  make test-compression"

init:
	@mkdir -p $(OUT_DIR)

# Main obfuscation targets
run: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) \
	--pe-obfuscate --pe-mimicry --pe-strings --pe-imports \
	--output $(OUTPUT)

run-pe: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) \
	--pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding --pe-compression --pe-encryption \
	--output $(OUTPUT)

dry-run:
	$(ENV_REDTEAM) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) \
	--pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding --pe-compression --pe-encryption

# Specialized module testing
test-modules: test-compression test-encryption test-strings test-sections
	@echo "All specialized modules tested successfully!"

test-compression:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest tests/test_pe_compression.py -v

test-encryption:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest tests/test_pe_encryption.py -v

test-strings:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest tests/test_pe_string_obfuscation.py -v

test-sections:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest tests/test_pe_section_manipulation.py -v

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
	--output $(OUT_DIR)/embedded_payload.py

bundle: embed
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) \
	$(PYTHON) -m PyInstaller --onefile --name dropper \
	--add-data "$(OUT_DIR)/embedded_payload.py:." \
	src/rt_evade/dropper/standalone.py --distpath $(OUT_DIR)

single: clean
	$(MAKE) embed INPUT=$(INPUT) DECODE_KEY=$(DECODE_KEY) LOG_LEVEL=$(LOG_LEVEL)
	$(MAKE) bundle LOG_LEVEL=$(LOG_LEVEL)

clean:
	@rm -rf $(OUT_DIR) build dist *.spec __pycache__ .pytest_cache
	@echo "Cleaned all build artifacts"

