# Red-team evasion toolkit Makefile

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

.PHONY: help init run run-pe dry-run clean test dropper embed bundle single

help:
	@echo "Targets: run run-pe dry-run dropper embed bundle single clean test"
	@echo "Usage: make single INPUT=payload.exe -- PE obfuscation"
	@echo "       make run-pe INPUT=payload.exe -- PE obfuscation"

init:
	@mkdir -p $(OUT_DIR)

run run-pe: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) \
	$(if $(findstring run-pe,$@),--pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding) \
	$(if $(findstring run,$@),--pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding) \
	--output $(OUTPUT)

dry-run:
	$(ENV_REDTEAM) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) --pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding

dropper:
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_KEY) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) dropper $(INPUT) --xor

test:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest

embed: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) embed $(INPUT) --pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding --output $(OUT_DIR)/embedded_payload.py

bundle: embed
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) \
	$(PYTHON) -m PyInstaller --onefile --name dropper --add-data "$(OUT_DIR)/embedded_payload.py:." src/rt_evade/dropper/standalone.py --distpath $(OUT_DIR)

single: clean
	$(MAKE) embed INPUT=$(INPUT) DECODE_KEY=$(DECODE_KEY) LOG_LEVEL=$(LOG_LEVEL)
	$(MAKE) bundle LOG_LEVEL=$(LOG_LEVEL)

clean:
	@rm -rf $(OUT_DIR) build dist *.spec __pycache__ .pytest_cache

