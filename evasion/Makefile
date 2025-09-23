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

.PHONY: help init run run-b64 run-xor dry-run clean test dropper embed bundle single

help:
	@echo "Targets: run run-b64 run-xor dry-run dropper embed bundle single clean test"
	@echo "Usage: make single INPUT=payload.exe DECODE_KEY=secret"

init:
	@mkdir -p $(OUT_DIR)

run run-b64 run-xor: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_KEY) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) \
	$(if $(findstring run-b64,$@),--base64-strings) \
	$(if $(findstring run-xor,$@),--xor-pack) \
	$(if $(findstring run,$@),--base64-strings --xor-pack) \
	--output $(OUTPUT)

dry-run:
	$(ENV_REDTEAM) $(ENV_KEY) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) transform $(INPUT) --base64-strings --xor-pack

dropper:
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_KEY) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) dropper $(INPUT) --xor

test:
	$(ENV_REDTEAM) $(ENV_LOG) $(ENV_PYTHONPATH) $(PYTHON) -m pytest

embed: init
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_KEY) $(ENV_LOG) \
	$(PYTHON) -m $(SRC_MODULE) embed $(INPUT) --base64-strings --xor-pack --embed-key --output $(OUT_DIR)/embedded_payload.py

bundle: embed
	$(ENV_REDTEAM) $(ENV_ACTIONS) $(ENV_LOG) \
	$(PYTHON) -m PyInstaller --onefile --name dropper --add-data "$(OUT_DIR)/embedded_payload.py:." src/rt_evade/dropper/standalone.py --distpath $(OUT_DIR)

single: clean
	$(MAKE) embed INPUT=$(INPUT) DECODE_KEY=$(DECODE_KEY) LOG_LEVEL=$(LOG_LEVEL)
	$(MAKE) bundle LOG_LEVEL=$(LOG_LEVEL)

clean:
	@rm -rf $(OUT_DIR) build dist *.spec __pycache__ .pytest_cache

