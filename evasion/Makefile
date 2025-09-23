# Simple Makefile to run the evasion toolkit and manage outputs

PYTHON ?= python
SRC_MODULE ?= src
SAMPLES_DIR ?= samples
OUT_DIR ?= out

# Defaults (override with make VAR=value)
INPUT ?= $(SAMPLES_DIR)/sample.bin
OUTPUT ?= $(OUT_DIR)/out.bin
DECODE_KEY ?= secret
LOG_LEVEL ?= INFO

.PHONY: help init run run-b64 run-xor dry-run clean test

help:
	@echo "Targets:"
	@echo "  make run        - run with base64+xor, write $(OUTPUT) (creates $(OUT_DIR))"
	@echo "  make run-b64    - run with base64 only, write $(OUTPUT)"
	@echo "  make run-xor    - run with xor only, write $(OUTPUT)"
	@echo "  make dry-run    - run transforms without writing output"
	@echo "  make clean      - remove $(OUT_DIR) and generated binaries"
	@echo "Variables (override: make VAR=value): INPUT, OUTPUT, DECODE_KEY, LOG_LEVEL"

init:
	@mkdir -p $(OUT_DIR)

run: init
	REDTEAM_MODE=true \
	ALLOW_ACTIONS=true \
	DECODE_KEY=$(DECODE_KEY) \
	LOG_LEVEL=$(LOG_LEVEL) \
	$(PYTHON) -m $(SRC_MODULE) $(INPUT) --base64-strings --xor-pack --output $(OUTPUT)

run-b64: init
	REDTEAM_MODE=true \
	ALLOW_ACTIONS=true \
	LOG_LEVEL=$(LOG_LEVEL) \
	$(PYTHON) -m $(SRC_MODULE) $(INPUT) --base64-strings --output $(OUTPUT)

run-xor: init
	REDTEAM_MODE=true \
	ALLOW_ACTIONS=true \
	DECODE_KEY=$(DECODE_KEY) \
	LOG_LEVEL=$(LOG_LEVEL) \
	$(PYTHON) -m $(SRC_MODULE) $(INPUT) --xor-pack --output $(OUTPUT)

dry-run:
	REDTEAM_MODE=true \
	DECODE_KEY=$(DECODE_KEY) \
	LOG_LEVEL=$(LOG_LEVEL) \
	$(PYTHON) -m $(SRC_MODULE) $(INPUT) --base64-strings --xor-pack

clean:
	@rm -rf $(OUT_DIR)

test:
	REDTEAM_MODE=true \
	LOG_LEVEL=$(LOG_LEVEL) \
	PYTHONPATH=src \
	$(PYTHON) -m pytest

