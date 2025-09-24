# PE Evasion Toolkit Docker Image
# Ubuntu 22.04 base with Python 3.10 and all dependencies

FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV REDTEAM_MODE=true
ENV ALLOW_ACTIONS=true
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Create output directory
RUN mkdir -p /app/out

# Create entrypoint script
RUN cat > /app/entrypoint.sh << 'EOF'
#!/bin/bash
set -e

# Default values
INPUT_PATH=""
OUTPUT_DIR="/app/out"
LOG_LEVEL="INFO"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --input)
            INPUT_PATH="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --help)
            echo "PE Evasion Toolkit Docker Container"
            echo ""
            echo "Usage: docker run -v /path/to/input:/input -v /path/to/output:/output pe-evasion [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --input PATH        Input file or directory (required)"
            echo "  --output-dir PATH   Output directory (default: /app/out)"
            echo "  --log-level LEVEL   Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)"
            echo "  --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  # Process a single file"
            echo "  docker run -v /host/samples:/input -v /host/output:/output pe-evasion --input /input/payload.exe"
            echo ""
            echo "  # Process a directory of files"
            echo "  docker run -v /host/samples:/input -v /host/output:/output pe-evasion --input /input"
            echo ""
            echo "  # Custom output directory"
            echo "  docker run -v /host/samples:/input -v /host/output:/output pe-evasion --input /input --output-dir /output/obfuscated"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if input path is provided
if [ -z "$INPUT_PATH" ]; then
    echo "Error: --input is required"
    echo "Use --help for usage information"
    exit 1
fi

# Check if input path exists
if [ ! -e "$INPUT_PATH" ]; then
    echo "Error: Input path '$INPUT_PATH' does not exist"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Set log level environment variable
export LOG_LEVEL="$LOG_LEVEL"

# Add current directory to Python path for module imports
export PYTHONPATH="/app:$PYTHONPATH"

# Determine if input is a file or directory
if [ -f "$INPUT_PATH" ]; then
    echo "Processing single file: $INPUT_PATH"
    # Single file processing
    python3 -m src transform "$INPUT_PATH" \
        --pe-obfuscate --pe-mimicry --pe-strings --pe-imports --pe-padding --pe-compression --pe-encryption \
        --output "$OUTPUT_DIR/$(basename "$INPUT_PATH")"
elif [ -d "$INPUT_PATH" ]; then
    echo "Processing directory: $INPUT_PATH"
    # Directory processing (batch obfuscation)
    python3 -m src.batch_obfuscate "$INPUT_PATH" \
        --output-dir "$OUTPUT_DIR" \
        --pe-mimicry --pe-strings --pe-imports --pe-padding --pe-compression --pe-encryption
else
    echo "Error: Input path '$INPUT_PATH' is neither a file nor a directory"
    exit 1
fi

echo "Processing complete. Output saved to: $OUTPUT_DIR"
EOF

# Make entrypoint script executable
RUN chmod +x /app/entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command (will show help)
CMD ["--help"]
