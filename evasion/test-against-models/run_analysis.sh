#!/bin/bash

# Comprehensive Model Analysis Runner
# This script runs the full analysis against all 17 models

echo "🚀 Starting Comprehensive Model Analysis"
echo "========================================"
echo "This will test all 17 models and create comprehensive visualizations"
echo ""

# Check if main.py exists
if [ ! -f "main.py" ]; then
    echo "❌ Error: main.py not found in current directory"
    exit 1
fi

# Check if run_all_models.py exists
if [ ! -f "run_all_models.py" ]; then
    echo "❌ Error: run_all_models.py not found in current directory"
    exit 1
fi

# Make sure we have the required Python packages
echo "📦 Checking dependencies..."
python3 -c "import requests, matplotlib, numpy, pandas, tqdm" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Installing required packages..."
    pip3 install requests matplotlib numpy pandas tqdm
fi

echo ""
echo "🎯 Starting analysis with optimized settings:"
echo "   - Threads per model: 4 (optimized for localhost API)"
echo "   - Timeout per model: 300 seconds"
echo "   - Models: 1-17"
echo ""
echo "Press Ctrl+C to cancel, or wait 5 seconds to start..."
sleep 5

# Run the comprehensive analysis
python3 run_all_models.py --timeout 300

echo ""
echo "🎉 Analysis complete!"
echo "Check the generated files for results and visualizations."
