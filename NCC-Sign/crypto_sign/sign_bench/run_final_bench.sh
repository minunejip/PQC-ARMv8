#!/bin/bash
#
# run_final_bench.sh - Build and run all NCC-Sign benchmarks
#
# Usage:
#   sudo ./run_final_bench.sh [output_csv]
#
# Default output: results_m1pro_final.csv in the sign_bench directory

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRYPTO_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT="${1:-${SCRIPT_DIR}/results_m1pro_final.csv}"

# Remove old results if starting fresh
if [ -f "$OUTPUT" ]; then
    echo "[!] $OUTPUT exists. Removing for fresh run."
    rm -f "$OUTPUT"
fi

echo "============================================="
echo " NCC-Sign Final Benchmark"
echo " Output: $OUTPUT"
echo "============================================="
echo ""

SIGNS="NCC-Sign1 NCC-Sign3 NCC-Sign5"
BUILDS="clean optimized"

# Phase 1: Build all
echo "[Phase 1] Building all targets..."
for sign in $SIGNS; do
    for build in $BUILDS; do
        dir="$CRYPTO_DIR/$sign/$build"
        echo "  Building $sign/$build..."
        (cd "$dir" && make clean > /dev/null 2>&1 && make final_bench > /dev/null 2>&1)
    done
done
echo "[Phase 1] All builds complete."
echo ""

# Phase 2: Run benchmarks
echo "[Phase 2] Running benchmarks..."
for sign in $SIGNS; do
    for build in $BUILDS; do
        dir="$CRYPTO_DIR/$sign/$build"
        echo ""
        echo "---------------------------------------------"
        echo " Running $sign / $build"
        echo "---------------------------------------------"
        "$dir/final_bench" "$OUTPUT"
    done
done

echo ""
echo "============================================="
echo " All benchmarks complete!"
echo " Results: $OUTPUT"
echo "============================================="

# Phase 3: Run analysis if Python is available
if command -v python3 &> /dev/null; then
    echo ""
    echo "[Phase 3] Running analysis..."
    python3 "$SCRIPT_DIR/analyze_results.py" "$OUTPUT"
else
    echo ""
    echo "[Phase 3] python3 not found, skipping analysis."
    echo "  Run manually: python3 $SCRIPT_DIR/analyze_results.py $OUTPUT"
fi
