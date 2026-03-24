#!/bin/bash
# NCC-Sign Profiling Build & Run Script
# Builds and runs profiling for all parameter sets (1, 3, 5) × (clean, optimized)
#
# Usage:
#   ./run_profile.sh          # Build and run all
#   ./run_profile.sh build    # Build only
#   ./run_profile.sh run      # Run only (assumes already built)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMMON_DIR="$BASE_DIR/common"
BENCH_DIR="$SCRIPT_DIR"

CC="${CC:-gcc}"

SOURCES_NAMES=(packing.c poly.c reduce.c rounding.c sign.c symmetric-shake.c)
PROFILE_SRC="$BENCH_DIR/profile_bench.c"

MODE="${1:-all}"

build_one() {
    local SIGN_LEVEL=$1   # 1, 3, or 5
    local IMPL=$2         # clean or optimized
    local SIGN_DIR="$BASE_DIR/crypto_sign/NCC-Sign${SIGN_LEVEL}/${IMPL}"
    local OUTPUT="profile_Sign${SIGN_LEVEL}_${IMPL}"

    if [ ! -d "$SIGN_DIR" ]; then
        echo "  [SKIP] $SIGN_DIR does not exist"
        return
    fi

    echo "  [BUILD] NCC-Sign${SIGN_LEVEL} (${IMPL}) -> ${OUTPUT}"

    # Build source file array with full paths
    local SRC_FILES=()
    for f in "${SOURCES_NAMES[@]}"; do
        SRC_FILES+=("$SIGN_DIR/$f")
    done

    local COMMON_FILES=(
        "$COMMON_DIR/cpucycles.c"
        "$COMMON_DIR/randombytes.c"
        "$COMMON_DIR/fips202.c"
        "$COMMON_DIR/fips202x2.c"
    )

    "$CC" -Wall -Wextra -O3 -fomit-frame-pointer \
        -I"$COMMON_DIR" -I"$SIGN_DIR" \
        -o "$BENCH_DIR/$OUTPUT" \
        "$PROFILE_SRC" \
        "${SRC_FILES[@]}" \
        "${COMMON_FILES[@]}"

    echo "  [OK]    $OUTPUT"
}

run_one() {
    local SIGN_LEVEL=$1
    local IMPL=$2
    local OUTPUT="profile_Sign${SIGN_LEVEL}_${IMPL}"
    local BIN="$BENCH_DIR/$OUTPUT"

    if [ ! -f "$BIN" ]; then
        echo "  [SKIP] $BIN not found (build first)"
        return
    fi

    echo ""
    echo "################################################################"
    echo "# Running: NCC-Sign${SIGN_LEVEL} (${IMPL})"
    echo "################################################################"
    "$BIN"
}

# Build
if [ "$MODE" = "all" ] || [ "$MODE" = "build" ]; then
    echo "=== Building profiling binaries ==="
    for LEVEL in 1 3 5; do
        for IMPL in clean optimized; do
            build_one $LEVEL $IMPL
        done
    done
    echo ""
    echo "=== Build complete ==="
fi

# Run
if [ "$MODE" = "all" ] || [ "$MODE" = "run" ]; then
    echo ""
    echo "=== Running profiling benchmarks ==="
    for LEVEL in 1 3 5; do
        for IMPL in clean optimized; do
            run_one $LEVEL $IMPL
        done
    done
    echo ""
    echo "=== All profiling complete ==="
fi
