#!/bin/bash
# Build and run the robust benchmark for all 6 variants
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMMON_DIR="$BASE_DIR/common"
BENCH_DIR="$SCRIPT_DIR"

CC="${CC:-gcc}"
SOURCES_NAMES=(packing.c poly.c reduce.c rounding.c sign.c symmetric-shake.c)
BENCH_SRC="$BENCH_DIR/robust_bench.c"

MODE="${1:-all}"

build_one() {
    local SIGN_LEVEL=$1
    local IMPL=$2
    local SIGN_DIR="$BASE_DIR/crypto_sign/NCC-Sign${SIGN_LEVEL}/${IMPL}"
    local OUTPUT="robust_Sign${SIGN_LEVEL}_${IMPL}"

    if [ ! -d "$SIGN_DIR" ]; then
        echo "  [SKIP] $SIGN_DIR does not exist"
        return
    fi

    echo "  [BUILD] NCC-Sign${SIGN_LEVEL} (${IMPL}) -> ${OUTPUT}"

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

    "$CC" -Wall -Wno-unused-result -O3 -fomit-frame-pointer \
        -I"$COMMON_DIR" -I"$SIGN_DIR" \
        -o "$BENCH_DIR/$OUTPUT" \
        "$BENCH_SRC" \
        "${SRC_FILES[@]}" \
        "${COMMON_FILES[@]}" \
        -lm

    echo "  [OK]    $OUTPUT"
}

run_one() {
    local SIGN_LEVEL=$1
    local IMPL=$2
    local OUTPUT="robust_Sign${SIGN_LEVEL}_${IMPL}"
    local BIN="$BENCH_DIR/$OUTPUT"

    if [ ! -f "$BIN" ]; then
        echo "  [SKIP] $BIN not found (build first)"
        return
    fi

    echo ""
    echo "################################################################"
    echo "# NCC-Sign${SIGN_LEVEL} (${IMPL})"
    echo "################################################################"
    "$BIN"
}

if [ "$MODE" = "all" ] || [ "$MODE" = "build" ]; then
    echo "=== Building robust benchmarks ==="
    for LEVEL in 1 3 5; do
        for IMPL in clean optimized; do
            build_one $LEVEL $IMPL
        done
    done
    echo "=== Build complete ==="
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "run" ]; then
    echo ""
    echo "=== Running robust benchmarks ==="
    for LEVEL in 1 3 5; do
        for IMPL in clean optimized; do
            run_one $LEVEL $IMPL
        done
    done
    echo ""
    echo "=== All benchmarks complete ==="
fi
