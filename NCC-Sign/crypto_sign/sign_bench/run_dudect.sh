#!/bin/bash
# Build and run dudect constant-time tests for NCC-Sign
#
# Usage:
#   ./run_dudect.sh build                # Build all tests for all variants
#   ./run_dudect.sh run [level] [test]   # Run specific test (requires sudo)
#
# Test IDs:
#   1 = NTT (forward)
#   2 = INTT (inverse)
#   3 = Pointwise multiply
#   4 = poly_chknorm
#   5 = unpack_sk + NTT(s1)
#
# Examples:
#   ./run_dudect.sh run 1 1    # Sign-1 optimized, test NTT
#   ./run_dudect.sh run 3 3    # Sign-3 optimized, test pointwise
#   ./run_dudect.sh runall 1   # Sign-1 optimized, all 5 tests
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMMON_DIR="$BASE_DIR/common"
BENCH_DIR="$SCRIPT_DIR"

CC="${CC:-gcc}"
SOURCES_NAMES=(packing.c poly.c reduce.c rounding.c sign.c symmetric-shake.c)

MODE="${1:-build}"
LEVEL="${2:-1}"
TEST_ID="${3:-1}"

TEST_NAMES=("" "NTT" "INTT" "Pointwise" "ChkNorm" "UnpackSK")

build_one() {
    local SIGN_LEVEL=$1
    local IMPL=$2
    local TID=$3
    local SIGN_DIR="$BASE_DIR/crypto_sign/NCC-Sign${SIGN_LEVEL}/${IMPL}"
    local OUTPUT="dudect_Sign${SIGN_LEVEL}_${IMPL}_t${TID}"

    [ ! -d "$SIGN_DIR" ] && return

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
        -DDUDECT_TEST_ID=$TID \
        -o "$BENCH_DIR/$OUTPUT" \
        "$BENCH_DIR/dudect_test.c" \
        "${SRC_FILES[@]}" \
        "${COMMON_FILES[@]}" \
        -lm 2>/dev/null

    echo "  [OK] $OUTPUT"
}

if [ "$MODE" = "build" ]; then
    echo "=== Building all dudect tests ==="
    for LVL in 1 3 5; do
        for TID in 1 2 3 4 5; do
            build_one $LVL optimized $TID
        done
    done
    echo "=== Done ==="

elif [ "$MODE" = "run" ]; then
    BIN="$BENCH_DIR/dudect_Sign${LEVEL}_optimized_t${TEST_ID}"
    if [ ! -f "$BIN" ]; then
        echo "Building first..."
        build_one $LEVEL optimized $TEST_ID
    fi
    echo "Running: Sign-${LEVEL} optimized, test ${TEST_NAMES[$TEST_ID]} (ID=$TEST_ID)"
    "$BIN"

elif [ "$MODE" = "runall" ]; then
    for TID in 1 2 3 4; do
        BIN="$BENCH_DIR/dudect_Sign${LEVEL}_optimized_t${TID}"
        if [ ! -f "$BIN" ]; then
            build_one $LEVEL optimized $TID
        fi
        echo ""
        echo "=========================================="
        echo "  Sign-${LEVEL}: ${TEST_NAMES[$TID]} (test $TID)"
        echo "=========================================="
        "$BIN"
    done
fi
