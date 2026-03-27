#!/bin/bash
# Script to run reference types tests locally or in CI

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Default values
BUILD_DIR="${PROJECT_ROOT}/build"
RUN_MODE="${RUN_MODE:-interpreter}"

echo "Running reference types tests..."
echo "Project root: $PROJECT_ROOT"
echo "Build dir: $BUILD_DIR"
echo "Run mode: $RUN_MODE"

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo "Build directory not found. Creating and building..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DZEN_ENABLE_REFERENCE_TYPES=ON \
        -DZEN_ENABLE_SPEC_TEST=ON \
        -DZEN_ENABLE_SINGLEPASS_JIT=OFF \
        -DZEN_ENABLE_MULTIPASS_JIT=OFF
    cmake --build . -j$(nproc)
fi

# Check if dtvm executable exists
DTVM_BIN="${BUILD_DIR}/dtvm"
if [ ! -f "$DTVM_BIN" ]; then
    echo "dtvm executable not found at $DTVM_BIN"
    exit 1
fi

# Run all reference types tests
FAILED_TESTS=()
PASSED_TESTS=()

for test_file in "$SCRIPT_DIR"/*.wast; do
    test_name=$(basename "$test_file")
    echo ""
    echo "========================================"
    echo "Running test: $test_name"
    echo "========================================"

    # Convert wast to json using wast2json
    test_dir="${BUILD_DIR}/ref_types_test_$(basename "$test_name" .wast)"
    mkdir -p "$test_dir"

    if wast2json --disable-bulk-memory --enable-reference-types \
        -o "${test_dir}/test.json" "$test_file" 2>/dev/null; then

        # Run the compiled wasm modules
        for wasm_file in "$test_dir"/*.wasm; do
            if [ -f "$wasm_file" ]; then
                wasm_name=$(basename "$wasm_file")
                echo "  Running $wasm_name..."
                if "$DTVM_BIN" --format wasm -m "$RUN_MODE" "$wasm_file" 2>&1; then
                    echo "  PASSED: $wasm_name"
                else
                    echo "  FAILED: $wasm_name"
                    FAILED_TESTS+=("$test_name:$wasm_name")
                fi
            fi
        done
        PASSED_TESTS+=("$test_name")
    else
        echo "  FAILED to convert wast to json"
        FAILED_TESTS+=("$test_name:wast2json")
    fi
done

echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Passed tests: ${#PASSED_TESTS[@]}"
echo "Failed tests: ${#FAILED_TESTS[@]}"

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo ""
    echo "Failed test details:"
    for test in "${FAILED_TESTS[@]}"; do
        echo "  - $test"
    done
    exit 1
fi

echo ""
echo "All reference types tests passed!"
exit 0