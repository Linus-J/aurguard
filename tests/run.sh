#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT_DIR/aurguard.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    local needle="$1"
    shift
    local haystack="$1"
    if ! grep -qF "$needle" <<< "$haystack"; then
        fail "expected to find '$needle'"
    fi
}

reset_state() {
    FINDINGS=()
    RISK_LEVEL="LOW"
}

setup

BAD_FIXTURE="$ROOT_DIR/tests/fixtures/known-bad/PKGBUILD"
GOOD_FIXTURE="$ROOT_DIR/tests/fixtures/known-good/PKGBUILD"

reset_state
if scan_file_for_patterns "$GOOD_FIXTURE"; then
    fail "expected good fixture to stay clear of IOC matches"
fi
if [[ ${#FINDINGS[@]} -ne 0 ]]; then
    fail "expected no findings for good fixture IOC scan"
fi

reset_state
if ! scan_file_for_patterns "$BAD_FIXTURE"; then
    fail "expected bad fixture to match at least one IOC pattern"
fi
assert_contains "IOC_MATCH:PKGBUILD" "${FINDINGS[*]}"
if [[ "$RISK_LEVEL" != "HIGH" ]]; then
    fail "expected bad fixture risk level HIGH, got $RISK_LEVEL"
fi

reset_state
GOOD_OUTPUT=$(check_sums "$GOOD_FIXTURE" 2>&1)
assert_contains "Checksums present" "$GOOD_OUTPUT"
if [[ "$RISK_LEVEL" != "LOW" ]]; then
    fail "expected good fixture risk level LOW, got $RISK_LEVEL"
fi

reset_state
check_sums "$BAD_FIXTURE"
assert_contains "NO_CHECKSUMS" "${FINDINGS[*]}"
if [[ "$RISK_LEVEL" != "MEDIUM" ]]; then
    fail "expected bad fixture checksum risk level MEDIUM, got $RISK_LEVEL"
fi

echo "All aurguard fixture tests passed."
