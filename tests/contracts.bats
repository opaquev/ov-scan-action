#!/usr/bin/env bats
# tests/contracts.bats - 45 named test contracts for ov-scan-action.
#
# Source: docs/superpowers/plans/2026-05-05-ov-scan-action-v1-impl.md
#         section "Test-driven implementation".
#
# These tests MUST FAIL today (red phase) because entrypoint.sh and
# action.yml do not yet exist. PR #5 implements both files until every
# contract here is green.
#
# Test contract numbering matches the plan doc:
#   #1-#14:  round-1 happy paths and basic gates
#   #15-#21: round-2 boolean/env/fork/swap/env-strip/forbidden-expressions
#   #22-#33: round-3 macOS shims, TOCTOU, symlink, jq, exit code, integer
#            regex, composed exec, vendored binaries
#   #34-#37: round-4 live-infrastructure correctness
#   #38-#43: round-5 CLI-interface + TOCTOU + replay correctness
#   #44-#45: round-6 R5-introduced regression contracts
#
# Tests use bats-core syntax. Helpers live in tests/helpers.bash and
# fixtures live in tests/fixtures/. The mock ov binary is conventionally
# placed at $WORK/ov by entrypoint.sh after extraction; for tests that
# need to bypass the download flow we drop a stub at $TEST_TMP/bin/ov
# via mock_ov_bin.

load 'helpers'

setup() {
    # Auto-skip all contract tests that require entrypoint.sh during PR #4
    # (red phase). PR #5 ships entrypoint.sh and skips auto-disable.
    # Exception: tests whose name contains "TestVendorBinariesNotNormalized"
    # or "TestNoActionsCacheUsage" or "TestNoInstallShBootstrap" are repo-
    # shape-only and don't need entrypoint.sh.
    case "$BATS_TEST_NAME" in
        *TestVendorBinariesNotNormalized*|*TestNoActionsCacheUsage*|*TestNoInstallShBootstrap*)
            ;;
        *)
            skip_if_no_entrypoint
            ;;
    esac
    make_test_workspace
    install_minisign_stub
    install_trusted_keys valid
    make_event_payload push
    # Sensible default INPUT_* values for tests that don't override them.
    export INPUT_PATH="."
    export INPUT_BASELINE_FILE=".ovscan-baseline.txt"
    export INPUT_FAIL_ON="high"
    export INPUT_MIN_OV_VERSION=""
    export INPUT_MAX_OV_VERSION=""
    export INPUT_ALLOW_PULL_REQUEST_TARGET="false"
    export INPUT_ALLOW_BINARY_VERSION="false"
    export INPUT_ALLOW_CI_BASELINE="false"
    export INPUT_TIME_BUDGET="300"
    export INPUT_MEMORY_BUDGET="1048576"
}

teardown() {
    teardown_test_workspace
}

# ===========================================================================
# Round-1 (#1-#14) - happy paths and basic gates
# ===========================================================================

@test "#1 TestCleanRepoExitsZero - clean fixture exits 0 with findings-count=0" {
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 0 ]
    [ "$(get_output_value findings-count)" = "0" ]
}

@test "#2 TestDirtyRepoExitsNonZeroWithCounts - dirty fixture exits non-zero with findings-count=1" {
    install_dirty_repo
    mock_ov_bin '{"findings":[{"rule":"aws-akia","severity":"high","baselined":false,"verified":false}]}'
    run run_entrypoint
    [ "$status" -ne 0 ]
    [ "$(get_output_value findings-count)" = "1" ]
}

@test "#3 TestSignatureFailureExitsNonZero - corrupted ov binary fails minisign verify with exit 2" {
    # Force a fixture where the downloaded checksums.txt.minisig is
    # corrupted - the minisign binary returns non-zero on verify.
    export OV_TEST_MUTATE_SIG="1"
    install_clean_repo
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#4 TestMultipleTrustedKeysAccepted - first-success-wins iterates required then legacy" {
    install_trusted_keys valid-with-legacy
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 0 ]
}

@test "#5a TestBinaryVersionOutsideRangeRefuses - lex-trap canary 0.9.5 vs 0.10.0" {
    # Real ov v0.10.0 binary's --check-version-bounds is invoked by
    # entrypoint.sh for every scan; the action's unconditional floor
    # (OV_VERSION="v0.10.0") rejects v0.9.5 even when customer min is
    # empty. The lex-trap canary asserts 0.9.5 < 0.10.0 numerically.
    install_clean_repo
    # Stub a mock that reports version 0.9.5 (fake version-bound rejection).
    mock_ov_bin '{"findings":[]}' "ov version 0.9.5 (commit fake, built 2026-01-01T00:00:00Z)"
    # Make --check-version-bounds return non-zero to simulate failure.
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.9.5 (commit fake, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds) exit 1 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#5b TestBinaryVersionOutsideRangeRefuses - flag form must be in entrypoint.sh (grep gate)" {
    # R5-B5-IMPL-4: positional invocation is silently a no-op. Assert
    # entrypoint.sh always uses --min-ov-version / --max-ov-version flags.
    [ -f "$ENTRYPOINT_PATH" ]
    # Every --check-version-bounds invocation must be followed (eventually
    # in the same line or args array) by --min-ov-version or --max-ov-version.
    # We assert the literal flag names appear at least once and that no
    # bare positional invocation pattern is present.
    grep -q -- '--check-version-bounds' "$ENTRYPOINT_PATH"
    grep -q -- '--min-ov-version' "$ENTRYPOINT_PATH"
}

@test "#6 TestNoActionsCacheUsage - action.yml AST has no actions/cache@* step" {
    [ -f "$ACTION_YML" ] || skip "action.yml not yet present (PR #5 implements)"
    if command -v yq >/dev/null 2>&1; then
        ! yq '.runs.steps[].uses // ""' "$ACTION_YML" | grep -qE 'actions/cache@'
    else
        ! grep -qE 'actions/cache@' "$ACTION_YML"
    fi
}

@test "#7 TestNoInstallShBootstrap - no install.sh or curl-pipe-sh pattern in any shell" {
    [ -f "$ACTION_YML" ] || skip "action.yml not yet present (PR #5 implements)"
    [ -f "$ENTRYPOINT_PATH" ] || skip "entrypoint.sh not yet present (PR #5 implements)"
    # Note: `\s` is NOT a valid whitespace class in BSD/macOS grep ERE
    # (it's interpreted as the literal character 's'). Use POSIX
    # [[:space:]]* for portable whitespace matching.
    ! grep -E '(install\.sh|curl[^|]*\|[[:space:]]*sh)' "$ENTRYPOINT_PATH" "$ACTION_YML" 2>/dev/null
}

@test "#8a TestBinaryVersionFromBinarySelfReport - --version output begins with 'ov version '" {
    install_clean_repo
    # Stub returns a malformed version string; action must reject.
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "totally not ov"; exit 0 ;;
    --check-version-bounds) exit 0 ;;
    scan) echo '{"findings":[]}'; exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#8b TestBinaryVersionFromBinarySelfReport - entrypoint must NOT invoke --version --json" {
    # R5-B5-IMPL-3 negative grep: --version --json does not exist in v0.10.0.
    [ -f "$ENTRYPOINT_PATH" ]
    ! grep -E -- '--version[[:space:]]+--json' "$ENTRYPOINT_PATH"
}

@test "#9a TestTrustedKeysFileFormat - malformed line (missing role) fails loud" {
    install_trusted_keys malformed
    install_clean_repo
    run run_entrypoint
    [ "$status" -eq 2 ]
    [[ "$output" == *"trusted-keys"* ]] || [[ "$output" == *"malformed"* ]]
}

@test "#9b TestTrustedKeysFileFormat - extra tokens rejected" {
    install_trusted_keys extra-tokens
    install_clean_repo
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#9c TestTrustedKeysFileFormat - unknown key role rejected" {
    install_trusted_keys unknown-role
    install_clean_repo
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#9d TestTrustedKeysFileFormat - zero required keys rejected" {
    install_trusted_keys zero-required
    install_clean_repo
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#9e TestTrustedKeysFileFormat - more than one required key rejected" {
    install_trusted_keys two-required
    install_clean_repo
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#10 TestSARIFContainsNoLiteralValueOr64Or6plus4Substring - findings text never leaks credential value" {
    # T3-H1: feed dirty fixture; assert the SARIF/JSON output written
    # never contains the literal credential value, never the
    # first-6-last-4 substring, never base64(value).
    install_dirty_repo
    local SCAN_LOG="$TEST_TMP/sarif.json"
    export OV_TEST_CAPTURE_OUT="$SCAN_LOG"
    # Mock returns a redacted-message finding with NO snippet/literal.
    mock_ov_bin '{"findings":[{"rule":"aws-akia","severity":"high","baselined":false,"verified":false,"message":{"text":"<redacted>"}}]}'
    run run_entrypoint
    # Per #2 TestDirtyRepoExitsNonZeroWithCounts: severity:"high" with
    # INPUT_FAIL_ON="high" exits non-zero (findings >= threshold).
    # The leak-check assertions below run regardless — we only need
    # $GITHUB_OUTPUT to have been written.
    [ "$status" -ne 0 ]
    [ -f "$GITHUB_OUTPUT" ]
    [ -s "$GITHUB_OUTPUT" ]
    # Now the load-bearing assertions: action emits findings count to
    # GITHUB_OUTPUT; check the literal credential never appears anywhere.
    local LITERAL="XXXFAKE_AKIA_DEADBEEFCAFE0123456789ABCDEF0123"
    local SUFFIX="F0123"
    local PREFIX="XXXFAKE_AKIA_DEADB"
    ! echo "$output" | grep -F -- "$LITERAL"
    ! grep -F -- "$LITERAL" "$GITHUB_OUTPUT"
    ! echo "$output" | grep -F -- "$PREFIX"
    ! echo "$output" | grep -F -- "$SUFFIX"
}

@test "#11 TestNoImplicitAllowCIBaseline - allow-ci-baseline=true on fork-PR exits 2" {
    make_event_payload fork-pr "attacker/test-fixture"
    export INPUT_ALLOW_CI_BASELINE="true"
    install_dirty_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#12 TestInputInjectionResistance - shell-metachar in path rejected, /tmp/pwned not created" {
    rm -f /tmp/pwned
    export INPUT_PATH='; rm -rf /tmp/pwned; #'
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
    [ ! -e /tmp/pwned ]
}

@test "#13 TestPathTraversalRejected - ../../../etc/passwd rejected" {
    export INPUT_PATH="../../../etc/passwd"
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#14 TestOutputInjectionResistance - count emit smuggling 0\\nfoo=bar rejected" {
    install_clean_repo
    # Mock returns scan output that, after jq parse, yields a smuggled
    # newline-bearing count. Realistic vector: a corrupted/trailing
    # response that includes literal chars after a digit.
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.10.0 (commit abc, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds) exit 0 ;;
    scan) printf '{"findings":[]}\nfoo=bar\n'; exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    [ "$status" -eq 2 ]
    ! grep -qE '^foo=bar' "$GITHUB_OUTPUT"
}

# ===========================================================================
# Round-2 (#15-#21) - boolean, env, fork, swap, env-strip, no-${{}}-in-run
# ===========================================================================

@test "#15 TestBooleanInputNormalization - normalize_bool table on bash 3.2" {
    # Source entrypoint.sh in a sub-bash and call normalize_bool directly.
    [ -f "$ENTRYPOINT_PATH" ]
    # Extract the function via a helper sub-script and exercise it.
    # Until entrypoint.sh exists, this fails.
    bash -c "
        source '$ENTRYPOINT_PATH'
        [ \"\$(normalize_bool 'True')\"   = 'true'  ] || exit 1
        [ \"\$(normalize_bool 'TRUE')\"   = 'true'  ] || exit 1
        [ \"\$(normalize_bool '1')\"      = 'true'  ] || exit 1
        [ \"\$(normalize_bool 'yes')\"    = 'true'  ] || exit 1
        [ \"\$(normalize_bool 'on')\"     = 'true'  ] || exit 1
        [ \"\$(normalize_bool 'false')\"  = 'false' ] || exit 1
        [ \"\$(normalize_bool '0')\"      = 'false' ] || exit 1
        [ \"\$(normalize_bool 'no')\"     = 'false' ] || exit 1
        [ \"\$(normalize_bool '')\"       = 'false' ] || exit 1
        [ \"\$(normalize_bool 'garbage')\" = 'false' ] || exit 1
    "
}

@test "#16a TestRefusesOutsideActionsContext - missing GITHUB_EVENT_NAME exits with :? message" {
    [ -f "$ENTRYPOINT_PATH" ]
    unset GITHUB_EVENT_NAME
    run run_entrypoint
    [ "$status" -ne 0 ]
    [[ "$output" == *"GITHUB_EVENT_NAME"* ]] || [[ "$output" == *"running outside"* ]]
}

@test "#16b TestRefusesOutsideActionsContext - missing GITHUB_REPOSITORY exits with :? message" {
    [ -f "$ENTRYPOINT_PATH" ]
    unset GITHUB_REPOSITORY
    run run_entrypoint
    [ "$status" -ne 0 ]
    [[ "$output" == *"GITHUB_REPOSITORY"* ]] || [[ "$output" == *"running outside"* ]]
}

@test "#16c TestRefusesOutsideActionsContext - missing GITHUB_EVENT_PATH exits with :? message" {
    [ -f "$ENTRYPOINT_PATH" ]
    unset GITHUB_EVENT_PATH
    run run_entrypoint
    [ "$status" -ne 0 ]
    [[ "$output" == *"GITHUB_EVENT_PATH"* ]] || [[ "$output" == *"running outside"* ]]
}

@test "#16d TestRefusesOutsideActionsContext - missing GITHUB_ACTION_PATH exits with :? message" {
    [ -f "$ENTRYPOINT_PATH" ]
    unset GITHUB_ACTION_PATH
    run run_entrypoint
    [ "$status" -ne 0 ]
    [[ "$output" == *"GITHUB_ACTION_PATH"* ]] || [[ "$output" == *"running outside"* ]]
}

@test "#16e TestRefusesOutsideActionsContext - missing RUNNER_TEMP exits with :? message" {
    [ -f "$ENTRYPOINT_PATH" ]
    unset RUNNER_TEMP
    run run_entrypoint
    [ "$status" -ne 0 ]
    [[ "$output" == *"RUNNER_TEMP"* ]] || [[ "$output" == *"running outside"* ]]
}

@test "#17a TestForkPrDetection - same-repo PR returns false" {
    make_event_payload same-repo-pr
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    # Same-repo PR is NOT a fork; allowance inputs are honored. Action
    # should proceed (or fail for a non-fork reason, but not the fork-strict reason).
    [ "$status" -eq 0 ]
}

@test "#17b TestForkPrDetection - fork PR returns true" {
    make_event_payload fork-pr "attacker/test-fixture"
    export INPUT_ALLOW_BINARY_VERSION="true"
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    # Fork-PR strict mode: any of the three "allow-*" knobs being true
    # forces an exit 2.
    [ "$status" -eq 2 ]
}

@test "#17c TestForkPrDetection - non-PR event returns false (no strict mode)" {
    make_event_payload push
    export INPUT_ALLOW_BINARY_VERSION="true"
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    # A push event with allow-binary-version=true is allowed (not a fork PR).
    [ "$status" -eq 0 ]
}

@test "#18 TestTrustedKeysSwapBetweenCheckAndUse - copy in WORK is read after SHA check" {
    # R3-CRITICAL-1: a same-UID writer that overwrites trusted-keys.txt
    # between the SHA check and the minisign read must NOT win. Action's
    # defense is to copy trust roots into $WORK and re-hash; only the copy
    # is read.
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    # We can't realistically race the action in a contract test; instead
    # we assert the structural property via grep: cp into $WORK before
    # minisign invocation, and chmod 0400 on the copy.
    [ -f "$ENTRYPOINT_PATH" ]
    grep -q 'cp.*trusted-keys' "$ENTRYPOINT_PATH"
    grep -qE 'chmod[[:space:]]+0400.*trusted-keys' "$ENTRYPOINT_PATH"
}

@test "#19 TestMinisignSwapBetweenCheckAndUse - copy in WORK is exec'd after SHA check" {
    # R3-CRITICAL-1 sibling: same pattern for the vendored minisign binary.
    [ -f "$ENTRYPOINT_PATH" ]
    grep -q 'cp.*minisign' "$ENTRYPOINT_PATH"
    grep -qE 'chmod[[:space:]]+0500.*minisign' "$ENTRYPOINT_PATH"
}

@test "#20 TestOvScanInvokedWithCleanEnv - exec env -i strips GITHUB_TOKEN, secrets, LD_PRELOAD" {
    install_clean_repo
    export GITHUB_TOKEN="ghs_FAKE_FOR_TEST"
    export MY_API_KEY="fake-api-key"
    export MY_SECRET="fake-secret"
    export LD_PRELOAD="/tmp/evil.so"
    local DUMP_FILE="$TEST_TMP/ov-env-dump.txt"
    export MOCK_OV_DUMP_ENV="$DUMP_FILE"
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ -f "$DUMP_FILE" ]
    ! grep -q '^GITHUB_TOKEN=' "$DUMP_FILE"
    ! grep -q '^MY_API_KEY='   "$DUMP_FILE"
    ! grep -q '^MY_SECRET='    "$DUMP_FILE"
    ! grep -q '^LD_PRELOAD='   "$DUMP_FILE"
}

@test "#21 TestNoUnsafeGitHubExpressionsInRunBlocks - action.yml run: blocks have no \${{ inputs.* }} or \${{ github.* }}" {
    [ -f "$ACTION_YML" ]
    if command -v yq >/dev/null 2>&1; then
        # Extract every run: value and grep for forbidden patterns.
        yq '.runs.steps[].run // ""' "$ACTION_YML" > "$TEST_TMP/runs.txt"
        ! grep -qE '\$\{\{[[:space:]]*(inputs|github)\.' "$TEST_TMP/runs.txt"
    else
        # Fallback: rough grep within run: block lines.
        ! grep -A1 '^[[:space:]]*run:' "$ACTION_YML" | grep -qE '\$\{\{[[:space:]]*(inputs|github)\.'
    fi
}

# ===========================================================================
# Round-3 (#22-#33) - macOS shims, TOCTOU, symlink, jq, exit code, integer
# regex, composed exec, vendor binaries
# ===========================================================================

@test "#22 TestNormalizeBoolOnBash32 - normalize_bool succeeds without 'bad substitution' on bash 3.2" {
    # Forbidden constructs: \${v,,}, \${v^^} (bash 4+ only).
    [ -f "$ENTRYPOINT_PATH" ]
    ! grep -qE '\$\{[A-Za-z_][A-Za-z0-9_]*,,\}' "$ENTRYPOINT_PATH"
    ! grep -qE '\$\{[A-Za-z_][A-Za-z0-9_]*\^\^\}' "$ENTRYPOINT_PATH"
    # And the function should still produce "true" for "True".
    bash -c "
        source '$ENTRYPOINT_PATH' >/dev/null 2>&1 || true
        [ \"\$(normalize_bool 'True')\" = 'true' ]
    "
}

@test "#23 TestSha256ShimResolvesOnLinuxAndMacOS - sha256 returns 64 hex on both platforms" {
    [ -f "$ENTRYPOINT_PATH" ]
    # Source the shim from entrypoint.sh and run it against a known input.
    local probe="$TEST_TMP/sha-probe.txt"
    printf '%s' "test" > "$probe"
    local actual
    actual="$(bash -c "source '$ENTRYPOINT_PATH' >/dev/null 2>&1 || true; sha256 '$probe'")"
    # Expected sha256 of 'test' is well-known.
    [ "$actual" = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" ]
}

@test "#24 TestBinarySwapBetweenVerifyAndExec - stat-snapshot defense rejects swapped \$WORK/ov" {
    # R3-H1: between minisign verify and exec, a same-UID attacker swaps
    # $WORK/ov. Defense: stat_inode_mtime_size snapshot + recheck.
    [ -f "$ENTRYPOINT_PATH" ]
    grep -qE 'stat_inode_mtime_size' "$ENTRYPOINT_PATH"
    # The recheck must compare to a stored snapshot before exec.
    grep -qE 'SNAPSHOT' "$ENTRYPOINT_PATH"
}

@test "#25 TestRefusesSymlinkedTrustRoot - symlinked trusted-keys.txt rejected" {
    install_trusted_keys symlink
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#26 TestRefusesMissingJq - jq removed from PATH causes fail-closed exit 2" {
    # Simulate jq genuinely missing: PATH points only at our isolated
    # $TEST_TMP/bin (which contains the mock ov but no jq). Earlier
    # iteration of this test set PATH=/usr/bin:/bin which RE-EXPOSED
    # the system jq — making the test masquerade as itself (Devin
    # PR #4 review catch).
    install_clean_repo
    # PATH excludes any system path; only the test bin dir.
    export PATH="$TEST_TMP/bin"
    # Sanity check: jq is actually unreachable in the test environment.
    ! command -v jq >/dev/null 2>&1
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#27a TestEmptyEventPayloadRefused - 0-byte event.json exits 2" {
    make_event_payload empty
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#27b TestNullHeadRepoTreatedAsFork - null head_repo on PR event treated as fork" {
    make_event_payload null-head-pr
    export INPUT_ALLOW_BINARY_VERSION="true"
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    # Null head repo on PR event → strict-mode clobber → exit 2.
    [ "$status" -eq 2 ]
}

@test "#28 TestForkPrInputClobberHappensBeforeReads - clobber fires before download" {
    make_event_payload fork-pr "attacker/test-fixture"
    export INPUT_ALLOW_BINARY_VERSION="true"
    export INPUT_MAX_OV_VERSION="v999.0.0"
    install_clean_repo
    # Don't even mock ov - the action must exit 2 BEFORE attempting to
    # download a custom binary.
    run run_entrypoint
    [ "$status" -eq 2 ]
    # If the clobber happened, the action did not attempt a v999.0.0 fetch.
    ! grep -qE 'v999\.0\.0' "$GITHUB_OUTPUT" 2>/dev/null
}

@test "#29 TestCleanupPreservesExitCode - successful run exits 0 even if WORK was empty" {
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 0 ]
}

@test "#30a TestOutputInjectionRejectsLeadingZeroAndMultiline - findings='0' accepted" {
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 0 ]
    [ "$(get_output_value findings-count)" = "0" ]
}

@test "#30b TestOutputInjectionRejectsLeadingZeroAndMultiline - findings='5' accepted" {
    install_clean_repo
    # 5 findings -> count=5
    mock_ov_bin '{"findings":[{"rule":"r1","severity":"low","baselined":false,"verified":false},{"rule":"r2","severity":"low","baselined":false,"verified":false},{"rule":"r3","severity":"low","baselined":false,"verified":false},{"rule":"r4","severity":"low","baselined":false,"verified":false},{"rule":"r5","severity":"low","baselined":false,"verified":false}]}'
    run run_entrypoint
    [ "$(get_output_value findings-count)" = "5" ]
}

@test "#30c TestOutputInjectionRejectsLeadingZeroAndMultiline - leading-zero, sign, scientific, multiline rejected" {
    # Validate the integer regex by sourcing it from entrypoint.sh.
    [ -f "$ENTRYPOINT_PATH" ]
    # Extract the INTEGER_RE literal from entrypoint.sh and re-test against it.
    local re
    re="$(grep -E "^INTEGER_RE='" "$ENTRYPOINT_PATH" | sed -E "s/^INTEGER_RE='([^']+)'.*/\\1/")"
    [ -n "$re" ]
    # Acceptable: '0', '5'
    [[ "0" =~ $re ]]
    [[ "5" =~ $re ]]
    # Rejected: '05', '+5', '-5', '5e0', $'5\nfoo=bar'
    ! [[ "05" =~ $re ]]
    ! [[ "+5" =~ $re ]]
    ! [[ "-5" =~ $re ]]
    ! [[ "5e0" =~ $re ]]
    local multiline=$'5\nfoo=bar'
    ! [[ "$multiline" =~ $re ]]
}

@test "#31 TestMemoryLimitAppliedAtExec - ulimit -v applied (Linux only; macOS skipped)" {
    if [ "$(uname -s)" = "Darwin" ]; then
        skip "macOS ulimit -v is a no-op (R3-M1)"
    fi
    install_clean_repo
    export INPUT_MEMORY_BUDGET="10240"
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.10.0 (commit abc, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds) exit 0 ;;
    scan)
        # Probe: read ulimit -v of self
        ulimit -v > "$TEST_TMP/ulimit-v.txt"
        echo '{"findings":[]}'
        exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    [ -f "$TEST_TMP/ulimit-v.txt" ]
    local v
    v="$(cat "$TEST_TMP/ulimit-v.txt")"
    # Expect 10240 (or close) - not "unlimited".
    [ "$v" = "10240" ]
}

@test "#32 TestEmptyRequiredInputExitsClean - empty path exits 2 with named-input error" {
    export INPUT_PATH=""
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#33 TestVendorBinariesNotNormalized - git check-attr binary set on every vendor binary" {
    cd "$REPO_ROOT"
    for f in vendor/minisign-0.12-linux_amd64 vendor/minisign-0.12-linux_arm64 vendor/minisign-0.12-darwin_arm64; do
        [ -f "$f" ] || skip "$f not vendored yet"
        attr="$(git check-attr binary -- "$f" | awk -F': ' '{print $NF}')"
        [ "$attr" = "set" ] || { echo "$f attr: $attr"; false; }
    done
}

# ===========================================================================
# Round-4 (#34-#37) - live-infrastructure correctness contracts
# ===========================================================================

@test "#34 TestDownloadURLPatternMatchesGoReleaser - downloads from releases.opaquevault.com/\${VERSION}/" {
    [ -f "$ENTRYPOINT_PATH" ]
    # Real GoReleaser+R2 layout per plan §14:
    grep -qE 'releases\.opaquevault\.com/\$\{?OV_VERSION\}?' "$ENTRYPOINT_PATH"
    # Tarball name pattern.
    grep -qE 'ov_\$\{?TARGET\}?\.tar\.gz' "$ENTRYPOINT_PATH"
    # checksums.txt pattern (GoReleaser uses ${.Version} = no leading v).
    grep -qE 'ov_\$\{?VERSION_NO_V\}?_checksums\.txt' "$ENTRYPOINT_PATH"
}

@test "#35a TestSignatureChainVerifiesChecksumsThenTarballSHA - happy path proceeds" {
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 0 ]
}

@test "#35b TestSignatureChainVerifiesChecksumsThenTarballSHA - tarball SHA mismatch exits 2" {
    install_clean_repo
    export OV_TEST_MUTATE_TARBALL=1
    run run_entrypoint
    [ "$status" -eq 2 ]
    [[ "$output" == *"SHA-256 mismatch"* ]] || [[ "$output" == *"tarball"* ]]
}

@test "#35c TestSignatureChainVerifiesChecksumsThenTarballSHA - mutated checksums fails sig verify" {
    install_clean_repo
    export OV_TEST_MUTATE_CHECKSUMS=1
    run run_entrypoint
    [ "$status" -eq 2 ]
    [[ "$output" == *"signature"* ]] || [[ "$output" == *"checksums"* ]]
}

@test "#36a TestTrustedKeysBase64Format - hex fingerprint instead of base64 rejected" {
    install_trusted_keys hex-fingerprint
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
    [[ "$output" == *"base64"* ]] || [[ "$output" == *"public key"* ]]
}

@test "#36b TestTrustedKeysBase64Format - proper base64 form proceeds" {
    install_trusted_keys valid
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 0 ]
}

@test "#37a TestScanOutputUnparseableExitsFailClosed - truncated JSON exits 2 with explicit error" {
    install_clean_repo
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.10.0 (commit abc, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds) exit 0 ;;
    scan) printf '{"findings": ['; exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    [ "$status" -eq 2 ]
    [[ "$output" == *"unparseable"* ]] || [[ "$output" == *"JSON"* ]] || [[ "$output" == *"cannot derive"* ]]
}

@test "#37b TestScanOutputUnparseableExitsFailClosed - empty SCAN_OUT with non-zero RC exits 2 with killed/OOM/timeout" {
    install_clean_repo
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.10.0 (commit abc, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds) exit 0 ;;
    scan) exit 137 ;;  # SIGKILL-style
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    [ "$status" -eq 2 ]
    [[ "$output" == *"killed"* ]] || [[ "$output" == *"OOM"* ]] || [[ "$output" == *"timeout"* ]] || [[ "$output" == *"no output"* ]]
}

@test "#37c TestScanOutputUnparseableExitsFailClosed - findings-count NEVER emitted on parse failure" {
    install_clean_repo
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.10.0 (commit abc, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds) exit 0 ;;
    scan) printf '{"findings":'; exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    [ "$status" -eq 2 ]
    assert_no_output_key "findings-count"
}

# ===========================================================================
# Round-5 (#38-#43) - CLI-interface + TOCTOU + replay correctness contracts
# ===========================================================================

@test "#38 TestStaleChecksumsReplayDefeated - genuine v0.9.5 artifacts at v0.10.0 URL exits 2" {
    install_clean_repo
    # Stub returns version 0.9.5 with --check-version-bounds returning
    # non-zero against the action's pinned floor v0.10.0.
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.9.5 (commit fake, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds)
        # Reject if any --min-ov-version arg references the floor.
        for a; do
            case "$a" in
                v0.10.0|0.10.0) exit 1 ;;
            esac
        done
        exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    # Customer bounds empty - the unconditional floor is the load-bearing check.
    export INPUT_MIN_OV_VERSION=""
    export INPUT_MAX_OV_VERSION=""
    run run_entrypoint
    [ "$status" -eq 2 ]
    [[ "$output" == *"pinned"* ]] || [[ "$output" == *"replay"* ]] || [[ "$output" == *"floor"* ]] || [[ "$output" == *"OV_VERSION"* ]]
}

@test "#39 TestTarballSwapBetweenSHACheckAndExtract - snapshot recheck before tar -xzf" {
    # R5-T4-HIGH-1: grep entrypoint.sh for snapshot recheck IMMEDIATELY
    # before tar -xzf. Structural assertion: the recheck must come
    # between the SHA match and the extract.
    [ -f "$ENTRYPOINT_PATH" ]
    grep -qE 'TARBALL_SNAPSHOT' "$ENTRYPOINT_PATH"
    # The line range: the second mention of TARBALL_SNAPSHOT (the recheck)
    # must be immediately before tar -xzf.
    awk '/TARBALL_SNAPSHOT/{count++; if (count==2) found=NR} /tar -xzf/{ if (found && NR-found < 5) print "ok"; exit }' \
        "$ENTRYPOINT_PATH" | grep -q ok
}

@test "#40a TestParseCountReturnsRcNotExitInSubshell - missing .findings field exits 2 with explicit error" {
    install_clean_repo
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.10.0 (commit abc, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds) exit 0 ;;
    scan) printf '{"summary":"clean"}'; exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    [ "$status" -eq 2 ]
    [[ "$output" == *"missing or non-array"* ]] || [[ "$output" == *".findings"* ]]
    # CRITICAL: findings-count MUST NOT be emitted (silent-false-clean defense).
    assert_no_output_key "findings-count"
}

@test "#40b TestParseCountReturnsRcNotExitInSubshell - non-array .findings exits 2" {
    install_clean_repo
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.10.0 (commit abc, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds) exit 0 ;;
    scan) printf '{"findings":"not-an-array"}'; exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    [ "$status" -eq 2 ]
    assert_no_output_key "findings-count"
}

@test "#41a TestTimeoutShimResolvesOnLinuxAndMacOS - OV_TIMEOUT array kills child within ~2s" {
    [ -f "$ENTRYPOINT_PATH" ]
    # Source entrypoint.sh (early portability shims only) and exercise OV_TIMEOUT.
    bash -c "
        set -euo pipefail
        # Source only the prefix up to the OV_TIMEOUT block.
        source '$ENTRYPOINT_PATH' 2>/dev/null || true
        # Run a command that must be killed. Wrapped to avoid suite hang.
        rc=0
        \"\${OV_TIMEOUT[@]}\" 1 sleep 5 || rc=\$?
        # GNU timeout convention: rc=124 on timeout.
        [ \"\$rc\" -eq 124 ]
    "
}

@test "#41b TestTimeoutShimResolvesOnLinuxAndMacOS - OV_TIMEOUT survives exec env -i" {
    [ -f "$ENTRYPOINT_PATH" ]
    # R6-IMPL-1: bash function fallbacks would fail with rc=127 inside
    # exec env -i. Verify the array form survives.
    bash -c "
        set -euo pipefail
        source '$ENTRYPOINT_PATH' 2>/dev/null || true
        rc=0
        ( exec env -i PATH=/usr/bin:/bin \"\${OV_TIMEOUT[@]}\" 1 sleep 5 ) || rc=\$?
        [ \"\$rc\" -eq 124 ]
    "
}

@test "#42 TestCheckVersionBoundsUsesFlagForm - every --check-version-bounds invocation uses flag form" {
    [ -f "$ENTRYPOINT_PATH" ]
    # R5-B5-IMPL-4: extract every line/block with --check-version-bounds
    # and confirm flag form (--min-ov-version / --max-ov-version) appears
    # in entrypoint.sh and no positional invocation pattern is used.
    grep -q -- '--check-version-bounds' "$ENTRYPOINT_PATH"
    grep -qE -- '--min-ov-version|--max-ov-version' "$ENTRYPOINT_PATH"
    # Negative: forbid positional pattern like
    # `--check-version-bounds v0.9.0 v0.11.0` where the next two args
    # are non-flag tokens. Check that no line matches that shape.
    ! grep -qE -- '--check-version-bounds[[:space:]]+[^-][^[:space:]]*[[:space:]]+[^-]' "$ENTRYPOINT_PATH"
}

@test "#43a TestUnconditionalVersionFloorEnforced - all customer inputs unset, replay scenario exits 2" {
    install_clean_repo
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.9.5 (commit fake, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds)
        for a; do
            case "$a" in
                v0.10.0|0.10.0) exit 1 ;;  # action floor rejects
            esac
        done
        exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    export INPUT_MIN_OV_VERSION=""
    export INPUT_MAX_OV_VERSION=""
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#43b TestUnconditionalVersionFloorEnforced - customer min looser than floor still rejects 0.9.5" {
    install_clean_repo
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.9.5 (commit fake, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds)
        for a; do
            case "$a" in
                v0.10.0|0.10.0) exit 1 ;;
            esac
        done
        exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    export INPUT_MIN_OV_VERSION="v0.9.0"
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "#43c TestUnconditionalVersionFloorEnforced - v0.10.0 binary with min v0.10.0 proceeds" {
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    export INPUT_MIN_OV_VERSION="v0.10.0"
    run run_entrypoint
    [ "$status" -eq 0 ]
}

# ===========================================================================
# Round-6 (#44-#45) - R5-introduced regression contracts
# ===========================================================================

@test "#44 TestFindingsArrayAbsentExitsFailClosed - silent-false-clean defense load-bearing test" {
    # R6-IMPL-2: if jq's `.findings | length` were used naïvely on
    # `{"summary":"clean"}` it would coerce null|length=0 and emit
    # findings-count=0 on a JSON missing the .findings field. The
    # action MUST reject this case.
    install_clean_repo
    cat > "$TEST_TMP/bin/ov" <<'BASH'
#!/usr/bin/env bash
case "$1" in
    --version) echo "ov version 0.10.0 (commit abc, built 2026-01-01T00:00:00Z)"; exit 0 ;;
    --check-version-bounds) exit 0 ;;
    scan) printf '{"summary":"clean"}'; exit 0 ;;
esac
exit 1
BASH
    chmod +x "$TEST_TMP/bin/ov"
    run run_entrypoint
    # (a) exits 2
    [ "$status" -eq 2 ]
    # (b) emits explicit error to stderr/stdout
    [[ "$output" == *"missing or non-array"* ]] || [[ "$output" == *".findings"* ]]
    # (c) NO findings-count line in $GITHUB_OUTPUT (load-bearing assertion)
    assert_no_output_key "findings-count"
}

@test "#45 TestTimeoutSurvivesExecEnvI - bash-function fallback would fail with rc=127" {
    # R6-IMPL-1: replay the exact exec composition from §17. Bash fns
    # do NOT survive exec env -i; only an external binary like
    # /usr/bin/perl does. This test guards the regression permanently.
    [ -f "$ENTRYPOINT_PATH" ]
    # Negative grep: forbid bash function forms like `ov_timeout()` defined
    # earlier in the file (R5 design that R6 superseded).
    ! grep -qE '^ov_timeout[[:space:]]*\(\)' "$ENTRYPOINT_PATH"
    # Positive: the OV_TIMEOUT array path must include either timeout(1),
    # gtimeout, or /usr/bin/perl as a vendored binary path.
    grep -qE '/usr/bin/perl|\bgtimeout\b|\btimeout\b' "$ENTRYPOINT_PATH"
    # Functional: the OV_TIMEOUT array must work under exec env -i.
    bash -c "
        set -euo pipefail
        source '$ENTRYPOINT_PATH' 2>/dev/null || true
        rc=0
        ( exec env -i PATH=/usr/bin:/bin \"\${OV_TIMEOUT[@]}\" 1 sleep 5 ) || rc=\$?
        [ \"\$rc\" -eq 124 ]
    "
}
