#!/usr/bin/env bats
# tests/structural.bats - 4 structural test contracts.
#
# These tests assert repo-shape (action.yml structure, entrypoint.sh
# preamble) rather than runtime behavior. Sourced from plan doc
# §"Structural tests".
#
# All 4 MUST FAIL today (red phase) because action.yml and entrypoint.sh
# do not yet exist.

load 'helpers'

setup() {
    # Auto-skip during PR #4 (red phase) — all 4 structural tests check
    # action.yml and/or entrypoint.sh shape. PR #5 ships those files and
    # the skips auto-disable.
    skip_if_no_entrypoint
    make_test_workspace
    install_minisign_stub
    install_trusted_keys valid
    make_event_payload pull-request-target
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

# ---------------------------------------------------------------------------
# Structural #1: TestActionYmlValidatesShellOnEveryStep (B3)
# Every run: step in action.yml has a sibling shell:.
# ---------------------------------------------------------------------------
@test "structural: TestActionYmlValidatesShellOnEveryStep - every run: step has sibling shell:" {
    [ -f "$ACTION_YML" ] || skip "action.yml not yet present (PR #5 implements)"
    if command -v yq >/dev/null 2>&1; then
        # For every step that has a `run` key, the same step must have a `shell` key.
        local missing
        missing="$(yq '[.runs.steps[] | select(has("run")) | select(has("shell") | not)] | length' "$ACTION_YML")"
        [ "$missing" = "0" ]
    else
        # Fallback grep: count run: lines and shell: lines.
        local runs shells
        runs=$(grep -cE '^[[:space:]]+run:' "$ACTION_YML" || true)
        shells=$(grep -cE '^[[:space:]]+shell:' "$ACTION_YML" || true)
        [ "$runs" -le "$shells" ]
    fi
}

# ---------------------------------------------------------------------------
# Structural #2: TestEntrypointShellSetEuoPipefail (R2-B2)
# First lines of entrypoint.sh are #!/usr/bin/env bash then set -euo pipefail.
# ---------------------------------------------------------------------------
@test "structural: TestEntrypointShellSetEuoPipefail - shebang + set -euo pipefail at top" {
    [ -f "$ENTRYPOINT_PATH" ] || skip "entrypoint.sh not yet present (PR #5 implements)"
    local first_line second_line third_line
    first_line=$(sed -n '1p' "$ENTRYPOINT_PATH")
    [ "$first_line" = "#!/usr/bin/env bash" ]
    # set -euo pipefail must appear within the first ~10 lines (to allow
    # for a comment block between the shebang and the safety preamble).
    grep -nE '^set -euo pipefail$' "$ENTRYPOINT_PATH" | head -1 | cut -d: -f1 > "$BATS_TMPDIR/setline.txt"
    local setline
    setline="$(cat "$BATS_TMPDIR/setline.txt")"
    [ -n "$setline" ]
    [ "$setline" -le 10 ]
}

# ---------------------------------------------------------------------------
# Structural #3: TestRefusesPullRequestTargetByDefault (B2)
# Default inputs + pull_request_target event = exit 2.
# ---------------------------------------------------------------------------
@test "structural: TestRefusesPullRequestTargetByDefault - pull_request_target event with defaults exits 2" {
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    # Defaults: INPUT_ALLOW_PULL_REQUEST_TARGET=false (set in setup).
    run run_entrypoint
    [ "$status" -eq 2 ]
    [[ "$output" == *"pull_request_target"* ]] || [[ "$output" == *"refuses"* ]]
}

# ---------------------------------------------------------------------------
# Structural #4: TestForkPrStrictMode
# Three fork-PR fixtures, each setting one of allow-binary-version /
# allow-ci-baseline / max-ov-version, all exit 2.
# ---------------------------------------------------------------------------
@test "structural: TestForkPrStrictMode - fork PR with allow-binary-version=true exits 2" {
    make_event_payload fork-pr "attacker/test-fixture"
    export INPUT_ALLOW_BINARY_VERSION="true"
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "structural: TestForkPrStrictMode - fork PR with allow-ci-baseline=true exits 2" {
    make_event_payload fork-pr "attacker/test-fixture"
    export INPUT_ALLOW_CI_BASELINE="true"
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
}

@test "structural: TestForkPrStrictMode - fork PR with max-ov-version set exits 2" {
    make_event_payload fork-pr "attacker/test-fixture"
    export INPUT_MAX_OV_VERSION="v999.0.0"
    install_clean_repo
    mock_ov_bin '{"findings":[]}'
    run run_entrypoint
    [ "$status" -eq 2 ]
}
