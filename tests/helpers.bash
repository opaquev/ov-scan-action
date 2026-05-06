#!/usr/bin/env bash
# tests/helpers.bash - shared bats helpers for ov-scan-action contracts.
#
# These helpers must work on both ubuntu-latest and macos-latest runners.
# Avoid GNU-only flags (use shasum -a 256 not sha256sum); avoid mktemp -d
# style differences on macOS where some flags differ.
#
# Each helper sets up an isolated $WORK area and synthesizes the GitHub
# Actions context env vars that entrypoint.sh expects. Tests use these
# helpers to build a fixture environment, invoke entrypoint.sh, and
# capture exit code, stdout, stderr, and the contents of $GITHUB_OUTPUT.

# REPO_ROOT is the checkout root (the directory containing tests/).
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENTRYPOINT_PATH="${ENTRYPOINT_PATH:-$REPO_ROOT/entrypoint.sh}"
ACTION_YML="${ACTION_YML:-$REPO_ROOT/action.yml}"

# ---------------------------------------------------------------------------
# Portable sha256 - works on both Linux (sha256sum) and macOS (shasum -a 256).
# ---------------------------------------------------------------------------
helper_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ---------------------------------------------------------------------------
# make_test_workspace
#
# Creates a fresh isolated test temp directory and exports the standard
# GitHub Actions env vars pointing into it. After this helper runs the
# caller has $TEST_TMP set; teardown_test_workspace tears it down.
#
# Layout:
#   $TEST_TMP/runner-temp/   - $RUNNER_TEMP
#   $TEST_TMP/workspace/     - $GITHUB_WORKSPACE (also customer repo root)
#   $TEST_TMP/action/        - $GITHUB_ACTION_PATH (where the action lives)
#   $TEST_TMP/event.json     - $GITHUB_EVENT_PATH
#   $TEST_TMP/output         - $GITHUB_OUTPUT
#   $TEST_TMP/bin/           - prepended to $PATH for mock binaries
# ---------------------------------------------------------------------------
make_test_workspace() {
    TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/ov-scan-action-test.XXXXXX")"
    export TEST_TMP

    mkdir -p \
        "$TEST_TMP/runner-temp" \
        "$TEST_TMP/workspace" \
        "$TEST_TMP/action" \
        "$TEST_TMP/action/vendor" \
        "$TEST_TMP/bin"

    : > "$TEST_TMP/output"

    export RUNNER_TEMP="$TEST_TMP/runner-temp"
    export GITHUB_WORKSPACE="$TEST_TMP/workspace"
    export GITHUB_ACTION_PATH="$TEST_TMP/action"
    export GITHUB_OUTPUT="$TEST_TMP/output"
    export GITHUB_EVENT_PATH="$TEST_TMP/event.json"

    # Default to a push event over the same-repo. Tests override this.
    export GITHUB_EVENT_NAME="push"
    export GITHUB_REPOSITORY="opaquev/test-fixture"

    # RUNNER_OS - defaults to actual host. Tests can override.
    if [ "$(uname -s)" = "Darwin" ]; then
        export RUNNER_OS="macOS"
    else
        export RUNNER_OS="Linux"
    fi

    # Prepend our mock-bin dir so tests can intercept commands.
    export PATH="$TEST_TMP/bin:$PATH"
}

teardown_test_workspace() {
    if [ -n "${TEST_TMP:-}" ] && [ -d "$TEST_TMP" ]; then
        chmod -R u+w "$TEST_TMP" 2>/dev/null || true
        rm -rf "$TEST_TMP"
    fi
    unset TEST_TMP RUNNER_TEMP GITHUB_WORKSPACE GITHUB_ACTION_PATH GITHUB_OUTPUT \
          GITHUB_EVENT_PATH GITHUB_EVENT_NAME GITHUB_REPOSITORY RUNNER_OS \
          INPUT_PATH INPUT_BASELINE_FILE INPUT_FAIL_ON \
          INPUT_MIN_OV_VERSION INPUT_MAX_OV_VERSION \
          INPUT_ALLOW_PULL_REQUEST_TARGET INPUT_ALLOW_BINARY_VERSION \
          INPUT_ALLOW_CI_BASELINE INPUT_TIME_BUDGET INPUT_MEMORY_BUDGET
}

# ---------------------------------------------------------------------------
# make_event_payload <kind> [head_repo]
#
# Creates a $GITHUB_EVENT_PATH JSON payload of the requested kind.
#   kind in { push | workflow_dispatch | same-repo-pr | fork-pr |
#            null-head-pr | empty | pull-request-target |
#            pull-request-target-fork }
# ---------------------------------------------------------------------------
make_event_payload() {
    local kind="$1"
    local head_repo="${2:-fork-user/test-fixture}"

    case "$kind" in
        push)
            export GITHUB_EVENT_NAME="push"
            printf '%s\n' '{"ref":"refs/heads/main","before":"0000","after":"abcd"}' > "$GITHUB_EVENT_PATH"
            ;;
        workflow_dispatch)
            export GITHUB_EVENT_NAME="workflow_dispatch"
            printf '%s\n' '{"inputs":{}}' > "$GITHUB_EVENT_PATH"
            ;;
        same-repo-pr)
            export GITHUB_EVENT_NAME="pull_request"
            printf '{"pull_request":{"head":{"repo":{"full_name":"%s"}}}}\n' \
                "$GITHUB_REPOSITORY" > "$GITHUB_EVENT_PATH"
            ;;
        fork-pr)
            export GITHUB_EVENT_NAME="pull_request"
            printf '{"pull_request":{"head":{"repo":{"full_name":"%s"}}}}\n' \
                "$head_repo" > "$GITHUB_EVENT_PATH"
            ;;
        null-head-pr)
            export GITHUB_EVENT_NAME="pull_request"
            printf '%s\n' '{"pull_request":{"head":{"repo":null}}}' > "$GITHUB_EVENT_PATH"
            ;;
        pull-request-target)
            export GITHUB_EVENT_NAME="pull_request_target"
            printf '{"pull_request":{"head":{"repo":{"full_name":"%s"}}}}\n' \
                "$GITHUB_REPOSITORY" > "$GITHUB_EVENT_PATH"
            ;;
        pull-request-target-fork)
            export GITHUB_EVENT_NAME="pull_request_target"
            printf '{"pull_request":{"head":{"repo":{"full_name":"%s"}}}}\n' \
                "$head_repo" > "$GITHUB_EVENT_PATH"
            ;;
        empty)
            export GITHUB_EVENT_NAME="pull_request"
            : > "$GITHUB_EVENT_PATH"
            ;;
        *)
            echo "make_event_payload: unknown kind '$kind'" >&2
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# install_trusted_keys [variant]
#
# Stage a trusted-keys.txt fixture into $GITHUB_ACTION_PATH/trusted-keys.txt.
#   variant in { valid | malformed | extra-tokens | unknown-role |
#                zero-required | two-required | hex-fingerprint | symlink }
# ---------------------------------------------------------------------------
install_trusted_keys() {
    local variant="${1:-valid}"
    local target="$GITHUB_ACTION_PATH/trusted-keys.txt"

    case "$variant" in
        valid)
            printf '%s\n%s\n' \
                '# Test fixture trusted keys' \
                'RWQLHCx3CKub+D3Wnc1zX/YBVr1fJD5SrK08d2xp4XoTQipbFET8V0fU required' \
                > "$target"
            ;;
        valid-with-legacy)
            printf '%s\n%s\n%s\n' \
                'RWQLHCx3CKub+D3Wnc1zX/YBVr1fJD5SrK08d2xp4XoTQipbFET8V0fU required' \
                'RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA legacy' \
                'RWQBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB legacy' \
                > "$target"
            ;;
        malformed)
            printf '%s\n' 'RWQLHCx3CKub+D3Wnc1zX/YBVr1fJD5SrK08d2xp4XoTQipbFET8V0fU' > "$target"
            ;;
        extra-tokens)
            printf '%s\n' 'RWQLHCx3CKub+D3Wnc1zX/YBVr1fJD5SrK08d2xp4XoTQipbFET8V0fU required EXTRA-TOKEN' > "$target"
            ;;
        unknown-role)
            printf '%s\n' 'RWQLHCx3CKub+D3Wnc1zX/YBVr1fJD5SrK08d2xp4XoTQipbFET8V0fU primary' > "$target"
            ;;
        zero-required)
            printf '%s\n' 'RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA legacy' > "$target"
            ;;
        two-required)
            printf '%s\n%s\n' \
                'RWQLHCx3CKub+D3Wnc1zX/YBVr1fJD5SrK08d2xp4XoTQipbFET8V0fU required' \
                'RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA required' \
                > "$target"
            ;;
        hex-fingerprint)
            printf '%s\n' 'F89BAB08772C1C0B required' > "$target"
            ;;
        symlink)
            local linktgt
            linktgt="$(mktemp "${TMPDIR:-/tmp}/attacker-controlled.XXXXXX")"
            printf '%s\n' 'RWQLHCx3CKub+D3Wnc1zX/YBVr1fJD5SrK08d2xp4XoTQipbFET8V0fU required' > "$linktgt"
            ln -sf "$linktgt" "$target"
            ;;
        *)
            echo "install_trusted_keys: unknown variant '$variant'" >&2
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# install_minisign_stub
#
# Drop a placeholder file in $GITHUB_ACTION_PATH/vendor/minisign-* so that
# entrypoint.sh's symlink/SHA checks have something to operate on. Tests
# of the actual signature flow stub the binary's behavior via a wrapper.
# ---------------------------------------------------------------------------
install_minisign_stub() {
    local target="$GITHUB_ACTION_PATH/vendor"
    mkdir -p "$target"
    # All vendored target names - entrypoint.sh picks one based on RUNNER_OS+arch.
    for name in minisign-0.12-linux_amd64 minisign-0.12-linux_arm64 minisign-0.12-darwin_arm64; do
        printf '#!/bin/sh\nexit 0\n' > "$target/$name"
        chmod +x "$target/$name"
    done
}

# ---------------------------------------------------------------------------
# install_clean_repo / install_dirty_repo
#
# Copy the corresponding fixture into $GITHUB_WORKSPACE.
# ---------------------------------------------------------------------------
install_clean_repo() {
    cp -R "$REPO_ROOT/tests/fixtures/clean-repo/." "$GITHUB_WORKSPACE/"
}

install_dirty_repo() {
    cp -R "$REPO_ROOT/tests/fixtures/dirty-repo/." "$GITHUB_WORKSPACE/"
}

# ---------------------------------------------------------------------------
# mock_ov_bin <scan-json> [version-text]
#
# Drop a mock ov binary into $TEST_TMP/bin so that exec()s of ov from
# entrypoint.sh execute our stub. The mock recognizes:
#   - --version            -> emit version-text and exit 0
#   - --check-version-bounds ...  -> exit 0
#   - scan ...             -> emit scan-json and exit 0
# Tests that need richer behavior write their own custom stub directly.
# ---------------------------------------------------------------------------
mock_ov_bin() {
    # Note: bash parameter expansion `${1:-{...}}` doesn't count nested braces,
    # so the closing `}}` would tack a trailing `}` onto a caller-supplied
    # value (helpers-bug discovered during PR #5 green phase). Use a plain
    # default-via-empty-check instead.
    local scan_json="${1-}"
    if [ -z "$scan_json" ]; then
        scan_json='{"findings":[]}'
    fi
    local version_text="${2:-ov version 0.10.0 (commit abc123, built 2026-05-05T00:00:00Z)}"
    local target="$TEST_TMP/bin/ov"
    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' '# Mock ov binary for tests.'
        printf '%s\n' 'if [ -n "${MOCK_OV_DUMP_ENV:-}" ]; then'
        printf '%s\n' '    env > "$MOCK_OV_DUMP_ENV"'
        printf '%s\n' 'fi'
        printf '%s\n' 'case "$1" in'
        printf '%s\n' '    --version)'
        printf "        printf '%%s\\n' '%s'\n" "$version_text"
        printf '%s\n' '        exit 0'
        printf '%s\n' '        ;;'
        printf '%s\n' '    --check-version-bounds)'
        printf '%s\n' '        exit 0'
        printf '%s\n' '        ;;'
        printf '%s\n' '    scan)'
        printf "        printf '%%s\\n' '%s'\n" "$scan_json"
        printf '%s\n' '        exit 0'
        printf '%s\n' '        ;;'
        printf '%s\n' 'esac'
        printf '%s\n' 'exit 1'
    } > "$target"
    chmod +x "$target"
}

# ---------------------------------------------------------------------------
# run_entrypoint
#
# Invoke entrypoint.sh under the prepared environment, capturing exit code,
# stdout, and stderr. Designed to be called from a bats run invocation:
#
#     run run_entrypoint
#
# Exit code propagates via bash entrypoint.sh's rc.
# ---------------------------------------------------------------------------
run_entrypoint() {
    # Use absolute /bin/bash so tests that set PATH to a minimal value
    # (e.g. #26 TestRefusesMissingJq) still find a bash to launch with.
    /bin/bash "$ENTRYPOINT_PATH"
}

# ---------------------------------------------------------------------------
# skip_if_no_entrypoint
#
# Call from each test's setup() (or first line of @test body) to auto-skip
# during PR #4 (red phase) when entrypoint.sh / action.yml don't exist
# yet. PR #5 ships those files and the skip auto-disables. The contracts
# remain authoritative — implementer sees them flip from "skipped" →
# "failed" → "passed" as PR #5 progresses.
#
# `skip` only works when called from the test body directly (or from
# setup() invoked by bats), NOT from within a function called via `run`.
# That's why this is a separate helper rather than baked into run_entrypoint.
# ---------------------------------------------------------------------------
skip_if_no_entrypoint() {
    if [ ! -f "$ENTRYPOINT_PATH" ]; then
        skip "entrypoint.sh not yet present (PR #5 implements)"
    fi
}

# ---------------------------------------------------------------------------
# get_output_value <key>
#
# Read a key=value line from $GITHUB_OUTPUT and print the value.
# ---------------------------------------------------------------------------
get_output_value() {
    local key="$1"
    grep -E "^${key}=" "$GITHUB_OUTPUT" | tail -1 | cut -d= -f2-
}

# ---------------------------------------------------------------------------
# assert_no_output_key <key>
#
# Fail the test if the named key was written to $GITHUB_OUTPUT.
# ---------------------------------------------------------------------------
assert_no_output_key() {
    local key="$1"
    if grep -qE "^${key}=" "$GITHUB_OUTPUT" 2>/dev/null; then
        echo "expected NO line ${key}= in \$GITHUB_OUTPUT, but found:" >&2
        grep -E "^${key}=" "$GITHUB_OUTPUT" >&2
        return 1
    fi
}
