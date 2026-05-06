#!/usr/bin/env bash
# tests/run-locally.sh — local-testing helper for ov-scan-action.
#
# Wraps the bats test suite with the GitHub Actions context env vars
# the action requires (`entrypoint.sh` exits early via `: ${VAR:?...}`
# checks if any of these are missing). For contributors who want to
# repro test failures locally without learning act's flag matrix.
#
# Usage:
#   ./tests/run-locally.sh                # run full bats suite (75 tests)
#   ./tests/run-locally.sh --filter '#26' # run a subset
#
# This script does NOT install the system-level dependencies bats needs
# (bats-core, jq, perl). On macOS:
#   brew install bats-core jq
# On Ubuntu/Debian:
#   sudo apt-get install -y bats jq
# Perl ships with both OSes by default.
#
# This script is for the LOCAL bats harness — it does NOT exercise the
# composite-action surface (action.yml). To test the composite-action
# surface, push a branch and let GH Actions run it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Sanity check: bats must be installed.
if ! command -v bats >/dev/null 2>&1; then
    cat >&2 <<'EOF'
::error::bats not found in PATH.

Install bats-core:
  macOS:   brew install bats-core
  Ubuntu:  sudo apt-get install -y bats

Then re-run this script.
EOF
    exit 127
fi

# Sanity check: jq is required by helpers.bash.
if ! command -v jq >/dev/null 2>&1; then
    echo "::error::jq not found in PATH. Install via 'brew install jq' or 'apt-get install jq'." >&2
    exit 127
fi

# Sanity check: perl required for OV_TIMEOUT shim on macos-without-coreutils.
if ! command -v perl >/dev/null 2>&1 && [ ! -x /usr/bin/perl ]; then
    echo "::warning::perl not found; OV_TIMEOUT shim may fall back differently than CI." >&2
fi

# Note: the bats harness's helpers.bash creates an isolated TEST_TMP for
# each test and exports the GITHUB_* env vars there. We don't need to
# pre-export those at this script level — bats setup() does it per-test.
#
# What we DO need: ensure $RUNNER_OS is sensible (helpers default it from
# `uname -s`, but if the contributor has a stale environment with
# RUNNER_OS=Windows from a prior `act` run, helpers will pick that up).
# Reset it to match the local host.
case "$(uname -s)" in
    Linux*)  export RUNNER_OS="Linux"  ;;
    Darwin*) export RUNNER_OS="macOS"  ;;
    *)
        echo "::error::unsupported local OS: $(uname -s) — bats needs Linux or macOS host." >&2
        exit 2
        ;;
esac

# Forward args directly to bats so e.g. `--filter '#26'` works.
exec bats "$@" tests/
