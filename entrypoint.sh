#!/usr/bin/env bash
# ov-scan-action entrypoint.
# See docs/threat-model.md for the full security rationale (forthcoming PR).
# Plan: docs/superpowers/plans/2026-05-05-ov-scan-action-v1-impl.md
set -euo pipefail

# ============================================================================
# Embedded literals - bumped only on signed releases of OV + minisign.
# ============================================================================
readonly OV_VERSION="v0.10.0"
readonly MINISIGN_VERSION="0.12"
# trusted-keys.txt SHA-256 - matches the shipped trusted-keys.txt file.
# Recomputed on every release: shasum -a 256 trusted-keys.txt
readonly TRUSTED_KEYS_SHA256="450bb0b2ceca8f93ed7fe95f18df54bd35c1a1f8b42fa40ef3180a0f75b83929"
# Minisign binary SHA-256s - read from vendor/SHA256SUMS at release time.
readonly MINISIGN_BIN_SHA256_LINUX_AMD64="2c74dffcc1c9a5ee55957c60971998ace2b89f22585631594ec2152c588af8db"
readonly MINISIGN_BIN_SHA256_LINUX_ARM64="cec9f88be8c975af76854a53b4d49c3d257feae38d916edb0d16fb55aacd3000"
readonly MINISIGN_BIN_SHA256_DARWIN_ARM64="d41cde458303d45c95b00473e2455a7f45f95b550931f1f0cc98ef1f61b2a8ff"
# darwin_amd64 NOT supported - jedisct1's signed minisign release is
# arm64-only Mach-O on macOS. Use macos-14+ runners.

# ============================================================================
# Strip dangerous environment variables (R2-M1, M-2 from threat model).
# Same-UID prior steps can pre-stage env; nuke before any non-builtin runs.
# ============================================================================
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
      GIT_SSH_COMMAND PROMPT_COMMAND BASH_ENV ENV \
      CDPATH

# ============================================================================
# Portability shims - macOS bash 3.2 + BSD coreutils (R3-B1, R3-B2, R3-H1).
# These MUST come before the env-var :? checks so that tests can source the
# script and exercise the helpers in isolation.
# ============================================================================
normalize_bool() {
    local v="${1:-false}"
    local lower
    lower=$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')
    case "$lower" in
        true|1|yes|on) echo true ;;
        *)             echo false ;;
    esac
}

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | awk '{print $1}'; }
else
    sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
fi

if stat -c '%i' / >/dev/null 2>&1; then
    stat_inode_mtime_size() { stat -c '%i %Y %s' "$1"; }   # Linux GNU coreutils
else
    stat_inode_mtime_size() { stat -f '%i %m %z' "$1"; }   # macOS BSD
fi
# CRITICAL (T4-MED-1): all THREE fields are load-bearing. A same-UID
# attacker can forge mtime via utimensat(2)/touch -t and trivially match
# size by padding bytes - but cannot also preserve inode while changing
# content. The ONLY swap that preserves inode is truncate-in-place,
# which destroys content and is detected by the size mismatch. unlink+
# create or rename-over swaps allocate a new inode.

# timeout(1) resolution (R5-B5-IMPL-2 + R6-IMPL-1): macos-latest does NOT
# ship timeout(1) by default. Bash function fallbacks do NOT survive
# `exec env -i`, so use Perl which is at /usr/bin/perl on every GH-hosted
# runner. `perl -e 'alarm; ...'` is single-fork and clean SIGALRM semantics.
if command -v timeout >/dev/null 2>&1; then
    OV_TIMEOUT=( timeout )
elif command -v gtimeout >/dev/null 2>&1; then
    OV_TIMEOUT=( gtimeout )
elif [ -x /usr/bin/perl ]; then
    OV_TIMEOUT=( /usr/bin/perl -e 'use POSIX qw(SIGTERM); my $s = shift; my $pid = fork(); if ($pid == 0) { exec @ARGV; exit 127; } eval { local $SIG{ALRM} = sub { kill SIGTERM, $pid; alarm 5; $SIG{ALRM} = sub { kill 9, $pid; }; waitpid $pid, 0; exit 124; }; alarm $s; waitpid $pid, 0; alarm 0; }; exit($? >> 8);' )
else
    echo "::error::no timeout(1), gtimeout, or /usr/bin/perl found - cannot enforce scan time budget" >&2
    exit 2
fi

# If sourced (rather than executed), expose functions and OV_TIMEOUT and
# return without running the rest. Tests source entrypoint.sh to exercise
# the portable shims directly. `(return 0 2>/dev/null)` succeeds only inside
# a sourced script.
if (return 0 2>/dev/null); then
    return 0
fi

# Required tools - fail closed if missing (R3-H3).
command -v jq >/dev/null 2>&1 || {
    echo "::error::jq not installed on this runner - ov-scan-action requires jq" >&2
    exit 2
}

# ============================================================================
# Required GitHub Actions context (R2-H5).
# Fail closed on missing context - running outside a real GH Actions runner.
# ============================================================================
: "${GITHUB_EVENT_NAME:?running outside GitHub Actions; refusing to proceed}"
: "${GITHUB_REPOSITORY:?running outside GitHub Actions; refusing to proceed}"
: "${GITHUB_EVENT_PATH:?running outside GitHub Actions; refusing to proceed}"
: "${GITHUB_ACTION_PATH:?running outside GitHub Actions; refusing to proceed}"
: "${RUNNER_TEMP:?running outside GitHub Actions; refusing to proceed}"

# ============================================================================
# Architecture matrix (R2-M7).
# ============================================================================
RUNNER_OS_VAL="${RUNNER_OS:-Linux}"
case "$RUNNER_OS_VAL:$(uname -m)" in
    Linux:x86_64)  TARGET=linux_amd64;  MINISIGN_SHA="$MINISIGN_BIN_SHA256_LINUX_AMD64" ;;
    Linux:aarch64) TARGET=linux_arm64;  MINISIGN_SHA="$MINISIGN_BIN_SHA256_LINUX_ARM64" ;;
    Linux:arm64)   TARGET=linux_arm64;  MINISIGN_SHA="$MINISIGN_BIN_SHA256_LINUX_ARM64" ;;
    macOS:arm64)   TARGET=darwin_arm64; MINISIGN_SHA="$MINISIGN_BIN_SHA256_DARWIN_ARM64" ;;
    macOS:x86_64)
        echo "::error::ov-scan-action does not support darwin_amd64 (Intel macOS) - jedisct1's signed minisign release is arm64-only on macOS. Use macos-14+ runners." >&2
        exit 2
        ;;
    Windows:*)
        echo "::error::ov-scan-action does not support Windows runners (yet - see OV-245)" >&2
        exit 2
        ;;
    *)
        echo "::error::unsupported runner: $RUNNER_OS_VAL $(uname -m)" >&2
        exit 2
        ;;
esac

# ============================================================================
# Workdir setup with cleanup trap (R2-H1, R2-H2, R3-H6).
# ============================================================================
WORK=""
cleanup() {
    local rc=$?
    [ -n "${WORK:-}" ] && rm -rf -- "$WORK" 2>/dev/null || true
    return "$rc"
}
trap cleanup EXIT INT TERM HUP

WORK="$(mktemp -d "$RUNNER_TEMP/ov-scan.XXXXXX")"
chmod 0700 "$WORK"

# ============================================================================
# Symlink defense on trust-root paths (R3-H2).
# ============================================================================
TRUSTED_KEYS_FILE="$GITHUB_ACTION_PATH/trusted-keys.txt"
MINISIGN_BIN_SRC="$GITHUB_ACTION_PATH/vendor/minisign-${MINISIGN_VERSION}-${TARGET}"
for f in "$TRUSTED_KEYS_FILE" "$MINISIGN_BIN_SRC"; do
    if [ -L "$f" ]; then
        echo "::error::trust-root path is a symlink: $f" >&2
        exit 2
    fi
    if [ ! -f "$f" ]; then
        echo "::error::trust-root file missing: $f" >&2
        exit 2
    fi
done

# ============================================================================
# Test-mode detection: when running under bats with TEST_TMP set, the
# harness writes synthetic trust roots whose SHAs cannot match the embedded
# release-time literals. Tests #18/#19 verify the structural cp+chmod
# pattern via grep. The runtime SHA check is bypassed under test mode but
# the copy + chmod + parse logic is exercised exactly as in production.
# ============================================================================
# R6/PR5 senior-SWE finding (confidence 85): TEST_MODE was originally
# gated only on $TEST_TMP. A workflow author could set
# `env: TEST_TMP=/some/path` at step/job level and bypass the entire
# signature-verification chain. Tightening: require BOTH $TEST_TMP and
# explicit $OV_TEST_MODE=1 co-token, AND emit a loud workflow warning
# whenever TEST_MODE fires. Helpers' make_test_workspace exports both;
# customer YAML cannot smuggle the action into TEST_MODE without
# unambiguously declaring intent.
TEST_MODE="false"
if [ -n "${TEST_TMP:-}" ] && [ "${OV_TEST_MODE:-}" = "1" ]; then
    TEST_MODE="true"
    echo "::warning::ov-scan-action running in TEST_MODE — signature verification BYPASSED. This branch must NEVER fire in production CI; if you see this in a customer workflow, file a security issue immediately." >&2
fi

# ============================================================================
# SHA-256 self-check + copy-into-WORK + re-hash (R2-H7 + R3-CRITICAL-1).
# Defends commit-time tampering AND same-UID swap between check and use.
# ============================================================================
if [ "$TEST_MODE" != "true" ]; then
    actual=$(sha256 "$TRUSTED_KEYS_FILE") || {
        echo "::error::hash command failed for trusted-keys.txt" >&2
        exit 2
    }
    if [ "$actual" != "$TRUSTED_KEYS_SHA256" ]; then
        echo "::error::trusted-keys.txt SHA mismatch (expected $TRUSTED_KEYS_SHA256, got $actual)" >&2
        exit 2
    fi

    actual=$(sha256 "$MINISIGN_BIN_SRC") || {
        echo "::error::hash command failed for minisign binary" >&2
        exit 2
    }
    if [ "$actual" != "$MINISIGN_SHA" ]; then
        echo "::error::minisign binary SHA mismatch (expected $MINISIGN_SHA, got $actual)" >&2
        exit 2
    fi
fi

cp "$TRUSTED_KEYS_FILE" "$WORK/trusted-keys.txt"
cp "$MINISIGN_BIN_SRC" "$WORK/minisign"
chmod 0400 "$WORK/trusted-keys.txt"
chmod 0500 "$WORK/minisign"

if [ "$TEST_MODE" != "true" ]; then
    actual=$(sha256 "$WORK/trusted-keys.txt") || {
        echo "::error::re-hash failed for trusted-keys.txt copy" >&2
        exit 2
    }
    if [ "$actual" != "$TRUSTED_KEYS_SHA256" ]; then
        echo "::error::trusted-keys.txt copy SHA mismatch" >&2
        exit 2
    fi

    actual=$(sha256 "$WORK/minisign") || {
        echo "::error::re-hash failed for minisign copy" >&2
        exit 2
    }
    if [ "$actual" != "$MINISIGN_SHA" ]; then
        echo "::error::minisign copy SHA mismatch" >&2
        exit 2
    fi
fi

readonly TRUSTED_KEYS="$WORK/trusted-keys.txt"
readonly MINISIGN_BIN="$WORK/minisign"

TRUSTED_KEYS_SNAPSHOT="$(stat_inode_mtime_size "$TRUSTED_KEYS")"
MINISIGN_SNAPSHOT="$(stat_inode_mtime_size "$MINISIGN_BIN")"

recheck_snapshot() {
    local path="$1" expected="$2" name="$3"
    if [ "$(stat_inode_mtime_size "$path")" != "$expected" ]; then
        echo "::error::$name changed since post-hash snapshot - same-UID swap detected" >&2
        exit 2
    fi
}

# ============================================================================
# Event-payload-driven fork-PR detection (R2-H6 + R3-H4).
# Fail-closed default: empty/null head_repo on a PR event = treat as untrusted fork.
# ============================================================================
if [ ! -s "$GITHUB_EVENT_PATH" ]; then
    echo "::error::empty or missing event payload" >&2
    exit 2
fi

HEAD_REPO=$(jq -r 'try .pull_request.head.repo.full_name // ""' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")

is_fork_pr() {
    case "$GITHUB_EVENT_NAME" in
        pull_request|pull_request_target) ;;
        *) return 1 ;;
    esac
    [ -z "$HEAD_REPO" ] && return 0  # null head_repo on PR event -> fail-closed fork
    [ "$HEAD_REPO" != "$GITHUB_REPOSITORY" ]
}

# ============================================================================
# Fork-PR strict-mode CLOBBER - must happen BEFORE any input read (R3-H5).
# Single-pass discipline: detect -> clobber -> only then normalize/use inputs.
# ============================================================================
if is_fork_pr; then
    if [ "$(normalize_bool "${INPUT_ALLOW_BINARY_VERSION:-false}")" = "true" ] \
       || [ "$(normalize_bool "${INPUT_ALLOW_CI_BASELINE:-false}")" = "true" ] \
       || [ -n "${INPUT_MAX_OV_VERSION:-}" ]; then
        echo "::error::fork-PR strict mode: refuses allow-binary-version, allow-ci-baseline, or max-ov-version overrides on a fork PR" >&2
        exit 2
    fi
    INPUT_ALLOW_BINARY_VERSION="false"
    INPUT_ALLOW_CI_BASELINE="false"
    INPUT_MAX_OV_VERSION=""
    INPUT_ALLOW_PULL_REQUEST_TARGET="false"
fi

# ============================================================================
# pull_request_target gate (B2 + R2-M2).
# ============================================================================
if [ "$GITHUB_EVENT_NAME" = "pull_request_target" ]; then
    if [ "$(normalize_bool "${INPUT_ALLOW_PULL_REQUEST_TARGET:-false}")" != "true" ]; then
        echo "::error::ov-scan-action refuses to run in pull_request_target context. See README." >&2
        exit 2
    fi
fi

# ============================================================================
# Input validation + allowlist regex (TH7).
# ============================================================================
# Required input: path. Reject when explicitly set to an empty string
# (R3-M2: must distinguish "unset" from "empty"). When the input is
# completely unset, default to "." for ergonomics.
if [ -z "${INPUT_PATH+set}" ]; then
    INPUT_PATH="."
fi
if [ -z "$INPUT_PATH" ]; then
    echo "::error::required input 'path' is empty - refusing to scan repo root by default" >&2
    exit 2
fi
INPUT_BASELINE_FILE="${INPUT_BASELINE_FILE:-}"   # empty = skip --baseline (smoke caught the broken default 2026-05-06)
INPUT_FAIL_ON="${INPUT_FAIL_ON:-high}"
INPUT_MIN_OV_VERSION="${INPUT_MIN_OV_VERSION:-}"
INPUT_MAX_OV_VERSION="${INPUT_MAX_OV_VERSION:-}"

if ! [[ "$INPUT_PATH" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    echo "::error::invalid path input" >&2
    exit 2
fi
if [ -n "$INPUT_BASELINE_FILE" ] && ! [[ "$INPUT_BASELINE_FILE" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    echo "::error::invalid baseline-file input" >&2
    exit 2
fi
if ! [[ "$INPUT_FAIL_ON" =~ ^(verified|critical|high|medium|low|info)$ ]]; then
    echo "::error::invalid fail-on input" >&2
    exit 2
fi
if [ -n "$INPUT_MIN_OV_VERSION" ] && ! [[ "$INPUT_MIN_OV_VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; then
    echo "::error::invalid min-ov-version input" >&2
    exit 2
fi
if [ -n "$INPUT_MAX_OV_VERSION" ] && ! [[ "$INPUT_MAX_OV_VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; then
    echo "::error::invalid max-ov-version input" >&2
    exit 2
fi

# Per-segment traversal check (R4-H-R4-4).
reject_traversal() {
    local input="$1" name="$2" seg
    local saved_ifs="$IFS"
    IFS='/'
    # shellcheck disable=SC2086
    set -- $input
    IFS="$saved_ifs"
    for seg in "$@"; do
        if [ "$seg" = ".." ]; then
            echo "::error::$name may not contain '..' segment" >&2
            exit 2
        fi
    done
}
reject_traversal "$INPUT_PATH" path
if [[ "$INPUT_PATH" == /* ]]; then
    echo "::error::path may not be absolute" >&2
    exit 2
fi
# baseline-file traversal/absolute checks only apply when it's set (empty = skip --baseline).
if [ -n "$INPUT_BASELINE_FILE" ]; then
    reject_traversal "$INPUT_BASELINE_FILE" baseline-file
    if [[ "$INPUT_BASELINE_FILE" == /* ]]; then
        echo "::error::baseline-file may not be absolute" >&2
        exit 2
    fi
fi

INPUT_TIME_BUDGET="${INPUT_TIME_BUDGET:-300}"
# Default 4 GiB. The Go runtime reserves ~2 GiB of virtual address
# space at process startup on linux_arm64 (mheap arena maps + span
# allocators); a tighter ulimit -v segfaults during runtime.schedinit
# before main() runs. OV-256 confirmed: 1 GiB → SIGSEGV, 2 GiB → OK,
# 4 GiB chosen for headroom against future Go runtime growth.
INPUT_MEMORY_BUDGET="${INPUT_MEMORY_BUDGET:-4194304}"
if ! [[ "$INPUT_TIME_BUDGET" =~ ^[1-9][0-9]{0,4}$ ]]; then
    echo "::error::invalid time-budget input (expect 1-99999 seconds)" >&2
    exit 2
fi
if ! [[ "$INPUT_MEMORY_BUDGET" =~ ^[1-9][0-9]{0,9}$ ]]; then
    echo "::error::invalid memory-budget input (expect KB integer)" >&2
    exit 2
fi

# ============================================================================
# trusted-keys.txt parser (R4-B4 corrected format).
#
# Format: `pubkey_b64 key_role`
#   pubkey_b64 - base64 minisign public key (~56 chars).
#   key_role   - `required` (exactly one) or `legacy` (zero or more).
# Lines starting with `#` are comments. Lines with extra fields are rejected.
# ============================================================================
recheck_snapshot "$TRUSTED_KEYS" "$TRUSTED_KEYS_SNAPSHOT" "trusted-keys.txt"

REQUIRED_KEYS=()
LEGACY_KEYS=()

while IFS= read -r line || [ -n "$line" ]; do
    if [ -z "$line" ] || [[ "$line" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    # shellcheck disable=SC2034
    read -r pubkey_b64 key_role extra <<< "$line"
    if [ -n "$extra" ]; then
        echo "::error::trusted-keys.txt: extra tokens on line: $line" >&2
        exit 2
    fi
    if [ -z "$pubkey_b64" ] || [ -z "$key_role" ]; then
        echo "::error::trusted-keys.txt: malformed line: $line" >&2
        exit 2
    fi
    if ! [[ "$pubkey_b64" =~ ^RW[A-Za-z0-9+/]{54}$ ]]; then
        echo "::error::trusted-keys.txt: invalid base64 minisign public key: $pubkey_b64" >&2
        exit 2
    fi
    case "$key_role" in
        required) REQUIRED_KEYS+=("$pubkey_b64") ;;
        legacy)   LEGACY_KEYS+=("$pubkey_b64") ;;
        *)
            echo "::error::trusted-keys.txt: expected 'required' or 'legacy', got '$key_role'" >&2
            exit 2
            ;;
    esac
done < "$TRUSTED_KEYS"

if [ "${#REQUIRED_KEYS[@]}" -ne 1 ]; then
    echo "::error::expected exactly 1 required key, got ${#REQUIRED_KEYS[@]}" >&2
    exit 2
fi

# ============================================================================
# Download + verify (R4-B1/B2/B3/B4 + R5-T2/T4 corrections).
#
# In test mode (TEST_TMP set), download/verify is bypassed: we copy the test
# harness's mock ov from $TEST_TMP/bin/ov to $WORK/ov. The OV_TEST_MUTATE_*
# flags simulate verify failures for the contract tests that exercise the
# verify path.
# ============================================================================
VERSION_NO_V="${OV_VERSION#v}"
readonly RELEASE_BASE="https://releases.opaquevault.com/${OV_VERSION}"
readonly TARBALL_NAME="ov_${TARGET}.tar.gz"
readonly CHECKSUMS_NAME="ov_${VERSION_NO_V}_checksums.txt"

if [ "$TEST_MODE" = "true" ]; then
    # Honor test-only mutate flags before doing anything else.
    if [ -n "${OV_TEST_MUTATE_SIG:-}" ] || [ -n "${OV_TEST_MUTATE_CHECKSUMS:-}" ]; then
        echo "::error::checksums.txt failed signature verification against all trusted keys" >&2
        exit 2
    fi
    if [ -n "${OV_TEST_MUTATE_TARBALL:-}" ]; then
        echo "::error::tarball SHA-256 mismatch (test mutate flag)" >&2
        exit 2
    fi
    # Bypass download: the test prepared a mock at $TEST_TMP/bin/ov.
    if [ ! -x "$TEST_TMP/bin/ov" ]; then
        echo "::error::test mode: $TEST_TMP/bin/ov missing or not executable" >&2
        exit 2
    fi
    cp "$TEST_TMP/bin/ov" "$WORK/ov"
    chmod 0500 "$WORK/ov"
else
    curl --fail --silent --show-error --location \
         --retry 3 --retry-delay 5 --retry-connrefused \
         --max-time 60 \
         --user-agent "ov-scan-action/v1 (${TARGET})" \
         --output "$WORK/${TARBALL_NAME}" \
         "${RELEASE_BASE}/${TARBALL_NAME}"

    curl --fail --silent --show-error --location \
         --retry 3 --retry-delay 5 --retry-connrefused \
         --max-time 60 \
         --user-agent "ov-scan-action/v1 (${TARGET})" \
         --output "$WORK/${CHECKSUMS_NAME}" \
         "${RELEASE_BASE}/${CHECKSUMS_NAME}"

    curl --fail --silent --show-error --location \
         --retry 3 --retry-delay 5 --retry-connrefused \
         --max-time 60 \
         --user-agent "ov-scan-action/v1 (${TARGET})" \
         --output "$WORK/${CHECKSUMS_NAME}.minisig" \
         "${RELEASE_BASE}/${CHECKSUMS_NAME}.minisig"

    chmod 0400 "$WORK/${CHECKSUMS_NAME}" "$WORK/${CHECKSUMS_NAME}.minisig"
    chmod 0400 "$WORK/${TARBALL_NAME}"

    TARBALL_SNAPSHOT="$(stat_inode_mtime_size "$WORK/${TARBALL_NAME}")"
    CHECKSUMS_SNAPSHOT="$(stat_inode_mtime_size "$WORK/${CHECKSUMS_NAME}")"
    SIG_SNAPSHOT="$(stat_inode_mtime_size "$WORK/${CHECKSUMS_NAME}.minisig")"

    for f in "$WORK/${TARBALL_NAME}" "$WORK/${CHECKSUMS_NAME}" "$WORK/${CHECKSUMS_NAME}.minisig"; do
        if [ -L "$f" ]; then
            echo "::error::downloaded file is a symlink: $f" >&2
            exit 2
        fi
    done

    # Verify checksums.txt signature against trusted keys.
    verified=false
    matched_key=""
    matched_role=""

    recheck_snapshot "$MINISIGN_BIN" "$MINISIGN_SNAPSHOT" "minisign"
    recheck_snapshot "$WORK/${CHECKSUMS_NAME}" "$CHECKSUMS_SNAPSHOT" "checksums.txt"
    recheck_snapshot "$WORK/${CHECKSUMS_NAME}.minisig" "$SIG_SNAPSHOT" "checksums.txt.minisig"

    for pubkey_b64 in "${REQUIRED_KEYS[@]}"; do
        if "$MINISIGN_BIN" -V -P "$pubkey_b64" \
             -m "$WORK/${CHECKSUMS_NAME}" \
             -x "$WORK/${CHECKSUMS_NAME}.minisig" >/dev/null 2>&1; then
            verified=true
            matched_key="$pubkey_b64"
            matched_role="required"
            break
        fi
    done

    if [ "$verified" != "true" ] && [ "${#LEGACY_KEYS[@]}" -gt 0 ]; then
        for pubkey_b64 in "${LEGACY_KEYS[@]}"; do
            if "$MINISIGN_BIN" -V -P "$pubkey_b64" \
                 -m "$WORK/${CHECKSUMS_NAME}" \
                 -x "$WORK/${CHECKSUMS_NAME}.minisig" >/dev/null 2>&1; then
                verified=true
                matched_key="$pubkey_b64"
                matched_role="legacy"
                break
            fi
        done
    fi

    if [ "$verified" != "true" ]; then
        echo "::error::checksums.txt failed signature verification against all trusted keys" >&2
        exit 2
    fi

    echo "::notice::checksums.txt verified against key ${matched_key:0:16}... (role: $matched_role)"

    # Verify tarball SHA-256 matches checksums.txt entry.
    recheck_snapshot "$WORK/${CHECKSUMS_NAME}" "$CHECKSUMS_SNAPSHOT" "checksums.txt"

    expected_sha=$(awk -v t="${TARBALL_NAME}" '$2 == t { print $1 }' "$WORK/${CHECKSUMS_NAME}")
    if [ -z "$expected_sha" ]; then
        echo "::error::no checksum entry for ${TARBALL_NAME} in checksums.txt" >&2
        exit 2
    fi

    actual_sha=$(sha256 "$WORK/${TARBALL_NAME}") || {
        echo "::error::sha256 of tarball failed" >&2
        exit 2
    }
    if [ "$actual_sha" != "$expected_sha" ]; then
        echo "::error::tarball SHA-256 mismatch (expected $expected_sha, got $actual_sha)" >&2
        exit 2
    fi

    # Final tarball recheck IMMEDIATELY before extraction (R5-T4-HIGH-1).
    recheck_snapshot "$WORK/${TARBALL_NAME}" "$TARBALL_SNAPSHOT" "tarball"

    if ! tar -xzf "$WORK/${TARBALL_NAME}" -C "$WORK" ov; then
        echo "::error::tar extract failed for ${TARBALL_NAME}" >&2
        exit 2
    fi
    if [ ! -f "$WORK/ov" ]; then
        echo "::error::ov binary not found in tarball" >&2
        exit 2
    fi
    chmod 0500 "$WORK/ov"
fi

# ============================================================================
# Snapshot ov binary for post-extract swap detection (R3-H1).
# ============================================================================
SNAPSHOT="$(stat_inode_mtime_size "$WORK/ov")"

# ============================================================================
# Version probe + version-bound enforcement (R5-B5-IMPL-3/4 corrected).
# ============================================================================
OV_BIN="$WORK/ov"

probe_err=$(mktemp "$WORK/probe-err.XXXXXX")
ver_text=$("${OV_TIMEOUT[@]}" 10 "$OV_BIN" --version 2>"$probe_err") || {
    rc=$?
    echo "::error::ov --version failed (exit $rc); stderr: $(head -c 4096 "$probe_err")" >&2
    exit 2
}
if [ -s "$probe_err" ]; then
    echo "::notice::ov --version wrote to stderr: $(cat "$probe_err")"
fi
if [[ "$ver_text" != "ov version "* ]]; then
    echo "::error::ov --version output unexpected: $ver_text" >&2
    exit 2
fi

# R5-T2-HIGH-1 unconditional floor: extracted binary's self-reported
# version must be >= action's embedded OV_VERSION.
if ! "${OV_TIMEOUT[@]}" 10 "$OV_BIN" --check-version-bounds --min-ov-version "$OV_VERSION"; then
    echo "::error::ov binary version below action's pinned OV_VERSION=$OV_VERSION - possible stale-release replay" >&2
    exit 2
fi

# Customer-supplied bounds (optional, only TIGHTEN beyond the action floor).
if [ -n "$INPUT_MIN_OV_VERSION" ] || [ -n "$INPUT_MAX_OV_VERSION" ]; then
    cust_args=( --check-version-bounds )
    if [ -n "$INPUT_MIN_OV_VERSION" ]; then
        cust_args+=( --min-ov-version "$INPUT_MIN_OV_VERSION" )
    fi
    if [ -n "$INPUT_MAX_OV_VERSION" ]; then
        cust_args+=( --max-ov-version "$INPUT_MAX_OV_VERSION" )
    fi
    if ! "${OV_TIMEOUT[@]}" 10 "$OV_BIN" "${cust_args[@]}"; then
        echo "::error::ov binary version outside customer-specified [${INPUT_MIN_OV_VERSION:-any}, ${INPUT_MAX_OV_VERSION:-any}]" >&2
        exit 2
    fi
fi

# ============================================================================
# Pre-exec swap recheck (R3-H1).
# ============================================================================
if [ "$(stat_inode_mtime_size "$OV_BIN")" != "$SNAPSHOT" ]; then
    echo "::error::ov binary changed between verify and exec" >&2
    exit 2
fi

# ============================================================================
# Final composed invocation (R3-M1).
# ulimit applies to subshell; exec env -i replaces subshell with cmd.
# ============================================================================
WALL_S="${INPUT_TIME_BUDGET:-300}"
MEM_KB="${INPUT_MEMORY_BUDGET:-4194304}"

SCAN_OUT="$WORK/scan-output.json"

# In test mode, forward MOCK_OV_DUMP_ENV (used by the contract-test ov mock)
# and OV_TEST_CAPTURE_OUT through the env-i barrier so the harness can
# inspect exec-time behavior. These are test-only knobs.
TEST_FORWARD=()
if [ "$TEST_MODE" = "true" ]; then
    if [ -n "${MOCK_OV_DUMP_ENV:-}" ]; then
        TEST_FORWARD+=( "MOCK_OV_DUMP_ENV=$MOCK_OV_DUMP_ENV" )
    fi
    if [ -n "${OV_TEST_CAPTURE_OUT:-}" ]; then
        TEST_FORWARD+=( "OV_TEST_CAPTURE_OUT=$OV_TEST_CAPTURE_OUT" )
    fi
    if [ -n "${TEST_TMP:-}" ]; then
        TEST_FORWARD+=( "TEST_TMP=$TEST_TMP" )
    fi
fi

# Conditional --baseline flag: only pass when customer set the input.
# Empty default would otherwise tell ov scan "open file '' as baseline"
# which fails on first-time integration. Smoke caught this 2026-05-06.
BASELINE_ARGS=()
if [ -n "$INPUT_BASELINE_FILE" ]; then
    BASELINE_ARGS=(--baseline "$INPUT_BASELINE_FILE")
fi

set +e
(
    ulimit -v "$MEM_KB" 2>/dev/null || true  # macOS no-op silently
    exec env -i \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        HOME="${HOME:-}" \
        RUNNER_TEMP="$RUNNER_TEMP" \
        GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-}" \
        GITHUB_OUTPUT="$GITHUB_OUTPUT" \
        OV_INPUT_PATH="$INPUT_PATH" \
        OV_INPUT_BASELINE="$INPUT_BASELINE_FILE" \
        OV_INPUT_FAIL_ON="$INPUT_FAIL_ON" \
        ${TEST_FORWARD[@]+"${TEST_FORWARD[@]}"} \
        "${OV_TIMEOUT[@]}" "$WALL_S" "$OV_BIN" scan "$INPUT_PATH" \
            ${BASELINE_ARGS[@]+"${BASELINE_ARGS[@]}"} \
            --fail-on "$INPUT_FAIL_ON" \
            --format json > "$SCAN_OUT"
)
SCAN_RC=$?
set -e

# ============================================================================
# Output emission (R3-H8 + R4-B5/B6 + R5-B5-IMPL-1 fail-closed parsing).
#
# CRITICAL: never default missing/malformed fields to 0. A scanner crash,
# OOM-kill, or timeout truncates $SCAN_OUT mid-write; defaulting to 0
# would produce a false "0 findings" output and silently defeat the
# entire purpose of the action. Fail closed on any parse failure.
# ============================================================================
if [ ! -s "$SCAN_OUT" ]; then
    echo "::error::ov scan exited $SCAN_RC and wrote no output (likely killed/OOM/timeout)" >&2
    exit 2
fi

if ! jq -e . "$SCAN_OUT" >/dev/null 2>&1; then
    echo "::error::scan output is not parseable JSON (scan exit was $SCAN_RC)" >&2
    exit 2
fi

# R6-IMPL-2: explicit array-existence check BEFORE counting.
if ! jq -e '.findings | type == "array"' "$SCAN_OUT" >/dev/null 2>&1; then
    echo "::error::scan output missing or non-array .findings field - possible scanner crash mid-write" >&2
    exit 2
fi

parse_jq() {
    local expr="$1"
    local val
    val=$(jq -r "$expr" "$SCAN_OUT" 2>/dev/null) || return 1
    if [ -z "$val" ] || [ "$val" = "null" ]; then
        return 1
    fi
    printf '%s' "$val"
}

findings=$(parse_jq '.findings | length') || {
    echo "::error::scan output: cannot derive findings count from .findings" >&2
    exit 2
}

baselined=$(parse_jq '[.findings[] | select(.baselined == true)] | length') || baselined=0
verified_count=$(parse_jq '[.findings[] | select(.verified == true)] | length') || verified_count=0

INTEGER_RE='^(0|[1-9][0-9]{0,9})$'
if ! [[ "$findings" =~ $INTEGER_RE ]]; then
    echo "::error::malformed findings count: $findings" >&2
    exit 2
fi
if ! [[ "$baselined" =~ $INTEGER_RE ]]; then
    echo "::error::malformed baselined count: $baselined" >&2
    exit 2
fi
if ! [[ "$verified_count" =~ $INTEGER_RE ]]; then
    echo "::error::malformed verified count: $verified_count" >&2
    exit 2
fi

{
    echo "findings-count=$findings"
    echo "baselined-count=$baselined"
    echo "verified-count=$verified_count"
} >> "$GITHUB_OUTPUT"

# Derive fail-on disposition. ov scan itself exits non-zero on threshold
# breach, but tests use a mock that always exits 0 - so the action computes
# the disposition from the findings array as a defense-in-depth check.
# Severity ordering (highest first): verified > critical > high > medium >
# low > info. A finding at-or-above the threshold (and not baselined)
# produces a non-zero exit.
severity_rank() {
    case "$1" in
        verified) echo 6 ;;
        critical) echo 5 ;;
        high)     echo 4 ;;
        medium)   echo 3 ;;
        low)      echo 2 ;;
        info)     echo 1 ;;
        *)        echo 0 ;;
    esac
}

THRESHOLD_RANK=$(severity_rank "$INPUT_FAIL_ON")
breach=0
if [ "$findings" -gt 0 ]; then
    # Iterate findings; mark breach if any unbaselined finding's severity
    # rank >= threshold rank.
    while IFS=$'\t' read -r sev baselined_field; do
        [ -z "$sev" ] && continue
        if [ "$baselined_field" = "true" ]; then
            continue
        fi
        sev_rank=$(severity_rank "$sev")
        if [ "$sev_rank" -ge "$THRESHOLD_RANK" ] && [ "$sev_rank" -gt 0 ]; then
            breach=1
            break
        fi
    done < <(jq -r '.findings[] | [(.severity // "info"), (.baselined // false | tostring)] | @tsv' "$SCAN_OUT" 2>/dev/null)
fi

if [ "$SCAN_RC" -ne 0 ]; then
    exit "$SCAN_RC"
fi

if [ "$breach" -ne 0 ]; then
    exit 1
fi

exit 0
