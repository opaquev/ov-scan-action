# Changelog

All notable changes to `opaquev/ov-scan-action` will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.1] — Unreleased

### Fixed
- **First-time integration UX**: `baseline-file` default changed from
  `.ovscan-baseline.txt` to empty string. Previously, customers
  dropping the action into a repo that had no baseline file got an
  error from `ov scan`: `loading baseline: open .ovscan-baseline.txt:
  no such file or directory`. The action now passes `--baseline` to
  `ov scan` only when the customer explicitly sets the input.
  Caught by [`opaquev/ov-scan-action-integration-test`](https://github.com/opaquev/ov-scan-action-integration-test)
  smoke on its very first run after v1.0.0 shipped — exactly the
  failure mode that test was designed to catch.

### Added
- Health badge on the README pointing at the smoke-test repo. **If
  the badge is red, the action is broken — do not integrate it
  until smoke is green.**

## [v1.0.0] — 2026-05-06

The first stable release of `ov-scan-action`. After 6 rounds of
pre-implementation security review (35+ findings patched before any
code shipped), v1 is what customers should pin to.

### Added
- Composite GitHub Action (`action.yml`) with 10 inputs and 3 outputs
- `entrypoint.sh` (~743 lines) with all 18 sections of the security plan implemented:
  - Required GitHub Actions context guards (§1)
  - Dangerous-env strip (LD_PRELOAD / BASH_ENV / PROMPT_COMMAND etc) (§2)
  - Portability shims for macOS bash 3.2 + BSD coreutils (§3)
  - Required-tool presence checks (jq) (§4)
  - Embedded version + hash literals (§5)
  - Architecture matrix with explicit darwin_amd64 refusal (§6)
  - Workdir setup with init-guarded trap (EXIT/INT/TERM/HUP) (§7)
  - Symlink defense at trust-root paths (§8)
  - SHA-256 self-check + copy-into-WORK + re-hash + stat snapshot (§9)
  - Fork-PR detection via `$GITHUB_EVENT_PATH` JSON (includes `pull_request_target`) (§10)
  - Fork-PR strict-mode CLOBBER (non-overridable) (§11)
  - `pull_request_target` gate (§12)
  - Input validation + path-traversal-rejection + budget regex (§13)
  - Download + checksums-sig verification + tarball SHA + tar extraction (§14)
  - Version probe + flag-form `--check-version-bounds` + unconditional version floor (§15)
  - Pre-exec snapshot recheck (§16)
  - Final composed invocation: `( ulimit -v ; exec env -i ... timeout ... ov scan ... )` (§17)
  - Output emission with fail-closed JSON parsing + INTEGER_RE (§18)
- Vendored minisign 0.12 binaries (linux_amd64, linux_arm64, darwin_arm64) verified against jedisct1's signing key
- `trusted-keys.txt` with single Ed25519 required key (`F89BAB08772C1C0B`)
- 3 CI workflows: `test.yml` (bats matrix + shellcheck), `ci.yml` (yamllint + structural guards), `release-gate.yml` (refuses v1* tag without fresh runbook drill)
- 75 bats test contracts (45 named + 4 structural with sub-case expansion)
- `docs/runbooks/release-key-rotation.md` (with `last_drilled` frontmatter)
- `docs/threat-model.md` (4-tier threat model)
- `tests/run-locally.sh` helper for contributor local-testing
- README + SECURITY policy with pwn-request warning, SHA-pinning gospel, supported-runner matrix

### Security
- Vendored minisign verifier prevents `go install`/CDN-trust attacks
- Same-UID swap defense via stat-snapshot recheck across all trust-root files
- Stale-checksums replay defeated by unconditional version floor
- `exec env -i` strips `GITHUB_TOKEN`/`*_KEY`/`*_SECRET` before scanner invocation
- Fork-PR strict mode is non-overridable (clobber happens before input read)
- Symlink rejection at every trust-root path
- TEST_MODE requires both `$TEST_TMP` AND `$OV_TEST_MODE=1` co-token + emits `::warning::` if it fires

### Not yet supported
- Windows runners (tracked: [OV-245](https://linear.app/thehunterfoundry/issue/OV-245))
- darwin_amd64 (Intel macOS) — jedisct1's macOS minisign release is arm64-only; macos-13 is deprecated by GitHub. Use macos-14+ runners.
- `revoked-versions.txt` (CVE'd-but-still-signed binary defense, tracked: [OV-246](https://linear.app/thehunterfoundry/issue/OV-246))
