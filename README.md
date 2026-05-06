# `opaquev/ov-scan-action`

[![smoke](https://github.com/opaquev/ov-scan-action-integration-test/actions/workflows/smoke.yml/badge.svg?branch=main)](https://github.com/opaquev/ov-scan-action-integration-test/actions/workflows/smoke.yml)

GitHub Action that runs [`ov scan`](https://opaquevault.com/docs/scan) on your repository to find leaked secrets in the working tree and (optionally) in git history.

> **Status: v1.0.0 shipped.** Implementation lives in this repo; security model + 6-round pre-review history is documented under [`docs/threat-model.md`](docs/threat-model.md) and the upstream OV-239 plan doc.

> **Health**: the badge above is the live status of the [`opaquev/ov-scan-action-integration-test`](https://github.com/opaquev/ov-scan-action-integration-test) smoke suite — runs daily against the published `@v1` tag AND the immutable `v1.0.0` SHA pin on `ubuntu-latest`, `ubuntu-24.04-arm`, and `macos-latest`. **If that badge is red, do not integrate this action until smoke is green again.**

## Why a separate action?

`ov scan` is the same secret-detection engine that protects every OpaqueVault MCP tool result at runtime — same rules, same false-positive tuning, same engine. Running it in CI means a credential that would have been redacted at runtime is also caught at PR time, before it reaches a server.

The action is a thin wrapper: it downloads a signed `ov` binary, verifies the signature against a vendored minisign + bundled trusted-keys file, and runs `ov scan` against the repository checkout. **No data leaves the runner unless the user explicitly opts in to vendor-API live verification (`--verify`) or rotation (`--fix --rotate`).**

## Quickstart

```yaml
# .github/workflows/secret-scan.yml
name: secret-scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: opaquev/ov-scan-action@<40-char-sha>  # see "Pin to SHA" below
        with:
          path: .
          fail-on: high
```

For the `<40-char-sha>` pin value, copy the latest commit SHA from the [opaquev/ov-scan-action releases](https://github.com/opaquev/ov-scan-action/releases) page.

### All inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to scan (relative to repo root). Allowlist regex; no `..` segments, no absolute paths. |
| `baseline-file` | `''` | Path to baseline file with HMAC-fingerprinted accepted findings. Empty = no baseline (the default for first-time integration). |
| `fail-on` | `high` | Severity threshold: `verified\|critical\|high\|medium\|low\|info`. |
| `min-ov-version` | `''` | Minimum ov binary version (e.g., `v0.10.0`). Customer floor; cannot loosen the action's embedded `OV_VERSION` floor. |
| `max-ov-version` | `''` | Maximum ov binary version. |
| `allow-pull-request-target` | `false` | **DANGEROUS** — see "Pull-request-target hardening" below. |
| `allow-binary-version` | `false` | Override binary version (refused on fork PRs). |
| `allow-ci-baseline` | `false` | Allow baseline modifications in CI (refused on fork PRs). |
| `time-budget` | `300` | Wallclock seconds for `ov scan` invocation. |
| `memory-budget` | `1048576` | Memory budget in KB (Linux only; macOS no-op per `ulimit -v` semantics). |

### Outputs

| Output | Description |
|---|---|
| `findings-count` | Total number of findings (includes baselined; subtract `baselined-count` for unbaselined-only). |
| `baselined-count` | Number of findings suppressed by baseline. |
| `verified-count` | Number of findings whose liveness was verified. |

## Supported runners

| Runner | Status | Notes |
|---|---|---|
| `ubuntu-latest` (linux_amd64) | ✅ supported | |
| Linux ARM64 (linux_arm64) | ✅ supported | self-hosted ARM runners |
| `macos-latest` / macos-14+ (darwin_arm64) | ✅ supported | |
| `macos-13` (darwin_amd64, Intel) | ❌ **not supported** | jedisct1's signed minisign 0.12 macOS release is arm64-only Mach-O; we don't ship a self-built darwin_amd64 binary because it would weaken the supply-chain trust chain. macOS 13 is deprecated by GitHub anyway; migrate to `macos-14+` (arm64). |
| `windows-latest` | ❌ not yet | tracked under [OV-245](https://linear.app/thehunterfoundry/issue/OV-245). |

## ⚠️ Security model

### Pin to SHA, not tag

Production users **must** pin to a commit SHA: `uses: opaquev/ov-scan-action@<40-char-sha>`.

The `@v1` tag is informational only — pinning to a tag means a maintainer (or a compromise of the action repo) can ship a malicious update that you consume on the next CI run. SHA pinning + Dependabot's `actions` ecosystem gives you reviewable, auditable bumps.

### Pull-request-target hardening (the "pwn-request" trap)

By default the action **refuses** to run under [`pull_request_target`](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target). This is the most dangerous workflow trigger in GitHub Actions: it runs in the **base repo's context** with **base-repo secrets**, but a malicious PR author can influence what the workflow does.

The combination most users get wrong:

```yaml
# ❌ DON'T DO THIS — CVE-class misconfiguration
on: pull_request_target
jobs:
  scan:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # ← attacker-controlled checkout
      - uses: opaquev/ov-scan-action@<sha>
        with:
          allow-pull-request-target: true                  # ← unlocks the gate
```

If you set `allow-pull-request-target: true` AND check out the PR head ref, you've created a fork-PR-controlled execution path with access to your base-repo `GITHUB_TOKEN`. A malicious PR's hooks/scripts/dependencies can exfiltrate the token. See [the GitHub Security Lab "pwn requests" writeup](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).

The action emits a `::warning::` whenever `allow-pull-request-target=true` is honored. **If you see that warning, double-check your `actions/checkout` step.**

### Fork-PR strict mode

When the action detects a fork PR (via `$GITHUB_EVENT_PATH` JSON), it **clobbers** all `allow-*` inputs to false BEFORE reading them. This is non-overridable: a fork PR cannot use `allow-binary-version`, `allow-ci-baseline`, or `max-ov-version` regardless of what the workflow YAML says.

### Vendored minisign + hash-pinned trust roots

The action vendors minisign 0.12 binaries for all 3 supported targets, each verified at vendor-time against [jedisct1's well-known minisign public key](https://github.com/jedisct1/minisign) (`RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3`, fingerprint `16839B40E54CDB8B`). At runtime, `entrypoint.sh` re-verifies SHA-256 against literal hashes embedded in the script.

The `trusted-keys.txt` file (which lists the Ed25519 keys minisign accepts for `ov` release artifacts) is also hash-pinned. Same-UID swap defenses apply: copy-into-WORK + re-hash + stat-snapshot recheck before each consumer use.

### Key rotation

When OV rotates the release-signing key (`F89BAB08772C1C0B`), we publish a [GitHub Security Advisory](https://github.com/opaquev/ov-scan-action/security/advisories) with the SHA bump customers need. The procedure is documented in [`docs/runbooks/release-key-rotation.md`](docs/runbooks/release-key-rotation.md). See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model.

## Local testing

Run the bats test suite locally to verify the action against your changes:

```bash
git clone https://github.com/opaquev/ov-scan-action.git
cd ov-scan-action
bats tests/                                    # 75/75 expected pass on Linux + macos-arm64
```

For testing the action against a real workflow without going through `gh actions`, use [`act`](https://github.com/nektos/act) — but `act` doesn't set every `$GITHUB_*` env var the action requires. Use the included helper:

```bash
./tests/run-locally.sh                         # wraps act + sets required env vars
```

The helper sets sensible defaults for `GITHUB_EVENT_NAME`, `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`, `GITHUB_ACTION_PATH`, `RUNNER_TEMP`, `RUNNER_OS`, `GITHUB_WORKSPACE`, `GITHUB_OUTPUT` so contributors can repro test failures locally without learning all of `act`'s flags.

## Roadmap

- **v1.0** — Linux + macOS arm64. (This release.)
- **Post-v1** — Windows runner support ([OV-245](https://linear.app/thehunterfoundry/issue/OV-245)).
- **Post-v1** — `revoked-versions.txt` for CVE'd-but-still-signed binary defense ([OV-246](https://linear.app/thehunterfoundry/issue/OV-246)).
- **Post-1.0 (deferred)** — PQC migration when sigstore/fulcio ML-DSA tooling stabilizes.

## Links

- Main repo: https://github.com/huntrock17/opaquevault
- Docs: https://opaquevault.com/docs
- `ov scan` v1 design: [`docs/superpowers/specs/2026-05-02-ov-scan-v1-design.md`](https://github.com/huntrock17/opaquevault/blob/main/docs/superpowers/specs/2026-05-02-ov-scan-v1-design.md)
- Plan + 6-round pre-review history: [`docs/superpowers/plans/2026-05-05-ov-scan-action-v1-impl.md`](https://github.com/huntrock17/opaquevault/blob/main/docs/superpowers/plans/2026-05-05-ov-scan-action-v1-impl.md)

## License

MIT (see [LICENSE](LICENSE)).
