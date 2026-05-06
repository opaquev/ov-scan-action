# ov-scan-action — Threat Model

This document captures the security posture of `opaquev/ov-scan-action`
across four threat tiers. The companion plan doc lives in the
opaquevault main repo at
`docs/superpowers/plans/2026-05-05-ov-scan-action-v1-impl.md`.

## Overview

The action is a composite GitHub Action that runs `ov scan` against a
customer's checkout in CI. It is the highest-trust-surface part of the
`ov scan v1` shipping plan: every customer using `@v1` depends on this
trust boundary, and a single defect can compromise every consumer
simultaneously.

The action's security posture rests on **four primary defenses**:

1. **Vendored minisign + hash-pinned trust roots.** No runtime
   `go install`, no apt pulling minisign, no third-party action proxy.
   The verifier binary, its SHA-256, and the trusted-keys file are
   all committed to the action repo and verified at runtime against
   embedded literal hashes in `entrypoint.sh`.
2. **`releases.opaquevault.com` operationally disjoint from
   `api.opaquevault.com`.** Different host, separate Cloudflare
   account/zone, separate retention policy (≤24h on origin,
   /24-truncated source IPs after 7 days, no User-Agent retention
   beyond aggregate counters).
3. **Same-UID swap defense via stat-snapshot recheck.** For every
   trust-root file (`trusted-keys.txt`, `minisign`, the downloaded
   tarball, checksums, signature, the extracted `ov` binary), the
   script captures `(inode, mtime, size)` once and rechecks before
   each consumer use. A same-UID prior step in the customer's CI
   that swaps the file between snapshot and use is detected and
   exits 2.
4. **`exec env -i` env-strip.** The `ov scan` invocation is launched
   with a clean environment containing only PATH, HOME, RUNNER_TEMP,
   GITHUB_WORKSPACE, GITHUB_OUTPUT, and `OV_INPUT_*`. `GITHUB_TOKEN`,
   `*_TOKEN`, `*_KEY`, `*_SECRET`, `LD_PRELOAD`, etc. are all stripped.

## Tier 1 — Curious server operator

The CDN serving the `ov` binary (`releases.opaquevault.com`) sees a
predictable per-run shape: 3 sequential curl GETs for tarball,
checksums, and signature, with `User-Agent: ov-scan-action/v1
(<target>)`. The operator can infer:

- Customer fleet size (count of distinct `/24` IPs hitting the v1
  binary path)
- Per-customer CI cadence (request burst frequency)
- Self-hosted-runner customer egress IPs (in the warm-log window)

What the operator CANNOT learn: customer repo contents, scan findings,
credential bytes, or anything from `api.opaquevault.com` (separate
trust domain).

The `--user-agent` is intentional truth-in-labeling — the operator
already knows action-vs-CLI from the URL path; explicit UA helps
post-incident forensics distinguish action traffic from CLI traffic
without revealing customer state.

**Mitigation**: ≤24h CF retention; /24-truncate after 7 days; no UA
aggregate retention. Documented in this file as the SLA.

## Tier 2 — Network attacker

A network attacker who can MITM the binary download cannot serve a
forged binary because:

1. The tarball SHA-256 must match an entry in the signed
   `checksums.txt`.
2. `checksums.txt` is signed by minisign with a key in
   `trusted-keys.txt`.
3. `trusted-keys.txt` is hash-pinned in `entrypoint.sh` via
   `TRUSTED_KEYS_SHA256`.
4. `entrypoint.sh` itself is content-pinned via the customer's
   `uses: opaquev/ov-scan-action@<40-char-sha>` SHA pin.

**Even a fully-compromised CDN cannot defeat this chain** — the
minisign signature requires `OV_RELEASE_PRIVATE_KEY` which is held
only on locked-down GitHub Actions secret storage on the OV main
repo.

**Stale-replay defense**: the unconditional version-floor check
(`--check-version-bounds --min-ov-version "$OV_VERSION"`) runs against
the action's embedded `OV_VERSION` literal **before** the
customer-supplied bounds. An attacker who replays a genuinely-signed
older release at the v0.10.0 URL fails the floor check.

## Tier 3 — Malicious AI / malicious PR

A malicious PR author could try to exfiltrate credentials via the
action's outputs / logs:

- **`$GITHUB_OUTPUT`**: only `findings-count`, `baselined-count`,
  `verified-count` (integers, regex-validated to `^(0|[1-9][0-9]{0,9})$`,
  no scientific notation, no leading zeros, no multi-line smuggle).
- **SARIF**: not emitted by this action surface (out of scope; `ov scan`
  has its own SARIF redaction discipline).
- **Workflow logs**: the action emits no finding bodies, no line
  context, no credential bytes. Only signature-verified key
  fingerprints (e.g., `RWQLHCx3CKub+D3W...`) and integer counts.
- **`$GITHUB_TOKEN`**: stripped via `exec env -i` before `ov scan`
  invocation.

**Pull-request-target hardening**: the action refuses to run under
`pull_request_target` unless the customer explicitly sets
`allow-pull-request-target: true` on the step. Even then, the
fork-PR strict-mode CLOBBER zeros out any allow-* inputs the workflow
might have set. Customers using the dangerous combo
(`pull_request_target` + `actions/checkout` with
`ref: ${{ github.event.pull_request.head.sha }}`) get a workflow
warning emitted by `entrypoint.sh`.

## Tier 4 — Compromised client / same-UID prior step

Same-UID prior steps in a customer's CI workflow are the canonical
TOCTOU adversary. The action defends with:

- **Symlink-rejection** at `$GITHUB_ACTION_PATH/trusted-keys.txt`,
  `$GITHUB_ACTION_PATH/vendor/minisign-*`, and every downloaded file
  (`$WORK/<tarball>`, `<checksums>`, `<.minisig>`).
- **Stat-snapshot tuple `(inode, mtime, size)`** is load-bearing — a
  same-UID attacker can forge mtime via `utimensat(2)` and pad bytes
  for size-collision, but cannot preserve inode while changing
  content. The only swap that preserves inode is truncate-in-place,
  which is detected by the size-mismatch the truncation creates.
- **`chmod 0700 "$WORK"`** restricts the work dir parent (defense in
  depth; the snapshot+recheck is the load-bearing defense).
- **`chmod 0500 "$OV_BIN"` BEFORE verify** prevents accidental
  corruption between download and verify. Same-UID attacker can still
  unlink+create, but the post-verify stat-snapshot catches it.

### Residual TOCTOU window

The `recheck_snapshot` helper narrows the same-UID swap window from
tens-of-milliseconds (between SHA hash and final consumer use) to
microseconds (between `stat` syscall and consumer's `open`). It does
NOT eliminate the race. A same-UID attacker with sub-microsecond
timing precision could still win.

For the action's stated threat model (same-UID prior step in
customer CI), microsecond-window narrowing combined with chmod
0400/0500 is adequate. Complete elimination would require loading
file content into memory before consumer use (`mmap` +
`MADV_DONTNEED`, or in-process binary load), which is incompatible
with the composite-action shell-script architecture.

If your threat model includes kernel-precision-timing same-UID
adversaries, do not use shell-based CI actions for trust-critical
code. Use a Docker-action-based isolation boundary or run on
single-job-per-VM ephemeral runners (GH-hosted runners are this by
default).

## TEST_MODE

The `entrypoint.sh` includes a TEST_MODE branch that bypasses
signature verification when BOTH `$TEST_TMP` AND `$OV_TEST_MODE=1` are
set. This branch fires only inside the bats test harness; customer
workflows cannot trigger it inadvertently because `OV_TEST_MODE` is
not in `action.yml`'s input list, and the helpers' `make_test_workspace`
is the only code that exports both vars together.

If TEST_MODE ever fires in production CI (e.g., via a malicious step
that exports both vars at job scope), the script emits a loud
`::warning::` to the workflow log so the bypass is visible. **If you
see that warning in a customer-facing workflow run, file a security
issue immediately.**

## Bootstrap / repo-governance posture

- `main` branch protection: required code-owner review (CODEOWNERS
  rule applies); no force-push; no deletion; required conversation
  resolution.
- CODEOWNERS: solo `@huntrock17` for v1. The 2-of-N defense normally
  provided by multiple human reviewers is delegated to the per-PR
  AI-reviewer loop (3-lens pre-review, post-review, Devin, senior
  SWE). Follow-up: add human co-reviewers post-launch.
- `.gitattributes`: `vendor/** binary` ensures Mach-O / ELF binaries
  are not silently corrupted by line-ending normalization.
- `release-gate.yml`: `workflow_dispatch`-only; refuses to greenlight
  a `v1*` tag unless `docs/runbooks/release-key-rotation.md` has a
  `last_drilled` frontmatter date < 90 days old.

## What this document does NOT cover

- The OV main repo's threat model (covered in `docs/architecture/README.md` §9 over there)
- The `ov scan` scanner's threat model (covered in the spec linked
  from the plan doc)
- Customer's own workflow security (their responsibility — but this
  action provides the strongest possible posture for the slice it
  controls)

## References

- Plan doc:
  `opaquevault/docs/superpowers/plans/2026-05-05-ov-scan-action-v1-impl.md`
- `vendor/README.md` — supply-chain trust procedure
- `docs/runbooks/release-key-rotation.md` — key rotation runbook
- 6 rounds of pre-review across 3 security lenses (ZK invariants,
  threat model, implementation risk) with 35+ findings patched
