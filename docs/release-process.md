# Release process

This document captures the procedure for cutting a new versioned release of `opaquev/ov-scan-action`. Read this **before** tagging a new `v1.x` (or any future major version).

## Pre-tag verification (every release)

Run from the repo root on the release-prep branch:

```bash
# 1. Trust-root literals match their bytes
echo "$(grep -E '^readonly TRUSTED_KEYS_SHA256' entrypoint.sh)"
shasum -a 256 trusted-keys.txt

# 2. Vendor binary literals match their bytes
cat vendor/SHA256SUMS
grep -E '^readonly MINISIGN_BIN_SHA256_' entrypoint.sh

# 3. CI workflows pass locally
python3 -m yamllint .
shellcheck --severity=warning entrypoint.sh tests/*.bash tests/*.sh
bats tests/

# 4. Runbook drill is fresh (release-gate.yml refuses tags > 90d)
python3 -c '
import re
from datetime import datetime, timezone, timedelta
text = open("docs/runbooks/release-key-rotation.md").read()
fm = re.match(r"^---\n(.*?)\n---", text, re.DOTALL).group(1)
raw = re.search(r"^last_drilled:\s*(\S+)", fm, re.MULTILINE).group(1).strip()
if raw.endswith("Z"): raw = raw[:-1] + "+00:00"
drilled = datetime.fromisoformat(raw)
age = datetime.now(timezone.utc) - drilled
print(f"last_drilled={drilled.isoformat()} age={age.days}d gate={"PASS" if age <= timedelta(days=90) else "FAIL"}")
'
```

Every step must report green. If any fails, do **not** tag — fix and re-verify.

## Tag procedure (v1.0.0 specific; reuse for v1.x.y bumps)

1. **Dispatch the release-gate workflow** (must run on `main` after the release-prep PR merges):
   ```bash
   gh workflow run release-gate.yml \
     --repo opaquev/ov-scan-action \
     --ref main \
     -f proposed-tag=v1.0.0
   ```
   Watch the run; expect `green`. If the gate refuses (typically because the runbook drill date is > 90 days old), update `docs/runbooks/release-key-rotation.md` with a fresh `last_drilled` timestamp and reopen this step.

2. **Create the annotated tag** locally:
   ```bash
   git checkout main && git pull --ff-only
   git tag -s v1.0.0 -m "ov-scan-action v1.0.0

   First stable release. See CHANGELOG.md for the full surface.
   "
   git push origin v1.0.0
   ```
   Use `-s` (signed tag) only if you have a configured GPG/minisign key for git tag signing; otherwise use `-a` (annotated, unsigned).

3. **Create the GitHub Release** from the tag:
   ```bash
   gh release create v1.0.0 \
     --repo opaquev/ov-scan-action \
     --title "v1.0.0" \
     --notes-file CHANGELOG.md \
     --verify-tag
   ```
   The `--verify-tag` flag refuses to create a release for an unpushed tag, providing a small consistency check.

4. **Verify the release surface** by running the action against itself in a test workflow:
   - Open a PR against this repo (any small docs change).
   - The CI workflow `test.yml` already runs `bats tests/` — confirm 75/75 still pass.
   - To smoke-test the composite-action surface (`uses: opaquev/ov-scan-action@v1.0.0`), open a PR in a separate test repo (or one of OV's downstream consumers) using the new tag.

## What changes in entrypoint.sh between releases?

Per the supply-chain trust model, **only these literals should change** between minor/patch releases:

| Literal | When to bump |
|---|---|
| `OV_VERSION` | When OV ships a new compatible release (e.g., `v0.10.1`, `v0.11.0`). Read [`ov` semver compatibility notes](https://github.com/huntrock17/opaquevault/blob/main/docs/VERSIONING.md) before bumping. |
| `MINISIGN_VERSION` | Only on numbered `jedisct1/minisign` releases. See `vendor/README.md` "Update procedure". |
| `TRUSTED_KEYS_SHA256` | Whenever `trusted-keys.txt` is edited (e.g., adding a new `legacy` key during rotation). Recompute via `shasum -a 256 trusted-keys.txt`. |
| `MINISIGN_BIN_SHA256_*` | Whenever vendor minisign is bumped. Recompute via `shasum -a 256 vendor/minisign-${VER}-${TARGET}`. Update both `vendor/SHA256SUMS` and the `entrypoint.sh` literals in the same PR. |

Any change to `entrypoint.sh` beyond these literals is a **logic change** and requires going through the full canonical loop again (3-lens pre-review + Devin + senior SWE). Trust me — the [6-round pre-review log](https://github.com/huntrock17/opaquevault/blob/main/docs/superpowers/plans/2026-05-05-ov-scan-action-v1-impl.md) on v1.0.0 is what it looks like when the discipline pays off.

## Tag-mutability policy

`v1` (major-only) is informational. **Customers who pin to `@v1` opt into trusting maintainer rotation.** Production users SHOULD pin to `@<40-char-sha>` per the README's SHA-pinning guidance.

`v1.x.y` (full semver) is immutable. We do not force-push tags. If a tag needs to be retracted (security issue), publish a `v1.x.y+1` and a [GitHub Security Advisory](https://github.com/opaquev/ov-scan-action/security/advisories) with the upgrade path.

## CHANGELOG hygiene

Every PR that lands on `main` should add or update a section in `CHANGELOG.md`. The release-prep PR moves the `Unreleased` heading to a versioned heading and adds a fresh `Unreleased` section above it.

## Deferred for v1.x

- **Sigstore / cosign migration** — wait for `sigstore/fulcio` ML-DSA tooling to stabilize. Tracking informally; no ticket yet.
- **Windows runner support** — [OV-245](https://linear.app/thehunterfoundry/issue/OV-245).
- **`revoked-versions.txt`** — defense against CVE'd-but-still-signed older binaries. [OV-246](https://linear.app/thehunterfoundry/issue/OV-246).

## Cross-references

- [`README.md`](../README.md) — customer-facing usage docs
- [`SECURITY.md`](../SECURITY.md) — vulnerability reporting + threat model
- [`docs/threat-model.md`](threat-model.md) — full 4-tier threat analysis
- [`docs/runbooks/release-key-rotation.md`](runbooks/release-key-rotation.md) — Ed25519 key rotation
- [`vendor/README.md`](../vendor/README.md) — minisign vendor procedure
- [`CHANGELOG.md`](../CHANGELOG.md) — release history
