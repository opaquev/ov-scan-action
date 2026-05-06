# Security Policy

## Reporting a vulnerability

Please send vulnerability reports to **security@opaquevault.com** with the subject `ov-scan-action: <one-line summary>`. Encrypt sensitive details with [our PGP key](https://opaquevault.com/.well-known/security.txt) when possible.

We commit to:
- Acknowledging receipt within **2 business days**.
- Triaging severity and providing an initial response within **5 business days**.
- Crediting reporters in the release notes (or anonymously, if preferred).

## Coordinated-disclosure timeline

| Day | Action |
|---|---|
| 0 | You report a vulnerability via the channels above. |
| ≤2 business | We acknowledge receipt. |
| ≤5 business | Initial triage; severity assessment; preliminary mitigation plan. |
| 30 (default) | Patch available, advisory published, reporter credited. |
| Up to 90 | Maximum embargo for complex / cross-system vulnerabilities. |

We negotiate the public-disclosure date with the reporter for issues that require coordinated patching with downstream consumers.

## Supported versions

| Version | Support status |
|---|---|
| `v1.0+` | ✅ active support |
| pre-v1 / scaffold tags | ❌ not supported (use latest `v1.x`) |

## Trust model

The action verifies downloaded `ov` binaries via [minisign](https://github.com/jedisct1/minisign) against the bundled `trusted-keys.txt` file. **You must pin to a commit SHA** in production:

```yaml
uses: opaquev/ov-scan-action@<40-char-sha>
```

A `@v1` tag is informational only — pinning to it means a maintainer compromise lands in your CI on the next run. Pin to SHA + use Dependabot's `actions` ecosystem for reviewable bumps.

The full threat model is documented in [`docs/threat-model.md`](docs/threat-model.md). Key points:

1. **Vendored minisign** — the verifier binary is committed to the action repo with hash-pinned SHA-256 literals in `entrypoint.sh`. No runtime `go install`, no third-party action proxies.
2. **`releases.opaquevault.com` operationally disjoint from `api.opaquevault.com`** — the binary CDN cannot correlate with API traffic.
3. **Same-UID swap defense** — `(inode, mtime, size)` stat-snapshot + recheck before every consumer use of every trust-root file.
4. **`exec env -i` env-strip** — `ov scan` is launched with a clean environment; `GITHUB_TOKEN`, `*_KEY`, `*_SECRET`, `LD_PRELOAD`, etc. are stripped.

## Key rotation

When OV rotates the release-signing key (`F89BAB08772C1C0B`), we publish a [GitHub Security Advisory](https://github.com/opaquev/ov-scan-action/security/advisories) with the SHA bump you need. The full rotation procedure is documented in [`docs/runbooks/release-key-rotation.md`](docs/runbooks/release-key-rotation.md). Old keys remain in `trusted-keys.txt` as `legacy` for a documented grace window before being removed.

## Threat model (key defenses)

The action runs `ov scan` against attacker-controlled PR contents (the standard `pull_request` context). The defenses are layered:

1. **Refuse `pull_request_target`** by default — exfiltration prevention. See README "Pull-request-target hardening" for the dangerous combo to avoid.
2. **Fork-PR strict mode** — clobbers `allow-binary-version`, `allow-ci-baseline`, `max-ov-version` overrides on fork-PR runs (non-overridable).
3. **Wallclock + memory budgets** on the `ov scan` invocation — defense against parser-DoS PRs.
4. **Signature verification** of the binary before exec — anti-supply-chain.
5. **Stale-checksums replay defense** — unconditional version-floor check against the action's embedded `OV_VERSION` runs BEFORE customer-supplied bounds; an attacker who replays a genuinely-signed older release fails the floor.
6. **Symlink rejection** at `$GITHUB_ACTION_PATH/trusted-keys.txt`, `vendor/minisign-*`, and every downloaded file in `$WORK/`.
7. **Fail-closed JSON parsing** — `findings-count=0` is NEVER emitted on a parse failure; `jq -e '.findings | type == "array"'` runs before counting.

Full threat-model documentation: [`docs/threat-model.md`](docs/threat-model.md).

## Pre-implementation review history

This action shipped after **6 rounds** of pre-implementation security review across 3 lenses (ZK invariants, threat model, implementation risk). 35+ findings were identified and patched before any code shipped. The history is preserved in the upstream OV-239 plan doc for audit.

## TEST_MODE

The action's `entrypoint.sh` includes a `TEST_MODE` branch for the bats test harness. It is gated on **both** `$TEST_TMP` AND `$OV_TEST_MODE=1`. Customer workflows cannot trigger it inadvertently because `OV_TEST_MODE` is not in `action.yml`'s input list. If TEST_MODE ever fires in production CI, the action emits a loud `::warning::` to the workflow log — **report any sighting of that warning as a security issue.**
