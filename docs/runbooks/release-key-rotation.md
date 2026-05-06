---
last_drilled: 2026-05-06T00:00:00Z
---

# Release-Key Rotation Runbook

This runbook covers rotation of the OpaqueVault Ed25519 release-signing
key (`F89BAB08772C1C0B`, base64 form `RWQLHCx3CKub+D3Wnc1zX/YBVr1fJD5SrK08d2xp4XoTQipbFET8V0fU`)
that signs `ov` release artifacts. The action's `trusted-keys.txt`
hard-pins this key; rotation requires coordinated changes across the
OV main repo, the action repo, and every customer's `@v<sha>` pin.

## Required cadence

Per `release-gate.yml`, the `last_drilled` frontmatter date in this
file must be **less than 90 days old** for any `v1*` tag to be
greenlit. The release-gate workflow refuses to bless a tag if the
runbook drill is stale.

## When to rotate

| Trigger | Urgency | Action |
|---------|---------|--------|
| Suspected key compromise | EMERGENCY | Pause v1 tag movement; rotate within 72h |
| Scheduled cadence | annual | Walk through this runbook; update `last_drilled` |
| Custodian transition | within 30d of transition | Verify access, dual-control test |
| PQC migration ready | when sigstore/fulcio ML-DSA stable | Deferred (post-1.0) |

## Rotation procedure

### 1. Pre-rotation checklist

- [ ] OV main repo: `OV_RELEASE_PRIVATE_KEY` GitHub Actions secret is
  current (last verified: see `.claude-session-log/` or release pipeline
  audit log)
- [ ] OV main repo: `OV_RELEASE_PRIVATE_KEY_PASSWORD` is current
- [ ] Action repo: `trusted-keys.txt` contains exactly one `required` key
  matching the embedded `TRUSTED_KEYS_SHA256` literal in `entrypoint.sh`
- [ ] At least one prior signed release verifies cleanly using the
  current trust root (run `minisign -V -P "$current_pubkey" -m
  ov_<version>_checksums.txt -x ov_<version>_checksums.txt.minisig`)

### 2. Generate the new key

On the release-custodian's air-gapped or locked-down workstation:

```bash
# Generate a new minisign key pair. Choose a new key ID; note the hex
# fingerprint and the base64 public key form.
minisign -G -p new-release.pub -s new-release.key -W

# Copy the base64 public key (line 2 of new-release.pub) for use below.
# Copy the hex fingerprint (line 1 comment) for human-readable identity.
```

### 3. Multi-key handover (preferred; zero-downtime)

The `trusted-keys.txt` format supports `legacy` keys — the verifier
iterates `required` first, then any number of `legacy` entries. Plan a
**handover window** of at least one signed release where both keys are
trusted:

1. Add the new key to `trusted-keys.txt` as `required`, demote the old
   key to `legacy`:
   ```
   <new-pubkey-b64> required
   <old-pubkey-b64> legacy
   ```
2. Recompute `TRUSTED_KEYS_SHA256` (`shasum -a 256 trusted-keys.txt`)
   and update the embedded literal in `entrypoint.sh`.
3. Open a PR titled `chore: rotate release key (<old-fp> → <new-fp>)`.
4. After the PR merges and a new `v1*` tag is cut against the new key,
   monitor customer issue reports for at least 30 days.
5. After the legacy key has been dormant for 30+ days AND no customer
   issues report verification failures:
   - Open a follow-up PR removing the `legacy` entry from
     `trusted-keys.txt`.
   - Update `TRUSTED_KEYS_SHA256` again.
6. The custodian destroys the old private key (shred, then verify it
   no longer exists via `minisign -G -p old.pub` rejecting on
   nonexistent key).

### 4. Emergency-rotation path (no handover window)

If the old key is **suspected compromised**, skip the handover. The
defense is `revoked-versions.txt` (filed as OV-246 follow-up; not yet
shipped):

1. Pause `v1*` tag movement on the action repo (no new tags until
   rotation completes).
2. Generate the new key per step 2 above.
3. Open a PR replacing the `required` key directly:
   ```
   <new-pubkey-b64> required
   ```
4. Recompute `TRUSTED_KEYS_SHA256`; update the embedded literal.
5. Sign and tag a new `v1*` release with the new key.
6. **Publish a security advisory** (`gh repo edit --advisory`) listing
   affected versions and the customer-action required (re-pin to a
   new SHA).
7. **Notify customers** through every available channel: GitHub
   Security Advisory, project README banner, and direct outreach for
   any known integrators.
8. Customers MUST re-pin their `uses: opaquev/ov-scan-action@<sha>` to
   a SHA that includes the new `trusted-keys.txt` and rotated key.

### 5. Post-rotation verification

For each runner platform in the action's matrix
(`linux_amd64`, `linux_arm64`, `darwin_arm64`):

- [ ] Pull a fresh tarball from `releases.opaquevault.com/<new-version>/`
- [ ] Verify checksums.txt against the new public key:
  `vendor/minisign-0.12-<target> -V -P <new-pubkey-b64> -m
  ov_<ver>_checksums.txt -x ov_<ver>_checksums.txt.minisig`
- [ ] Run the action against `tests/fixtures/clean-repo/`; confirm
  `findings-count=0` propagates correctly through the composite
  outputs surface
- [ ] Run the action against `tests/fixtures/dirty-repo/`; confirm
  non-zero exit + non-zero `findings-count`

### 6. Drill update

Edit the frontmatter at the top of this file:

```yaml
---
last_drilled: <ISO-8601 timestamp of this drill>
---
```

Commit the date update in the SAME PR as the rotation work, so
`release-gate.yml` greenlights the post-rotation tag.

## Recovery: lost custodian access

If the OV release-custodian loses access to `OV_RELEASE_PRIVATE_KEY` /
`OV_RELEASE_PRIVATE_KEY_PASSWORD` and no backup exists:

1. Treat as compromise (the unknown access state is its own threat).
2. Follow the emergency-rotation path above.
3. Reset GitHub Actions secrets in the OV main repo with new key
   material.
4. Add a backup-key procedure to onboarding documentation so this
   doesn't happen again.

## Auditing this runbook

When you complete a drill (real or simulated), log it under
`.claude-session-log/` in the OV main repo with:
- Date
- Operator
- Outcome (success / partial / blocked)
- Any deviations from this procedure
- Updates needed to this runbook (open as a separate PR)

## Out-of-scope (explicitly)

This runbook does NOT cover:

- **Rotating GitHub Actions secrets that are NOT the release key.**
  See OpaqueVault main repo's secrets inventory in
  `docs/operations/secrets.md` or the runbook for `OV_API_TOKEN`,
  `OV_BACKUP_KMS`, etc.
- **Rotating the customer's vendored minisign binary.**
  See `vendor/README.md` "Update procedure".
- **Adding a co-custodian.** That's an org-policy change, not a
  rotation. File a separate PR adding the second `required` key.

## References

- Plan doc §R2-N1 / §TH1: key-rotation runbook is a hard release-blocker
- Plan doc §R6.1: vendored minisign is hash-pinned per platform
- `vendor/README.md`: minisign supply-chain trust procedure
- `release-gate.yml`: enforces this drill date < 90 days
- `entrypoint.sh:5-21`: embedded literals (`OV_VERSION`,
  `TRUSTED_KEYS_SHA256`, `MINISIGN_BIN_SHA256_*`)
