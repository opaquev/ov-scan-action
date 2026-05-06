# Vendored minisign binaries

This directory contains pre-built `minisign` binaries used by `entrypoint.sh`
to verify the signed `ov` release artifacts. Vendoring these binaries (rather
than installing minisign at runtime via `go install` or `apt-get`) collapses
the trust chain to the action's own SHA-pin: a customer who pins
`uses: opaquev/ov-scan-action@<40-char-sha>` is protected by the same git
content hash that gates this directory.

## Trust chain

1. **jedisct1's well-known minisign public key** signs every official
   minisign release on GitHub. The key is published at:
   - https://github.com/jedisct1/minisign (README + `minisign.pub` in repo)
   - The public key bytes (base64): `RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3`
   - The hex fingerprint: `16839B40E54CDB8B`

2. **Each minisign release archive** (e.g., `minisign-0.12-linux.tar.gz`) is
   accompanied by a `.minisig` signature file from jedisct1's key. We
   verify these signatures BEFORE extracting binaries from the archives.

3. **The extracted binaries** (`minisign-${VER}-${TARGET}`) are committed
   to this directory with their SHA-256 hashes recorded in `SHA256SUMS`.
   `entrypoint.sh` embeds these hashes as literal constants
   (`MINISIGN_BIN_SHA256_*`) and verifies them at runtime before use.

## Supported targets

- `linux_amd64` — extracted from `minisign-0.12-linux.tar.gz` `x86_64/`
- `linux_arm64` — extracted from `minisign-0.12-linux.tar.gz` `aarch64/`
- `darwin_arm64` — extracted from `minisign-0.12-macos.zip` (arm64-only)

**Not supported: `darwin_amd64`.** jedisct1's macOS release ships an
arm64-only Mach-O, not a fat universal binary. Self-building a
darwin_amd64 binary would require us to add a "we built this, here's
our hash" trust assumption that's weaker than the rest of the chain.
Customers on Intel Macs should use `macos-13` runners with manual
minisign install, or migrate to `macos-14+` runners (arm64). GitHub
deprecated `macos-13` in 2026; this is a supported-platform alignment,
not a meaningful regression.

## Update procedure

**Scheduled bumps** (e.g., minisign 0.12 → 0.13):

1. Verify the new release archive against jedisct1's key:
   ```bash
   gh release download <new-version> --repo jedisct1/minisign \
     --pattern 'minisign-<new-version>-linux.tar.gz*' \
     --pattern 'minisign-<new-version>-macos.zip*'
   minisign -V -p jedisct1.pub \
     -m minisign-<new-version>-linux.tar.gz \
     -x minisign-<new-version>-linux.tar.gz.minisig
   minisign -V -p jedisct1.pub \
     -m minisign-<new-version>-macos.zip \
     -x minisign-<new-version>-macos.zip.minisig
   ```
   Both must report `Signature and comment signature verified`.

2. Extract binaries:
   ```bash
   tar -xzf minisign-<new-version>-linux.tar.gz
   cp minisign-linux/x86_64/minisign  vendor/minisign-<new-version>-linux_amd64
   cp minisign-linux/aarch64/minisign vendor/minisign-<new-version>-linux_arm64
   unzip -o minisign-<new-version>-macos.zip minisign
   cp minisign vendor/minisign-<new-version>-darwin_arm64
   ```

3. Regenerate `SHA256SUMS`:
   ```bash
   cd vendor && shasum -a 256 minisign-<new-version>-* > SHA256SUMS
   ```

4. Update `MINISIGN_VERSION` and the three `MINISIGN_BIN_SHA256_*`
   literals in `entrypoint.sh`. Bump in the SAME PR — the action's
   trust model assumes binary content + embedded hash literal +
   `MINISIGN_VERSION` are all consistent at any commit.

5. Open a PR that references this README. The 9-PR canonical loop
   applies: pre-review → implementer (you) → post-review → CI green
   → Devin → senior SWE → merge.

**Emergency CVE bumps** (out-of-band, faster cadence): treat as a
supply-chain incident. Same verification + commit procedure as above,
but pause `@v1` tag movement until the bump merges. Document the CVE
ID in the commit message body.

## Recovery: jedisct1 key rotation

If jedisct1 rotates the minisign signing key (`16839B40E54CDB8B`),
treat as a supply-chain incident:

1. Confirm key-rotation announcement on jedisct1/minisign repo (GitHub
   Issues, release notes, security advisory).
2. Pause `@v1` tag movement on `opaquev/ov-scan-action`.
3. File an OV-XXX security ticket; coordinate with @huntrock17.
4. Update the public-key reference in this README and in any
   verification scripts.
5. Verify the next minisign release against the NEW key; repeat the
   "Scheduled bumps" procedure.
6. Resume `@v1` tag movement only after a fresh release-key-rotation
   drill (per `docs/runbooks/release-key-rotation.md`).

## Why not Sigstore / cosign?

Sigstore + Fulcio is the long-term direction for signed releases, but
as of 2026-Q2 jedisct1's minisign project does not publish via
Sigstore. Adopting Sigstore here would require either (a) trusting a
third-party re-signing service (weakens trust chain) or (b) waiting
for jedisct1 upstream to migrate. We track this as future work.

## Files in this directory

- `minisign-0.12-linux_amd64` — Linux x86_64, 288K, statically linked, stripped ELF
- `minisign-0.12-linux_arm64` — Linux ARM64, 195K, statically linked, stripped ELF
- `minisign-0.12-darwin_arm64` — macOS ARM64, 181K, Mach-O 64-bit (single-arch)
- `SHA256SUMS` — `shasum -a 256` output covering all three binaries
- `README.md` — this file
