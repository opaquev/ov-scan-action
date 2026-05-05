# `opaquev/ov-scan-action`

GitHub Action that runs [`ov scan`](https://opaquevault.com/docs/scan) on your repository to find leaked secrets in the working tree and (optionally) in git history.

> **Status: scaffold.** The action implementation is being tracked under [OV-239](https://linear.app/thehunterfoundry/issue/OV-239) and lands in a follow-up PR. This README + repo skeleton exist so customers can preview the upcoming release page.

## Why a separate action?

`ov scan` is the same secret detection engine that protects every OpaqueVault MCP tool result at runtime — same rules, same false-positive tuning, same engine. Running it in CI means a credential that would have been redacted at runtime is also caught at PR time, before it reaches a server.

The action is a thin wrapper: it downloads a signed `ov` binary, verifies the signature against a bundled trusted-keys file, and runs `ov scan` against the repository checkout. **No data leaves the runner unless the user explicitly opts in to vendor-API live verification (`--verify`) or rotation (`--fix --rotate`).**

## Quickstart (when shipped)

```yaml
# .github/workflows/secret-scan.yml
name: secret-scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: opaquev/ov-scan-action@<commit-sha>  # see Security below for SHA-pinning rationale
        with:
          path: .
          fail-on: medium
```

## Security model (preview)

When the action ships, it will:

1. **Download `ov` directly** from `https://get.opaquevault.com/` (no `install.sh` bootstrap).
2. **Verify the binary** via [minisign](https://github.com/jedisct1/minisign) against a `trusted-keys.txt` file bundled in the action repo.
3. **Run the binary** with strict argument quoting and a wallclock + memory budget.
4. **Refuse to run in `pull_request_target` context** by default (anti-fork-PR-exfiltration gate).
5. **Refuse `allow-binary-version`, `allow-ci-baseline`, and `max-ov-version` overrides** in fork-PR contexts.
6. **Use `$GITHUB_OUTPUT` heredoc** with integer validation for action outputs (no output-injection).

### Pin to commit SHA, not tag

Production users **must** pin to a commit SHA: `uses: opaquev/ov-scan-action@<40-char-sha>`. The `@v1` tag is informational only — pinning to a tag means a maintainer (or a compromise of the action repo) can ship a malicious update that you consume on the next CI run. SHA pinning + Dependabot's `actions` ecosystem gives you reviewable, auditable bumps.

### Key rotation

The bundled `trusted-keys.txt` lists the Ed25519 minisign keys the action accepts. When OV rotates its release-signing key, we publish a security advisory with explicit `git diff` of the SHA bump customers need. See [`docs/runbooks/release-key-rotation.md`](docs/runbooks/release-key-rotation.md) when it lands.

## Roadmap

- **v1.0** — Linux + macOS (x86_64 + arm64). The Linear ticket: OV-239.
- **Post-v1** — Windows runner support ([OV-245](https://linear.app/thehunterfoundry/issue/OV-245)).
- **Post-v1** — `revoked-versions.txt` for CVE'd-but-still-signed binary defense ([OV-246](https://linear.app/thehunterfoundry/issue/OV-246)).

## Links

- Main repo: https://github.com/huntrock17/opaquevault
- Docs: https://opaquevault.com/docs
- `ov scan` v1 design: [`docs/superpowers/specs/2026-05-02-ov-scan-v1-design.md`](https://github.com/huntrock17/opaquevault/blob/main/docs/superpowers/specs/2026-05-02-ov-scan-v1-design.md)

## License

MIT (see [LICENSE](LICENSE)).
