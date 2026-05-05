# Security Policy

## Reporting a vulnerability

Please send vulnerability reports to **security@opaquevault.com** with the subject `ov-scan-action: <one-line summary>`. Encrypt sensitive details with [our PGP key](https://opaquevault.com/.well-known/security.txt) when possible.

We commit to:
- Acknowledging receipt within **2 business days**.
- Triaging severity and providing an initial response within **5 business days**.
- Crediting reporters in the release notes (or anonymously, if preferred).

## Supported versions

This is a scaffold. The supported-versions matrix lands with v1.0.

## Trust model

The action verifies downloaded `ov` binaries via [minisign](https://github.com/jedisct1/minisign) against the bundled `trusted-keys.txt` file. **You must pin to a commit SHA** in production:

```yaml
uses: opaquev/ov-scan-action@<40-char-sha>
```

A `@v1` tag is informational only — pinning to it means a maintainer compromise lands in your CI on the next run. Pin to SHA + use Dependabot's `actions` ecosystem for reviewable bumps.

## Key rotation

When OV rotates the release-signing key (`F89BAB08772C1C0B`), we publish a [GitHub Security Advisory](https://github.com/opaquev/ov-scan-action/security/advisories) with the SHA bump you need. Old keys remain in `trusted-keys.txt` as `legacy` for a documented grace window before being removed.

## Threat model (pre-v1.0 outline)

The action runs `ov scan` against attacker-controlled PR contents (the standard `pull_request` context). The defenses are layered:

1. **Refuse `pull_request_target`** by default — exfiltration prevention.
2. **Fork-PR strict mode** — refuses `allow-binary-version`, `allow-ci-baseline`, `max-ov-version` overrides on fork-PR runs.
3. **Wallclock + memory budgets** on the `ov scan` invocation — defense against parser-DoS PRs.
4. **Signature verification** of the binary before exec — anti-supply-chain.
5. **`hardenedGitEnv`-equivalent** when invoking `git` from the action — strips `GIT_ALTERNATE_OBJECT_DIRECTORIES`, pins `GIT_NO_REPLACE_OBJECTS=1` + `core.useReplaceRefs=false`.

Full threat-model documentation lands with the v1.0 release.
