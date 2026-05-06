# clean-repo fixture

A small, realistic-looking repository used by `tests/contracts.bats` to
exercise the "no findings" path through `entrypoint.sh`.

This directory is intentionally free of credentials. No file in the tree
contains an AWS key, GitHub token, Stripe key, JWT, password, private
key, or any other credential-shaped string. It exists to give
`ov scan` a non-trivial surface to walk while still emitting
`findings-count=0`, so contract tests assert the action's exit code and
output shape rather than the scanner's recall.

When the action is run against this fixture (with a mocked `ov` binary
returning `{"findings":[]}`) the expected behavior is:

- exit code `0`
- `findings-count=0` line in `$GITHUB_OUTPUT`
- no `::error::` annotations on stderr

## Layout

```
clean-repo/
├── README.md           - this file
├── LICENSE             - MIT placeholder
├── Makefile            - minimal build rules
├── main.go             - hello-world Go entrypoint
├── app.py              - hello-world Python script
├── .env.example        - template (placeholder values only)
└── config/
    └── settings.yaml   - configuration with no secret values
```

All of these files are deliberately small and non-sensitive.
