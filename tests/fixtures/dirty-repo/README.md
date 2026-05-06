# dirty-repo fixture

A test fixture that contains multiple credential-shaped strings spread
across several common file kinds. Used by `tests/contracts.bats` to
exercise the "non-zero exit, findings-count > 0" path through
`entrypoint.sh`.

## All values here are FAKE

Every credential-looking string in this directory uses one of two safe
prefixes per the OV `R3-LOW` discipline:

- `XXXFAKE_` — for AWS-, GitHub-, and Stripe-shaped tokens.
- `EXAMPLE_` — for connection-string segments (usernames, passwords).

Both prefixes are chosen so that:

1. GitHub push-protection does not block commits to this repository.
2. The strings do not match real provider regex patterns, so they are
   guaranteed not to be valid credentials at any vendor.

The contract tests do NOT actually invoke `ov scan` against this tree;
they substitute a `mock_ov_bin` helper that returns synthetic finding
JSON. These files exist for two purposes:

1. They give the action a non-empty workspace to walk over so structural
   tests (path traversal, permission handling, OS-portability) get a
   realistic input shape.
2. They serve as input for any future end-to-end / demo flow that calls
   the real `ov scan` against the fixture and asserts non-empty
   findings.

## Layout

```
dirty-repo/
├── README.md         - this file
├── aws_creds.txt     - AWS-shaped XXXFAKE_AKIA marker
├── tokens.env        - GitHub-PAT-shaped XXXFAKE_ghp marker
├── payments.config   - Stripe-shaped XXXFAKE_sk_test marker
├── auth.json         - JWT-shaped XXXFAKE marker
└── .env              - EXAMPLE_DATABASE_URL with username/password segments
```

If you need to add another finding kind, follow the same prefix rule:
either `XXXFAKE_` or `EXAMPLE_`. Anything else risks tripping
push-protection or, worse, accidentally committing a real credential.
