# Event payload fixtures

Static GitHub Actions event-payload JSON files used as inputs to
`entrypoint.sh` during contract testing and any future end-to-end /
demo flow.

The current `tests/contracts.bats` suite drives event JSON synthesis via
`make_event_payload` in `tests/helpers.bash` (it `printf`s minimal JSON
inline). These static files mirror those minimal payloads but expand
each one with enough surrounding context (`action`, `number`, `title`,
`base.repo`, `repository`) to be readable by a human reviewer or
re-usable for documentation. `entrypoint.sh` itself only parses
`.pull_request.head.repo.full_name`; the rest of each payload is for
human readers.

## Files

| File                      | `GITHUB_EVENT_NAME`     | What it represents |
|---------------------------|-------------------------|--------------------|
| `push.json`               | `push`                  | Branch push to `main` of the same-repo. |
| `same-repo-pr.json`       | `pull_request`          | PR opened from a topic branch in the same repo (`head.repo.full_name == base.repo.full_name`). |
| `fork-pr.json`            | `pull_request`          | PR opened from a forked repo (`head.repo.full_name = "fork-user/test-fixture"`); strict-mode triggers fire. |
| `null-head-pr.json`       | `pull_request`          | PR whose `head.repo` is `null` (head fork was deleted). Fail-closed treats this as untrusted. |
| `empty.json`              | `pull_request`          | Zero-byte file. Tests `entrypoint.sh`'s empty-payload guard. |
| `pull-request-target.json`| `pull_request_target`   | Same-repo PR delivered via `pull_request_target`. Refused unless `allow-pull-request-target=true`. |
| `workflow-dispatch.json`  | `workflow_dispatch`     | Manual run; no PR context. |

## Conventions

- `repository.full_name` is `opaquev/test-fixture` everywhere except in
  `fork-pr.json`, where the head fork lives at `fork-user/test-fixture`.
- All SHAs are 40-char hex with a recognizable leading word
  (`abcd…`, `beef…`, `cafe…`, `dead…`) so logs are easier to read.
- Every payload is valid JSON (except `empty.json`, which is 0 bytes by
  design).

## Adding a new fixture

1. Drop the JSON file here using the same conventions.
2. Add a row to the table above.
3. If you also want `helpers.bash` to load the file, extend
   `make_event_payload` to read from this directory; otherwise the
   helpers will continue synthesizing inline JSON for the existing
   kinds.
