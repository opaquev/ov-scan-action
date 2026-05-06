# Clean Repo Fixture

This directory is a fixture used by `tests/contracts.bats`. It contains
zero credentials and zero matches against any ov scan rule. The action
must exit 0 and emit `findings-count=0` when scanning this directory.

PR #6 will populate this fixture with a richer no-credentials surface
(non-matching example values, comments, prose). For PR #4 (red phase)
this stub is sufficient: tests assert the action's exit code and output
shape, not the scanner's recall.
