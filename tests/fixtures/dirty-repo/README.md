# Dirty Repo Fixture

Contains exactly ONE high-severity finding marker for ov scan to detect.

The marker is a deliberately-fake AKIA-style string used purely as a test
fixture; it is NOT a real AWS credential. ov scan's pattern matchers
recognize it and emit a finding.

PR #6 will expand this fixture with multiple finding kinds (PAT, GH PAT,
slack token, etc) and severity levels. For PR #4 (red phase) one
high-severity finding is sufficient to drive the dirty-repo contracts.
