# Result Collector

The collector is a pure normalization boundary. It accepts bounded JSON bytes from the fixed Gitleaks and Bandit profiles and returns normalized finding records. It does not write to MongoDB, log raw output, or retain scanner payloads.

## Data minimization

- Gitleaks: never copies `Secret`, `Match`, raw values, or scanner-supplied fingerprints.
- Bandit: never copies `issue_text` or `code`, which may contain source fragments.
- Titles and descriptions are generated from fixed templates; only validated rule IDs are interpolated.
- Fingerprints are recomputed from scanner, rule ID, repository-relative path, and line.
- Commit SHA and scanner version are validated before normalization.

## Validation

- Strict UTF-8 JSON parsing with duplicate-key rejection.
- Maximum output size: 2 MiB by default.
- Maximum finding count: 1,000.
- Paths must be relative POSIX paths without empty, dot, dot-dot, backslash, NUL, or excessive-depth segments.
- Line and column values are bounded positive integers.
- Severity is normalized to low/medium/high/critical; unsupported values fail closed.
- Unsupported scanner IDs, malformed payloads, and invalid metadata are rejected.

The caller must persist only the returned normalized records. Raw output must remain transient and must never be included in logs or job error messages. MongoDB persistence and lease-checked job completion are separate follow-up work.
