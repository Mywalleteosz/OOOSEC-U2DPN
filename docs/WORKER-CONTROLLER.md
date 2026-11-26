# Security Worker Controller

Status: orchestration code and unit tests only. The worker is not enabled in Docker Compose and no scanner has been executed against a live repository.

## Immutable scan input

Every scan request now requires a 40- or 64-character Git commit SHA. The API normalizes it to lowercase and stores it with the queued job. A worker never resolves a mutable branch name or tag at execution time.

## Processing sequence

1. Atomically claim one queued job with a bounded lease (default 600 seconds) and attempt count.
2. Verify the worker owns the running lease and resolve the active registered asset.
3. Accept only the implemented profiles: Gitleaks and Bandit. Other scanner identifiers fail with `scanner_not_implemented`.
4. Require a digest-pinned scanner image from `SCANNER_GITLEAKS_IMAGE` or `SCANNER_BANDIT_IMAGE`.
5. Fetch the immutable GitHub commit archive through the DNS-pinned source fetcher and safely extract it into a per-job temporary directory.
6. Run the fixed profile in the Docker sandbox with network disabled, read-only source, non-root UID, resource limits, and bounded output.
7. Normalize scanner output in memory. Persist only sanitized findings, keyed idempotently by job and fingerprint.
8. Complete or fail only while the worker's lease is still current. Job errors contain stable codes only.

The collector's `scanner_version` field records the 64-character image digest, providing exact scanner image provenance rather than trusting scanner output.

## Runtime boundary — not enabled yet

Do not mount a rootful Docker socket into the API or worker. The Docker socket grants host-level control. Before enabling a worker service, provision a dedicated rootless Docker daemon and mount only its socket into a separately hardened worker container. The scanner containers themselves must never receive that socket.

The worker needs outbound HTTPS to the approved GitHub endpoints and access to the dedicated Security Core database. The scanner containers use `--network none` and receive no credentials. Enforce worker egress at the host/network layer; application URL validation is not a substitute for egress policy.

No production deployment, Docker socket mount, database credential change, or live scanner execution is part of this increment.
