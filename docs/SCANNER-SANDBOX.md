# Scanner Sandbox — first implementation increment

This increment adds a fixed-profile Docker invocation builder and a bounded runner. It does not connect the queue to the runner, publish images, or enable scans.

## Fixed profiles

Only `gitleaks` and `bandit` are accepted. Their argument vectors are defined in code; API callers cannot supply an image, executable, flags, shell text, or arbitrary command array. Each image must be configured as a full immutable image reference ending in `@sha256:<64 lowercase hex characters>`. No default mutable tag is accepted.

## Runtime boundary

The generated invocation enforces:

- `--network none`;
- read-only container root filesystem;
- read-only bind mount of the validated source directory at `/src`;
- non-root UID/GID 65532;
- all Linux capabilities dropped;
- `no-new-privileges`;
- bounded PID, memory, CPU, open-file and file-size limits;
- private `/tmp` tmpfs with `noexec,nosuid,nodev`;
- no host environment forwarding, runtime socket mount, host PID namespace, host network, or privileged mode.

The runner reads only bounded stdout, discards stderr, applies a wall-clock deadline, and attempts to kill the container by its CID on timeout/output overflow. Raw scanner output may contain secret material (especially Gitleaks findings); callers must keep it transient, never log it, and sanitize findings before persistence.

## Critical deployment constraints

The runner is a control-plane component and requires access to the Docker daemon. It must run separately from the API and database credential holder, under a dedicated host identity with narrowly scoped access to the container runtime. The scanner container itself must never receive the Docker socket. Docker daemon access is effectively host-root-equivalent and must not be granted to an internet-facing API container.

The image references in tests are syntax fixtures only, not verified image digests. Deployment must supply real digests obtained from a trusted registry, verify image provenance, and scan the pinned images before use.

This increment does not start containers in CI or on the user's host. Before enabling jobs, validate the exact Docker/Compose runtime behavior on a disposable host, verify AppArmor/seccomp policy, test network denial from inside the container, verify timeout kill behavior, and run a disposable test repository end-to-end.
