# Scanner Engine Isolation Contract

Status: design gate for the first executable scanner worker.

This document defines the security boundary required before scanner execution is enabled. The current Security Core only registers assets and queues scan jobs. It must not execute repository content or accept arbitrary commands.

## 1. Trust boundaries

| Component | Network | Credentials | Untrusted input |
|---|---|---|---|
| Security Core API | Compose network to MongoDB | API token and MongoDB URI | API payloads |
| Queue controller | MongoDB only | Dedicated queue DB identity | Job metadata |
| Source fetcher | HTTPS egress to GitHub only | No application or database secrets | Repository URL and archive |
| Scanner sandbox | No network | No credentials | Read-only source tree |
| Result collector | Internal bounded channel | Database write identity only | Scanner output |

The queue controller, fetcher, scanner sandbox, and result collector must not be combined into one privileged container.

## 2. Source acquisition requirements

The fetcher must:
- accept only canonical `https://github.com/{owner}/{repo}` URLs from registered assets;
- resolve DNS and reject loopback, private, link-local, multicast, reserved, and unspecified IP ranges for IPv4 and IPv6;
- revalidate every redirect target and every resolved address; reject redirects away from the approved GitHub host;
- connect to the validated address while preserving TLS hostname verification and SNI for `github.com`;
- reject URL userinfo, non-443 ports, query strings, fragments, encoded path separators, and unexpected path segments;
- use bounded connect/read timeouts, response size, archive size, file count, path depth, and total extracted bytes;
- reject absolute paths, traversal components, symlinks, hardlinks, device nodes, and duplicate normalized archive paths;
- write only into a fresh per-job staging directory and never follow symlinks during extraction;
- pin the resolved repository commit SHA before scanning so the fetched source is immutable and auditable.

A URL allowlist alone is not SSRF protection. Do not implement fetching with an unrestricted `requests.get(repository_url)` or follow redirects automatically.

## 3. Scanner sandbox requirements

The scanner runtime must:
- run as a non-root UID with a read-only root filesystem;
- receive source only through a read-only mount;
- have `network_mode: none` (or an equivalent enforced network policy);
- have no Docker socket, container-runtime socket, host PID namespace, host network, or privileged mode;
- drop all Linux capabilities and enable no-new-privileges;
- use seccomp and AppArmor/SELinux profiles where supported;
- set strict CPU, memory, PID, file-size, open-file, wall-clock, and output-size limits;
- use a bounded scratch filesystem mounted `noexec,nosuid,nodev`;
- receive no API token, MongoDB URI, cloud credential, SSH key, or host environment;
- execute only a fixed scanner profile selected by an enum; never accept shell fragments, executable paths, flags, or arbitrary command arrays from API clients;
- use pinned scanner image digests and periodically audit image contents and vulnerability databases.

The sandbox must not install dependencies, execute project build scripts, import project modules, or run repository-provided hooks. Initial scanners must operate in filesystem-only/offline modes.

## 4. Control-plane contract

The queue controller owns job leases and MongoDB state. The scanner sandbox does not access MongoDB.

The controller must:
1. claim one eligible job atomically with a bounded lease and attempt count;
2. resolve the asset ID to a registered canonical repository;
3. pass only a validated immutable source snapshot and fixed scanner profile to the isolated execution boundary;
4. enforce a hard execution deadline and terminate the entire sandbox process/container on timeout;
5. validate scanner output against a strict schema and byte/count limits;
6. persist normalized findings and bounded error codes;
7. complete or fail a job only while its worker lease is still valid.

A stale worker must not be able to overwrite the result of a newer lease holder. Raw exception strings, command output, source contents, and secrets must not be copied into job error fields or ordinary application logs.

## 5. Result schema limits

Each finding should contain only:
- scanner identifier and scanner version;
- rule ID and normalized severity;
- repository-relative path;
- line/column where available;
- short sanitized title and description;
- stable fingerprint;
- immutable commit SHA.

Enforce maximum finding count, string lengths, output bytes, and path normalization. Reject absolute paths and paths containing traversal components. Do not store full source files or unbounded raw scanner output.

## 6. Rollout gates

Do not enable executable scans until all gates pass:

- [ ] SSRF-resistant fetcher tests cover redirects, DNS rebinding, IPv4/IPv6 private ranges, and invalid ports.
- [ ] Archive extraction tests cover traversal, symlinks, hardlinks, device entries, duplicate paths, and decompression bombs.
- [ ] Sandbox configuration is verified from the running container, not just Compose YAML.
- [ ] Network isolation is tested from inside the scanner runtime.
- [ ] No credentials or runtime sockets are visible inside the scanner.
- [ ] Resource-limit and timeout tests prove termination of runaway scanners.
- [ ] Malformed and oversized scanner output is rejected.
- [ ] Queue lease expiry and stale-worker completion races are tested.
- [ ] Container images are pinned by digest and scanned.
- [ ] A disposable test repository is used for end-to-end validation.

## 7. Explicit non-goals for this increment

This contract does not add a Docker socket, run scanner binaries, download repositories, change MongoDB authentication, alter the existing bot/API/Mini App, or deploy any service. Those are separate changes after the isolation boundary is implemented and tested.
