# GitHub Source Fetcher

The source acquisition layer provides strict URL policy, DNS-pinned HTTPS transport, manual redirect validation, immutable commit archive downloads, and bounded ZIP/TAR.GZ extraction.

## Network transport

- Downloads only a GitHub repository archive from a canonical repository URL and a full 40- or 64-character commit SHA.
- Builds the codeload archive URL from the validated owner/repository and immutable commit SHA.
- Resolves each allowed hostname and rejects the entire DNS answer set if any address is non-global.
- Dials a validated IP address directly; it does not perform a second hostname lookup during TCP connection establishment.
- Wraps the pinned socket with the default certificate-verifying TLS context and uses the original hostname for SNI and certificate verification.
- Sends one GET per connection; redirects are never followed automatically.
- Manually validates each redirect destination and repeats DNS resolution and IP pinning for every hop.
- Uses no environment-configured HTTP proxy.
- Enforces connection timeout, redirect count, Content-Length and streamed byte limits; deletes partial output on errors.

Allowed download hosts are restricted to github.com and codeload.github.com, HTTPS port 443 only. The fetcher currently uses public unauthenticated GitHub archive access.

## Archive validation

- ZIP and gzip-TAR extraction into a new private directory only.
- Rejects absolute paths, traversal, dot segments, backslashes, NULs, duplicate paths, links, device/special entries, and encrypted ZIP members.
- Enforces compressed archive size, expanded total size, per-file size, file count, and path-depth limits.
- Removes partial extraction output after a validation or extraction error.

## Remaining security gates

This is a controlled implementation, not yet an enabled production job worker. Before deployment, validate actual egress policy at the container/network layer, run DNS-rebinding and redirect integration tests against a controlled HTTPS fixture, inspect TLS behavior, test archive edge cases and filesystem race assumptions, and pin eventual scanner images by digest. The downloader must run in a dedicated fetcher boundary with no MongoDB/API credentials. Scanner execution remains disabled.
