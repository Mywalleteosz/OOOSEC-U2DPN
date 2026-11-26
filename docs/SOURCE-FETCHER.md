# GitHub Source Fetcher — first implementation increment

This increment implements URL/DNS policy helpers and bounded ZIP/TAR.GZ extraction. It does **not** perform outbound HTTP requests and does not start scanners.

## Implemented controls

- Canonical GitHub repository URL validation; no userinfo, non-HTTPS scheme, alternate port, query, fragment, encoded path, or extra path segments.
- Download redirect host allowlist limited to `github.com` and `codeload.github.com`.
- DNS answer validation rejects empty results and any non-global IPv4/IPv6 address. A mixed public/private answer is rejected in full.
- ZIP and gzip-TAR extraction into a newly created directory only.
- Rejects absolute paths, traversal, backslashes, NULs, duplicate paths, symbolic/hard links, device/special entries, and encrypted ZIP members.
- Enforces compressed archive size, expanded total size, per-file size, file count, and path-depth limits.
- Removes partial extraction output after a validation or extraction error.

## Important network boundary

These helpers are policy primitives, not a complete SSRF-resistant downloader. A production fetcher still needs a transport that pins the validated DNS address for the actual TCP connection while preserving TLS certificate verification and SNI, disables automatic redirects, revalidates each redirect, and applies an outbound firewall allowlist. A DNS check followed by an ordinary HTTP client call is vulnerable to DNS rebinding and is not an acceptable substitute.

No repository content is executed during acquisition or extraction. Scanner execution remains disabled pending a separately reviewed sandbox implementation.
