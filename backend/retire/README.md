# Offline Retire.js adapter

The worker image downloads the official Retire.js 6.1.0 npm tarball at build time, verifies the pinned SHA-512 integrity, and extracts only its dependency-free static engine and license. Advisory JSON, license and NOTICE use an immutable upstream commit and SHA-256 pins in `scripts/fetch-retire.py`.

`scan.cjs` calls only `scanFileContent` with static content/replacement/hash extractors. It never invokes the upstream CLI, dynamic function extractors, a browser, or a network client. Files must be regular fingerprint-named JavaScript downloads within the existing 100-file, 512 KiB/file and 16 MiB combined limits. The Go process supplies a 60-second timeout and process-group cleanup; Node uses a 128 MiB V8 heap limit. This heap limit is not a total RSS limit; the worker container retains its own memory cap.

Output contains per-file component/advisory observations and a final completion marker with the advisory commit. Incomplete output retains positive observations without clean coverage. Source contents are not included in reports. Worker resolution checks the original file and snapshot; snapshot upgrades intentionally retain older unchecked findings until a reviewed migration supports those rules.

To update, review the release engine/API, advisories, licenses and NOTICE; update the downloader pins, wrapper checksum/commit, Go database constant and scanner version metadata together. Run the native Linux fixture with networking disabled. No runtime update is performed.
