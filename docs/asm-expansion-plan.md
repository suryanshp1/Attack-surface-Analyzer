# Open-source ASM expansion plan

## First delivery

1. Integrate Retire.js 6.1.0's dependency-free static engine with a checksum-pinned advisory snapshot. Reuse bounded public JavaScript downloads; never execute scripts, fetch advisory data during a scan, or validate credentials. Preserve partial findings and require original-file coverage for resolution.
2. Retain validated CVE/CWE/CVSS metadata from Nuclei and dependency/version/detection provenance from Retire.js. Expose it in finding details and queries without changing fingerprints or triage.
3. Add append-only structured DNS, certificate, port and technology changes between comparable successful scans. Include before/after observations and scan lineage. Partial/missing observations must not imply removal.
4. Expand reviewed signed Nuclei exposure checks where compatible templates can be validated with the isolated Linux fixture.
5. Validate with deterministic regression tests, typecheck/build, the native scanner fixture, disposable storage round trips, and desktop/mobile light/dark UI inspection.

All fields are additive to existing JSON/JSONB records. No database reset, new paid service, production fixture data, external evidence upload, or change to worker credentials/network topology is needed.

## Subsequent deliveries

- Controlled KEV/EPSS import and dated local cache, followed by explainable prioritization. CVE metadata from the first delivery is the prerequisite; target scan permits cannot authorize arbitrary feed hosts.
- cdncheck infrastructure enrichment and deeper bounded TLSx enumeration, each with gateway fixtures and pinned data.
- DNS posture validation/uncertainty improvements and selectively adapted checkdmarc functionality.
- Ownership, due dates, SLA reporting and grouped notifications.
- Benchmark Amass incremental discovery, and isolate optional ZAP/screenshot profiles before integrating them.

See [the research](asm-research.md) for upstream sources, licenses and tradeoffs. Delivery status and actual validation belong in the implementation summary; this plan does not establish that a feature is complete.
