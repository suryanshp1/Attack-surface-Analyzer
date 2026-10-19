# Scanning and coverage

[Back to README](../README.md)

Scans operate on the selected root domain and its subdomains. Use them only for systems you are authorized to assess. Public observations are retained even when some checks cannot finish; missing results alone never establish that an asset is clean.

## Scanner profiles

| Tool | Profile |
| --- | --- |
| Subfinder | Passive discovery through crt.sh, HackerTarget, and RapidDNS; includes the root and previous inventory with provenance |
| DNSx | A/AAAA resolution through the gateway DNS relay; non-public addresses excluded from active checks |
| Naabu | Unprivileged TCP connect against observed public domain addresses, 35 explicit ports, at most 10 attempts/s |
| HTTPx | HTTP status, title, technologies, restricted redirects, and failed-probe reporting |
| TLSx | Negotiated TLS version/cipher, certificate names, issuer, expiry, and trust/name observations |
| GAU | Wayback/Common Crawl URL history; stored separately as unverified history with query values removed |
| Katana | Non-headless, scoped crawl; depth 3, up to 2 requests/s per seed within the shared scan budget, 200-page profile, 90-second per-service budget; endpoint, JavaScript, form, robots, and sitemap discovery |
| Gitleaks | Public JavaScript only; at most 100 files, 512 KiB/file and 16 MiB total; secrets masked and never validated |
| Nuclei | Reviewed signed HTTP templates; technology-specific gates; no intrusive/fuzz/bruteforce/dos tags, public interactsh, or cloud upload |

The [scanner downloader](../scripts/fetch-scanners.py) pins versions and validates release SHA-256 checksums. License files ship with the worker binaries. The [template manifest](../backend/templates/manifest.json) records upstream URLs, hashes, technology gates, and the pinned template release.

The curated 14-template set covers selected exposed configuration, source-control files, metrics, API documentation, GraphQL consoles, and service status endpoints. It is not the full upstream CVE catalog. New templates require review, provenance, and fixture validation.

## Partial results and recovery

A scan has a 60-minute worker budget and a 75-minute overall active deadline. Discovery, history and JavaScript analysis retain seven-minute stage guards. DNS, HTTP/TLS and detection budgets scale with workload up to twenty minutes; port discovery derives a workload-aware budget capped at forty minutes. Every stage budget is limited by the remaining worker window, reserving fifteen seconds for each downstream stage and ten seconds for final commits. Request, connection and subprocess timeouts remain enabled. Port checks run in batches of up to five addresses with three-minute batch limits, reduced further at low configured rates. Completed batches survive interruption.

Discovery, DNS resolution, TLS assessment and HTTP probing retain complete records produced before a subprocess failure or timeout. Discovery always includes the selected root and previous inventory. HTTP probing marks unanswered services incomplete. A missing HTTP response does not mean a host is safe or absent.

Katana runs separately for each deduplicated service origin with a 110-second process guard. Its stage budget is seven–twenty minutes based on unfinished work and effective seed concurrency. Up to five seeds run concurrently, with per-process rates and concurrency divided to stay within the scan settings. Completed seed checkpoints and valid JSONL records survive interruption; a truncated last record is ignored. Bounded crawl passes continue to downstream analysis with collected data. Large inventories can require several passes. A single result collector owns crawl and detection checkpoint updates. Transient checkpoint failures receive up to three attempts within a five-second commit window; invalid or lost leases are never retried. Commit failures are reported, and completed observations are retained for the final stage commit.

Use **Scan activity → Resume scan** or `POST /api/scans/{id}/retry` to create a new run from saved stages. The original run remains in history. Completed port batches, crawl seeds and confirmed detection services are reused; unfinished work is retried. Stage execution can finish with incomplete coverage: explicit stage issues force a partial scan, and resume starts at the earliest affected stage. Retrying discovery or DNS invalidates stale downstream network checkpoints. Worker shutdown or execution-window expiration checkpoints the current stage before releasing the lease; three interrupted worker attempts terminate as partial. Concurrent target runs, revoked access, paused scanning, and missing ownership proof in required-verification mode prevent retry.

DNS takeover checks use a bounded pool of at most ten tasks, honor the configured concurrency, share gateway DNS pacing and have eight-second task guards plus an allowance for pacing wait. Transient DNS errors remain incomplete checks rather than negative results. Takeover candidates resolve only after two consecutive completed successful scans without a matching observation, and reopen immediately with reset missing scan counts if rediscovered.

Nuclei groups curated templates by matching technology (with generic templates evaluated across all services). URLs are batched in groups of up to 50, with up to three parallel worker processes. Rate, template concurrency, and host concurrency are scaled across subprocesses to stay within the scan settings (`-mhe 5` skips unresponsive hosts before they exhaust stage budgets). Scanner output is streamed line by line to eliminate buffer overflow risks. Observed records and findings are merged in memory and checkpointed to the API periodically (or whenever new findings are discovered). A resumed detection pass skips services whose required templates already have coverage and preserves observed findings.

Finding observations are published and become visible in the workspace as each scan stage or detection batch checkpoint commits, rather than waiting for the entire scan to complete. Finding summaries lead each stage log. Finding lifecycle resolution still requires two completed, successful scans with explicit host and template coverage; stage-time publishing only performs additive ingestion and triage preservation.

Stage completion commits retry transient API failures (up to 4 attempts over 20 seconds). Heartbeat monitoring tolerates transient failures up to a 20-second safety window before cancelling execution.

JavaScript downloads honor configured concurrency (up to six), deduplicate URLs, and reserve disk budget before writing files. Every discovered JavaScript file counts toward coverage, including files excluded by the 100-file or 16 MiB budget. Failed, skipped, oversized or incomplete downloads prevent clean secret coverage for that host; one successful file cannot clear unchecked secret history.

Completed-stage evidence uploads run outside the global API state lock so heartbeats can proceed. Upload objects are immutable and keyed by lease/content; the API checks the current lease and target authorization again before committing. Expired leases cannot be revived by late heartbeats. Empty worker claim polls do not rewrite workspace storage.

Stage progress is not asset coverage. A finished bounded crawl is not proof of exhaustive website coverage. Expected non-public exclusions do not themselves fail public coverage, but failed checks and unfinished stages keep affected coverage incomplete.

## Lifecycle rules

| Record | When it can be removed or resolved |
| --- | --- |
| Finding | After two successful scans with explicit coverage of its host and template |
| Asset | After two successful scans with confirmed DNS absence |
| Endpoint | After two clean completed crawls establishing absence |
| Subdomain takeover | After two successful scans confirming absence of the dangling CNAME |

Partial scans, blocked hosts, missing responses, resolver failures, and checks that did not run preserve unchecked history. Accepted-risk and false-positive decisions remain suppressed; resolved issues reopen when rediscovered. First-seen timestamps and triage notes are retained through normalization.

Live endpoint records store paths and query parameter names, not captured query values or form values. Form extraction does not submit forms. Historical archive URLs are labeled unverified and do not establish a live service.

## Pacing and blocked hosts

Workspace scan rates are capped at 30 requests/s and concurrency at 10. The egress gateway paces plain HTTP requests and HTTPS tunnel creation according to the scan's cryptographically signed permit rate and concurrency, with scaled jitter to avoid arrival synchronization. Legacy permits without explicit rate settings fall back to a conservative 500 ms interval and two concurrent plain HTTP requests per domain. Active scan verification at gateway admission is cached for 2 seconds to reduce API load while preserving rapid revocation response. These limits are shared across workers. TCP scanning uses separate admission pacing.

User-Agent variants identify `Surfacer/1.0`; they do not impersonate browsers. Observed HTTP 403/429/503 responses trigger shared cooldowns and exponential backoff. `Retry-After` seconds and HTTP dates can extend cooldowns. Blocked hosts are skipped with incomplete coverage and retain prior findings.

HTTPS payloads remain encrypted: the gateway paces tunnel creation, while scanner limits govern requests within tunnels. Cooldown reporting from scanner output can be delayed until a subprocess finishes. Gateway cooldown state resets on restart. Header variation does not guarantee scanning will be permitted.

## Evidence

Finding evidence is redacted, capped at 16 KiB, and rendered as inert text. Sensitive new configuration matches omit raw response bodies. Raw evidence and stage objects are cleaned according to retention settings every 15 minutes; summary and audit records remain. Evidence is self-contained and is never sent to third-party services.

## Pipeline measurements

The owner metrics endpoint includes stage duration summaries, `surfacer_scan_stage_timeouts_total`, `surfacer_checkpoint_writes_total`, `surfacer_checkpoint_failures_total` and a `surfacer_checkpoint_duration_seconds` summary. Checkpoint metrics measure port/crawl/detection progress commits and interrupted-stage commits, including bounded retry time. Counters reset with the process. Compare completed service/template coverage and partial-run frequency alongside runtime; a shorter scan with more unchecked work is not a throughput improvement.

## Understanding scan outcomes in the workspace

Scan detail distinguishes a finished execution pass from a pass with coverage gaps. HTTP outcomes are recorded per service origin; a failed or silent sibling service cannot disappear behind a successful response on the same host. HTTP subprocess errors preserve observations and force an incomplete stage. A healthy sibling stays eligible for detection, subject to the same shared gateway cooldowns and pacing.

HTTP coverage counts origins that responded without blocking/server errors versus origins still unchecked. Detection coverage counts completed and unfinished required service/template pairs for eligible services; services with unsuccessful HTTP checks are listed separately. These are bounded-profile counts, not exhaustive site or vulnerability coverage. Older snapshots without the new counters display unavailable counts rather than zero completed checks. Public service issue lists are capped at 50 entries and include the total affected count.

Before continuing a partial or failed attempt, scan detail shows the restart stage, earlier stage passes retained, downstream passes rerun, and checkpoint reuse policy. The preview and retry use the same server restart-stage logic. A continued attempt creates a new run with a link to its parent; original observations, timestamps and triage history remain. Stage timings are recorded for new execution passes. Existing JSON and PostgreSQL JSONB records load without a schema reset or migration.

Scan history is paginated with URL-backed filters. Live updates reconnect with bounded backoff and use periodic snapshot refresh only while disconnected; hidden tabs suspend stream/poll activity. The workspace shows connection state and the time the last snapshot was received, independently of observation age.
