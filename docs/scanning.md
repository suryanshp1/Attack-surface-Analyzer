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
| Katana | Non-headless, scoped crawl; depth 3, 2 requests/s, 200-page profile, 90-second per-service budget; endpoint, JavaScript, form, robots, and sitemap discovery |
| Gitleaks | Public JavaScript only; at most 100 files, 512 KiB/file and 16 MiB total; secrets masked and never validated |
| Nuclei | Reviewed signed HTTP templates; technology-specific gates; no intrusive/fuzz/bruteforce/dos tags, public interactsh, or cloud upload |

The [scanner downloader](../scripts/fetch-scanners.py) pins versions and validates release SHA-256 checksums. License files ship with the worker binaries. The [template manifest](../backend/templates/manifest.json) records upstream URLs, hashes, technology gates, and the pinned template release.

The curated 14-template set covers selected exposed configuration, source-control files, metrics, API documentation, GraphQL consoles, and service status endpoints. It is not the full upstream CVE catalog. New templates require review, provenance, and fixture validation.

## Partial results and recovery

A scan has a 60-minute worker budget and a 75-minute overall active deadline. Most stages have seven-minute timeouts; port discovery derives a workload-aware budget capped at 40 minutes. Port checks run in batches of up to five addresses with three-minute batch limits, reduced further at low configured rates. Completed batches survive interruption.

HTTP probing retains complete records produced before a timeout and marks unanswered services incomplete. A missing HTTP response does not mean a host is safe or absent.

Katana runs separately for each deduplicated service origin with a 110-second process guard. Its stage budget is seven–twenty minutes based on unfinished work. Completed seed checkpoints and valid JSONL records survive interruption; a truncated last record is ignored. Bounded crawl passes continue to downstream analysis with collected data. Large inventories can require several passes.

Use **Scan activity → Resume scan** or `POST /api/scans/{id}/retry` to create a new run from saved stages. The original run remains in history. Completed port batches and crawl seeds are reused; unfinished work is retried. Concurrent target runs, revoked access, paused scanning, and missing ownership proof in required-verification mode prevent retry.

Stage progress is not asset coverage. A finished bounded crawl is not proof of exhaustive website coverage. Expected non-public exclusions do not themselves fail public coverage, but failed checks and unfinished stages keep affected coverage incomplete.

## Lifecycle rules

| Record | When it can be removed or resolved |
| --- | --- |
| Finding | After two successful scans with explicit coverage of its host and template |
| Asset | After two successful scans with confirmed DNS absence |
| Endpoint | After two clean completed crawls establishing absence |

Partial scans, blocked hosts, missing responses, resolver failures, and checks that did not run preserve unchecked history. Accepted-risk and false-positive decisions remain suppressed; resolved issues reopen when rediscovered. First-seen timestamps and triage notes are retained through normalization.

Live endpoint records store paths and query parameter names, not captured query values or form values. Form extraction does not submit forms. Historical archive URLs are labeled unverified and do not establish a live service.

## Pacing and blocked hosts

Workspace scan rates are capped at 30 requests/s and concurrency at 10. The gateway additionally spaces plain HTTP requests and HTTPS tunnel creation by at least 500 ms with jitter, with two concurrent plain HTTP requests and ten HTTPS tunnels per domain. These limits are shared across workers. TCP scanning uses separate admission pacing.

User-Agent variants identify `Surfacer/1.0`; they do not impersonate browsers. Observed HTTP 403/429/503 responses trigger shared cooldowns and exponential backoff. `Retry-After` seconds and HTTP dates can extend cooldowns. Blocked hosts are skipped with incomplete coverage and retain prior findings.

HTTPS payloads remain encrypted: the gateway paces tunnel creation, while scanner limits govern requests within tunnels. Cooldown reporting from scanner output can be delayed until a subprocess finishes. Gateway cooldown state resets on restart. Header variation does not guarantee scanning will be permitted.

## Evidence

Finding evidence is redacted, capped at 16 KiB, and rendered as inert text. Sensitive new configuration matches omit raw response bodies. Raw evidence and stage objects are cleaned according to retention settings every 15 minutes; summary and audit records remain. AI triage is disabled and evidence is not sent to third-party AI services.
