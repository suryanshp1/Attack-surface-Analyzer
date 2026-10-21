# Attack surface management expansion research

Research date: 21 October 2026. This is a proposal based on repository inspection and upstream documentation, not an implementation or scanner benchmark.

## Recommendation

Improve detection depth, observation history, and remediation workflow before adding another general discovery stack. The strongest initial additions are reviewed Nuclei exposure checks, offline browser-library analysis with Retire.js, structured change tracking, and CVE-based prioritization using KEV and EPSS. Most of this can run without paid API subscriptions; hosting, maintenance, and some optional upstream data sources still have costs.

## Comparison with Strobes

[Strobes' ASM page](https://strobes.co/solutions/attack-surface-management/) advertises discovery, scanning, classification, correlation, risk prioritization, attack paths, monitoring, and reporting. These are vendor descriptions; this review does not independently verify its coverage, effectiveness, or performance claims.

| Area | Evidence in Surfacer today | Useful next step |
| --- | --- | --- |
| Discovery | Subfinder, DNSx, root/previous inventory, provenance, archive URL collection | Measure discovery sources; retain observed relationships and confidence |
| Service inventory | Naabu, HTTPx, technology identification, TLSx | Provider context and more complete TLS configuration checks |
| Exposure detection | 14 curated Nuclei templates, public-JavaScript Gitleaks, endpoint hazard candidates | Broaden reviewed checks and identify vulnerable browser libraries |
| DNS/email | SPF/DMARC policy parsing, three common DKIM selectors, MX observations, takeover candidates | Validation depth and explicit unavailable/unchecked states |
| Correlation | Stable finding fingerprints and triage/history preservation | Group related observations without merging away evidence or lifecycle |
| Prioritization | Severity and asset finding counts | Structured CVE/CVSS metadata, KEV, EPSS, owner-supplied criticality |
| Monitoring | Scheduled scans, events, new asset/port/high finding/takeover webhook triggers | Structured field changes, certificate/technology drift, alert grouping |
| Reporting/remediation | PDF/CSV, scan history, notes, triage, overview work in the current tree | Ownership, due dates, SLA tracking, comparable historical trends |
| Attack paths | External observations and candidate hazards | Evidence-backed relationship view; internal lateral movement is outside current visibility |

Repository evidence: [scanner execution](../backend/worker.go), [advanced scanners](../backend/advanced_scanners.go), [DNS checks](../backend/takeover_dns.go), [normalization/events](../backend/jobs.go), [webhooks](../backend/webhooks.go), [types](../lib/types.ts), [template manifest](../backend/templates/manifest.json), [reports](../backend/reports.go), and [deployment boundaries](../compose.yaml). The working tree already contains overview and query-language work; those should not be proposed as wholly missing features.

## Tool and data shortlist

Effort below is relative engineering judgment: small means focused enrichment, medium means new parsing/state/coverage work, and large means a new execution or trust boundary. It is not a delivery estimate. Licenses describe upstream projects; pinned releases, dependencies, datasets, and notices still need packaging review.

| Priority | Tool/data | Benefit and integration | Effort / constraints |
| --- | --- | --- | --- |
| 1 | [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates), MIT | Expand the existing curated manifest with reviewed checks for exposed management/status interfaces and configuration exposures; later add suitable non-invasive CVE checks | Medium. Review each request and matcher, pin hashes/signatures, preserve metadata-only sensitive evidence and explicit per-service/template coverage. Never enable the entire catalog by default |
| 1 | [Retire.js](https://github.com/RetireJS/retire.js), Apache-2.0 | Detect known-vulnerable browser libraries from JavaScript already downloaded for Gitleaks; optionally export an observed-library CycloneDX inventory | Medium. Run local static analysis without executing scripts or fetching arbitrary resources. Pin advisory data and its notices; retain component/version confidence and advisory provenance |
| 1 | [CISA KEV](https://github.com/cisagov/kev-data) and [FIRST EPSS](https://www.first.org/epss/data.html), public feeds | Identify CVE findings associated with exploitation in the wild and show exploit-probability context | Medium. These are feeds, not scanners. First preserve CVE/CVSS metadata; cache with timestamps and show stale/unavailable values. A hostname or technology name alone is insufficient for CVE attribution |
| 2 | [cdncheck](https://github.com/projectdiscovery/cdncheck), MIT | Label observed infrastructure as a likely CDN/cloud/WAF provider; improve grouping and explain shared infrastructure | Small–medium. Prefer local matching against pinned provider data and already-resolved addresses. Provider membership does not prove tenant ownership, origin exposure, or a vulnerability |
| 2 | [TLSx](https://github.com/projectdiscovery/tlsx), MIT, already bundled | Add supported-version and bounded weak-cipher enumeration to existing negotiated-TLS metadata | Medium. Upstream exposes version/cipher enumeration and SOCKS proxy options; confirm behavior against the pinned release and gateway. Bound additional handshakes and track incomplete checks |
| 2 | [checkdmarc](https://github.com/domainaware/checkdmarc), Apache-2.0 | Deeper SPF/DMARC validation, lookup budgets, DNSSEC, MTA-STS and TLS reporting | Medium–large. Start with bounded DNS parsing/validation. Resolver protocol compatibility needs proof. Disable SMTP/STARTTLS and third-party fetch behavior unless explicitly supported by the current scope/gateway model |
| 3 | [OWASP Amass](https://github.com/owasp-amass/amass), Apache license with separately licensed subcomponents | A complementary discovery and relationship source | Large. Benchmark incremental discoveries over Subfinder before bundling; upstream sources can overlap or require credentials. Pin the chosen version and validate its data model and egress behavior |
| 3 | [ZAP Baseline](https://www.zaproxy.org/docs/docker/baseline-scan/) / [ZAP core](https://github.com/zaproxy/zaproxy), Apache-2.0 | Optional deeper passive web analysis after bounded spidering | Large. Baseline spiders the target and then performs passive analysis; it still generates requests. Prove chained proxy routing, scope, cancellation, pacing, budgets, and redacted results before enabling |
| 3 | [gowitness](https://github.com/sensepost/gowitness), GPL-3.0 | Opt-in screenshot gallery and visual comparison | Large. Chromium adds memory/process costs and untrusted page execution. All redirects, subresources, DNS, and browser transports must respect gateway scope; screenshots also need sensitive-content retention controls |

Retire.js output reflects identifiable, observed browser libraries, not a complete application SBOM. A matched advisory establishes an affected component/version observation, not proof that an attack is reachable.

FIRST documents free daily EPSS publication, small-batch API lookups, and daily CSV downloads for bulk synchronization. Store score date/model context. KEV membership describes known exploitation of a vulnerability; it does not prove compromise of this workspace's asset. Absence from either feed must not become a clean bill of health.

## Features worth building without another scanner

### Structured changes and drift

Add an append-only observation/change model keyed by target, service, field, and scan. Show added hosts/ports, DNS address changes, certificate changes, and technology changes with before/after values, timestamps, source, and confidence. Group alerts by scan or time window.

The existing union/merge behavior preserves history but is not sufficient for reliable port or technology removal detection. Record observation scope and successful coverage before asserting absence. Keep lifecycle rules intact; failures become unknown, never removed or fixed.

### Explainable prioritization

Keep scanner severity separate from priority. Show CVE identifiers and CVSS provenance, KEV status, dated EPSS, confidence, exposure type, and user-entered business criticality. Findings without a CVE remain actionable using exposure and business context.

Start with transparent priority tiers rather than an unexplained numeric formula. Do not infer confirmed vulnerabilities from banners alone. Expanding valid CVE detection is a prerequisite for feeds to enrich many current findings.

Feed updates need an explicit controlled path: the API currently has no public internet egress, and worker target permits do not authorize arbitrary feed hosts. A bounded feed importer or administrator-supplied snapshots should validate schema/size and publish normalized cache data through an authenticated API. Do not give workers database credentials or generic internet access.

### Ownership, routing, and SLA

Add asset/finding ownership, environment and business-criticality tags, due dates, overdue filters, and grouped notification payloads. Measure time from first observation to triage and verified resolution. Keep accepted risk separate from remediation.

The existing Slack/Discord/generic webhook support is a foundation, not a missing integration. If teams already use [DefectDojo](https://github.com/DefectDojo/django-DefectDojo), its BSD-3-Clause community project provides vulnerability tracking, deduplication, remediation and reporting; consider a focused export/API integration instead of embedding another platform. Preserve stable external IDs and prevent ticket status changes from bypassing Surfacer's verified-resolution rules.

### Classification and relationship view

Classify likely admin/login interfaces, APIs, staging hosts, documentation and metrics surfaces from observed metadata. Show the evidence for each label. An exposed login or API page is not automatically a vulnerability; endpoint parameter hazards remain candidates.

Map domain → host → observed IP → service → technology → endpoint → finding, plus provider/certificate relationships where observed. Shared IPs and certificates are associations, not proof of common ownership or exploit paths. A relational edge model is sufficient initially; a graph database is not required.

### Coverage and trends

Build trends from persisted comparable observations, with clear handling of partial runs and unavailable historical values. Show completed/unchecked checks, newly observed exposures, verified fixes and overdue remediation. Avoid scoring a failed scan as improvement or interpreting finished stages as exhaustive coverage.

## Recommended sequence

1. **Observation quality:** structured change records, uncertainty states for DNS posture, explicit classification confidence, and correct comparable scan baselines.
2. **Detection depth:** reviewed Nuclei additions and offline Retire.js integration, with fixtures and resource budgets.
3. **Prioritization:** CVE/CVSS fields, controlled KEV/EPSS import/cache, explainable priority tiers, and owner-supplied criticality.
4. **Operational value:** drift alerts, ownership/SLA workflow, cdncheck labels and bounded TLSx enumeration.
5. **Optional heavier profiles:** evaluate Amass incremental yield, ZAP Baseline and screenshot capture in isolation before shipping.

Some items can be developed independently, but prioritization must not imply detection coverage that has not been built. Each feature should have its own focused proposal and validation.

## Defer or keep separate

- **Authenticated cloud inventory:** [Prowler](https://github.com/prowler-cloud/prowler) is an open-source cloud security option, but cloud-account assessment needs a separate credential and authorization model. DNS-visible cloud infrastructure is not an inventory of the customer's accounts. Do not add cloud credentials to current scanner workers.
- **Internal lateral movement:** external domain scans cannot establish identity permissions, internal reachability or crown-jewel access paths. Do not label an association graph as a validated attack path engine.
- **AI false-positive elimination:** start with reproducible matchers and evidence confidence. No new external evidence upload or autonomous dismissal is justified by vendor AI claims.
- **Mass scanning, credential guessing or automatic resource claiming:** these do not fit the existing product scope. Takeover observations should remain candidates unless supported by safe, specific evidence.

## Implementation acceptance criteria

For a selected addition, inspect its actual pinned source/CLI and license files; upstream README claims do not establish deployment compatibility. Preserve lease checks, scope, DNS protections, revocation, shared pacing, redaction and interrupted-run checkpoints. Add compatible JSON/PostgreSQL state and public API fields together, with per-check successful/failed/skipped coverage and regression tests. Scanner/template execution changes require the isolated native Linux fixture and gateway-path validation. This research did not install tools, run scanners, access targets, or modify application behavior.
