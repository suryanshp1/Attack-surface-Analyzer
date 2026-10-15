PRD: Web Attack Surface Analyzer
13 Oct 2026 · @Suryansh
1. Overview
Web Attack Surface Analyzer (working name: Surfacer) continuously discovers every internet-facing asset a team owns, finds exposures on them, and shows what changed since the last scan. It is built only on open-source scanners, with a Go backend, a Next.js frontend, and Docker for deployment.
Problem. Teams do not know their full external footprint. Subdomains, forgotten staging sites, open ports, stale certificates and exposed files appear and disappear faster than manual reviews can track. Commercial ASM tools solve this but are costly and closed. Existing OSS tools (nuclei, subfinder, httpx and others) are powerful but are CLIs: no ownership checks, no history, no UI, no safe multi-user operation.
Product vision. A self-hostable platform that turns the OSS recon ecosystem into a safe, always-on service: prove you own a domain, get an inventory within minutes, see new exposures as they appear, and track each finding until it is fixed.
Scope of this PRD. The first production release (MVP) plus the next two phases. It covers external, black-box discovery and detection against assets the customer has verified. It does not cover exploitation, internal network scanning, or source-code analysis.
Optional AI triage. Findings can be scored by Jev, a hosted decision model from TypeSafe AI that returns typed answers (a yes/no probability, a score or a choice) with a confidence value. Jev is proprietary and cannot be self-hosted, so it is an optional plugin that is off by default; the core product must work with open-source tools alone. Section 15 records how this PRD changed after reviewing a second research report.
2. Goals, non-goals and success metrics
The MVP succeeds if a new user can verify a domain and see a trustworthy asset inventory with prioritized findings in their first session, and if scans never touch anything the user does not own.
Goals
1. Safe by construction. No scan traffic reaches a target whose ownership is unverified, and no scan can reach private or cloud-metadata addresses.
2. Fast time to value. Verified domain to first inventory in under 15 minutes for a typical small organization.
3. Continuous visibility. Scheduled rescans produce a change feed: new and removed assets, new ports, new and resolved findings.
4. Actionable, low-noise findings. Technology-targeted detection, severity filtering, and a clear finding lifecycle.
5. Self-hostable with OSS only. One docker compose up for a single node; no proprietary scanner or paid API required for core features.
6. Replaceable parts. Each scanner sits behind an adapter so a tool can be upgraded or swapped without schema changes.
Non-goals (v1)
• Exploitation, brute-forcing, credential stuffing, or any intrusive or denial-of-service testing.
• Internal network, agent-based, or authenticated application scanning (considered for a later phase).
• Source-code analysis (SAST) and dependency scanning.
• Scanning assets the customer has not verified, including third-party or competitor targets.
• Replacing a full pentest or a managed vulnerability-management suite.
• Evading or bypassing WAFs and other defenses: no stealth modes and no rotating identities to dodge filters.
• Sending finding evidence to any third-party service without explicit org opt-in and redaction.
Success metrics
Metric
Target
How measured
Time from verified domain to first inventory
under 15 min (p50)
Scan stage timestamps
Scans started against unverified targets
0
Audit log plus integration test in CI
Egress to private or metadata ranges
0
Firewall drop counters and dial-time check logs
Findings marked false positive by users
under 15% of open findings
Finding status changes
Scan completion rate (no stage failure)
at least 95%
Scan status
Weekly active orgs with a scheduled scan
tracked from launch; set a target after beta
Product analytics
3. Users and personas
Three personas drive the MVP; the first is the primary buyer and daily user.
Persona
Context
Top jobs to be done
Security engineer (primary)
Small to mid-size security team, owns external exposure
See every public asset; know what changed this week; triage and track fixes
DevOps / platform engineer
Ships and runs sites and APIs
Find forgotten subdomains and open ports before attackers do; get alerts when a deploy exposes something
Engineering manager or CTO
Accountable for risk, not tooling
Understand overall exposure at a glance; export a report for audits or customers
Out of scope as users (v1): bug-bounty hunters scanning third-party programs. The ownership gate deliberately blocks this use.
4. User stories
Stories are grouped by epic. P0 ships in the MVP, P1 in the following phase, P2 later.
ID
Epic
Story
Priority
US-01
Onboarding
As a security engineer, I add a root domain and prove ownership with a DNS TXT record so scans are allowed.
P0
US-02
Onboarding
As a user, I can use an HTTP file or meta tag instead of DNS if I cannot edit DNS.
P1
US-03
Discovery
As a user, I see all subdomains, resolved IPs and live web services found for my domain.
P0
US-04
Discovery
As a user, I see technologies, titles, status codes and TLS details for each web service.
P0
US-05
Discovery
As a user, I add my own IP ranges after verifying ownership, and the platform scans their open ports.
P1
US-06
Detection
As a user, I get findings from curated nuclei templates matched to the technologies on each host.
P0
US-07
Detection
As a user, I see endpoints, forms and exposed JavaScript secrets discovered by crawling.
P1
US-08
Findings
As a user, I change a finding's status (open, accepted risk, false positive) with a note.
P0
US-09
Findings
As a user, a finding auto-resolves only after it is absent from several consecutive successful scans.
P0
US-10
Change tracking
As a user, I see a feed of new and removed assets, new ports and new findings since the last scan.
P0
US-11
Scheduling
As a user, I schedule daily or weekly rescans and cancel a running scan at any time.
P0
US-12
Alerts
As a user, I get Slack, email or webhook alerts for new critical or high findings and new assets.
P1
US-13
Reporting
As a manager, I export an inventory and findings report as PDF or CSV.
P1
US-14
Teams
As an admin, I invite teammates with roles (owner, analyst, viewer).
P1
US-15
Audit
As an admin, I see who scanned what, when and with which settings.
P0
US-16
Integrations
As a developer, I use an API key to read assets and findings.
P1
US-17
Scale
As an admin, I add more workers to speed up scans.
P1
US-18
Triage
As an analyst, I can opt in to AI triage that ranks findings and suggests likely false positives, and I can override every suggestion.
P2
US-19
Prioritization
As a user, I see KEV status and EPSS score next to CVE-based findings.
P1
US-20
Discovery
As a user, I see historical URLs for my domains from public archives, clearly marked as historical.
P1
5. Functional requirements
Every requirement has an ID and a testable acceptance criterion. Priorities follow the user stories.
ID
Requirement
Acceptance criterion
Pri
FR-01
Target management: add a root domain, show a unique verification token and instructions.
Token is at least 128 bits, unique per org and domain, shown with the exact TXT record name and value.
P0
FR-02
DNS TXT verification: check the record on demand and on a schedule.
Domain flips to verified only when the record matches; scanning pauses automatically if later checks fail.
P0
FR-03
Subdomain scope: verified root covers its subdomains; each resolved IP is checked before any active step.
A subdomain resolving to an IP outside allowed space is listed but not actively scanned.
P0
FR-04
Scan orchestration: a scan is a set of stage jobs with retries, timeouts and resumability.
A killed worker mid-stage leads to the stage retrying on another worker without duplicating results.
P0
FR-05
Discovery stage: passive subdomain enumeration and DNS resolution.
Only names that resolve are stored as active assets.
P0
FR-06
Probing stage: HTTP probing with technology detection and TLS data.
Each live service stores URL, status, title, technologies, certificate expiry.
P0
FR-07
Detection stage: nuclei run with technology-targeted templates from a curated, signed set.
Run excludes dos, intrusive and fuzz tags; unsigned templates do not execute.
P0
FR-08
Normalization: every tool output becomes typed assets and findings with a stable fingerprint.
The same issue in two scans yields one finding with updated last_seen.
P0
FR-09
Change detection: compute diffs between consecutive successful scans.
Feed lists new, removed and changed assets and findings with timestamps.
P0
FR-10
Finding lifecycle: open, accepted risk, false positive, resolved.
Auto-resolve needs N consecutive clean successful scans of that host (default N=2). Partial or failed scans never resolve findings.
P0
FR-11
Scheduling and control: daily, weekly or manual runs; cancel at any time.
Cancel stops all child processes within 10 seconds.
P0
FR-12
Rate controls: per-target request rate and concurrency caps.
Defaults at or below 30 requests per second per target; org admins can lower but not exceed the platform maximum.
P0
FR-13
Evidence: store request and response snippets for findings with size caps and secret redaction.
Evidence over the cap is truncated; known secret patterns are masked in the UI.
P0
FR-14
Audit log: record target, user, settings and tool versions for every scan.
Log is append-only and visible to org admins.
P0
FR-15
Crawling and JS analysis (katana plus gitleaks over crawled JS).
Crawl is confined to verified hosts; secrets found are masked and flagged.
P1
FR-16
Port scanning on verified IP ranges (naabu).
Ports are scanned only on IPs inside verified ranges.
P1
FR-17
Alerts via Slack, email and webhook with per-severity rules.
A new critical finding triggers an alert within 5 minutes of scan completion.
P1
FR-18
Reports: PDF and CSV export of inventory and findings.
Export matches on-screen filters.
P1
FR-19
Teams and roles: owner, analyst, viewer.
Viewers cannot change findings or start scans.
P1
FR-20
Public API with API keys, generated OpenAPI spec and TypeScript client.
All UI actions available via the API.
P1
FR-21
Scanner attribution: every HTTP request from scanners carries a deterministic X-Scanner header with the platform name and scan id.
Header present on all tool traffic in integration tests; a published page explains how a target's SOC can allowlist it.
P0
FR-22
Graceful shutdown and cooperative cancel: on SIGTERM a worker stops taking jobs, cancels running tools through context cancellation, flushes output and returns the job for retry.
A worker stopped mid-scan leaves no orphaned process; the job resumes on another worker within 60 seconds.
P0
FR-23
Untrusted output handling: all tool output (headers, bodies, titles, payloads) is escaped on render, size-capped and never rendered as HTML.
Test pages containing script payloads show as inert text in every UI view and export.
P0
FR-24
Asset provenance: store which source discovered each asset (for example subfinder's per-source output).
Asset detail lists its sources and first discovery time.
P0
FR-25
Intelligence enrichment: add CISA KEV status and EPSS score to CVE-based findings.
Fields refresh daily and appear in the findings list and API.
P1
FR-26
Historical URL discovery from public archives (gau).
Historical URLs are flagged as such and used as crawl seeds only inside verified scope.
P1
FR-27
Optional AI triage plugin behind an adapter (Jev first): off by default, org opt-in, only redacted fields sent, suggestions never resolve or delete findings, analysts can override.
Disabling or losing the plugin changes no core behavior; every suggestion is logged with its confidence and the analyst's final decision.
P2
6. Safety, legal and abuse-prevention requirements
These are release blockers: the product sends attack-like traffic, so weak controls create legal and reputational risk for customers and for us. Nothing in this section is a P1 or later.
Ownership verification (SAF-1 to SAF-5)
1. DNS TXT is the primary proof; HTTP file or meta tag is the fallback. Tokens are random, per-org and per-domain.
2. Verification is re-checked on a schedule and again at scan start. If the proof disappears, scanning for that target pauses.
3. A verified root covers its subdomains. IP addresses and CIDR ranges use a separate flow with ASN or WHOIS confirmation.
4. Domains on a public-suffix list, and well-known third-party platforms, cannot be claimed as roots.
5. Every verification and scan action is written to the audit log.
Network safety (SAF-6 to SAF-10)
6. Workers run on a dedicated Docker network whose host firewall drops loopback, RFC 1918, link-local and cloud-metadata destinations.
7. Every outbound connection is checked at dial time with a custom dialer, after DNS resolution and after each redirect; blocked addresses fail closed.
8. Workers cannot reach the database, queue or object store directly; they talk to the API over an authenticated channel.
9. No container receives the Docker socket or elevated host privileges.
10. DNS resolution for scans uses a pinned resolver so results cannot be steered by the target.
Scan safety (SAF-11 to SAF-15)
11. Active detection excludes dos, intrusive and fuzz template tags. There is no brute-force or credential-guessing capability.
12. Only curated, signed templates run in production; community templates are reviewed before they enter the set.
13. Per-target rate and concurrency limits, plus a global cap per worker.
14. A kill switch cancels any scan immediately; an org-level and a platform-level pause exist.
15. Out-of-band testing uses a self-hosted interactsh server, not a third-party one.
Abuse handling (SAF-16 to SAF-18)
16. Terms of use require the user to be authorized to test every verified asset.
17. A published abuse contact and a way for a target owner to opt out a domain from scanning.
18. Anomaly alerts: many new targets added quickly, or verification flapping, triggers review.
Scanner identity and third-party data (SAF-19 to SAF-22)
19. Scanners identify themselves with a deterministic X-Scanner header, and the platform publishes how target owners can recognize and allowlist it.
20. No evasion: no rotating identities or tricks to get past WAFs. When a target throttles or blocks, the scan backs off and reports the host as blocked.
21. Finding evidence stays inside the deployment unless an org opts in to an external service, and only redacted fields leave.
22. OSINT provider keys (Shodan, Censys, GitHub and similar) live in a secret store, are injected at run time, never baked into images, and are rate-limited per source to respect quotas.
Note: this section is an engineering requirement list, not legal advice. Terms of service and regional law need counsel review before launch.
7. Scan pipeline specification
A scan runs eight stages in order; each is its own retryable job that writes normalized rows to Postgres, so a failure never loses earlier work.
Each stage reads the previous stage's output from the database, not from files, so any stage can resume on another worker.
Stage defaults
• Rate: 10 to 30 requests per second per target. Nuclei's own default of 150 is overridden.
• Detection: technology-targeted templates through nuclei's automatic scan mode; excludes dos, intrusive and fuzz tags; JSONL output.
• Crawl scope: verified hosts only, with in-scope and out-of-scope patterns set per target.
• Timeouts: every stage has a hard timeout; the worker kills the whole process tree on cancel.
• Evidence: request and response snippets are size-capped, redacted and stored in object storage.
Additional stage rules
• Discovery sources: subfinder runs with a provider config, per-source rate limits (-rls), JSON output and source collection (-cs) so every asset keeps its provenance.
• Attribution: nuclei adds the X-Scanner header with -H; the other tools get the same header through their own custom-header options once confirmed per tool.
• Out-of-band checks: nuclei points to a self-hosted interactsh server with -iserver and -itoken. Older write-ups use -interactsh-url, the previous flag name.
• Severity: findings below medium are stored as asset data, not alerts, unless the org lowers the threshold.
• Throttling: on repeated errors or blocks a stage lowers its rate and records the host as blocked; it never tries to evade.
• Historical URLs (P1): gau output is stored as historical and used as crawl seeds only inside verified scope.
8. Architecture and tech stack
The Next.js app is a pure frontend; a Go API owns auth, scope rules and scheduling, and Go workers run the scanners behind a filtered network path.
The highlighted egress filter is the one component that every scan packet must pass; it is a release blocker (section 6).
Layer
Choice
Rationale
Frontend
Next.js 16, App Router
UI only. Uses proxy.ts instead of middleware; request APIs are async; authorization is repeated inside every handler.
Backend
Go with chi or the standard router, pgx plus sqlc, goose or atlas migrations
Most scanners are Go; one static binary per service; typed queries.
Queue
River on Postgres (alternative: a Redis-based queue)
Fewer moving parts for v1. See open questions.
Live updates
Server-sent events from the API
Simple, proxy-friendly progress for the UI.
Storage
Postgres plus MinIO or S3
Relational data in Postgres; raw output and evidence in object storage.
Workers
Docker service scaled horizontally, one pinned scanner image
Tool binaries and templates versioned together; tools run as subprocesses with JSONL output.
API contract
OpenAPI, with a generated TypeScript client
One source of truth for web and API clients.
Deployment
Docker Compose on one node for v1
Kubernetes jobs considered in a later phase.
Scanners start as pinned subprocesses with JSONL output. Selected tools move to their Go libraries only where tighter control, such as rate limiting and result callbacks, justifies the extra dependency weight.
9. Data model
Postgres is the system of record. Raw tool output and evidence go to object storage (MinIO or S3) and are referenced by key.
Entity
Key fields
Notes
orgs, users, memberships
org_id, role
Roles: owner, analyst, viewer
targets
root domain or CIDR, token, verification_method, verified_at, last_verified_at, status
Status: pending, verified, paused, revoked
scans
scan_id, target_id, trigger, status, started_at, finished_at, config snapshot
Config snapshot stores rate limits and template set version
scan_stages
stage name, status, attempts, tool versions, timings
One row per stage job; drives resume and retry
assets
type (domain, ip, service, url, tech), canonical key, attributes (JSONB), first_seen, last_seen
Unique on (org, type, canonical key)
findings
fingerprint, template id, severity, host, matched_at, status, first_seen, last_seen, evidence_key
Fingerprint = hash(template id, host, matched_at)
asset_events, finding_events
event type, before and after, scan_id, at
Powers the change feed and alerts
audit_log
actor, action, target, settings, at
Append-only
Lifecycle rules
• An asset or finding seen in a scan gets last_seen updated; a new fingerprint gets first_seen set and emits a created event.
• An asset is marked removed only after it is absent from N consecutive successful scans of its target.
• A finding auto-resolves only after N consecutive successful scans that covered its host and did not see it. Default N is 2.
• A scan with any failed or timed-out stage is marked partial and never closes assets or findings.
• A finding in accepted-risk or false-positive status stays suppressed until its fingerprint changes.
10. UX: key screens and flows
The UI answers three questions in order: what do we own, what changed, what is wrong.
Screen
Purpose
Key elements
Target setup wizard
Add and verify a domain
Token, copyable DNS record, Check now button, clear failure reasons
Inventory
See the whole surface
Filters by type, technology, port and age; per-asset detail with history
What changed
Review the delta
New and removed assets, new ports, new and resolved findings, certificates expiring soon
Findings
Triage
Severity filter, status workflow, notes, evidence viewer with redaction
Scan activity
Trust and control
Live stage progress over server-sent events, cancel button, per-stage logs
Settings
Govern
Schedules, rate limits, alert rules, members, API keys, audit log
UX principles
• Raw HTTP evidence stays behind a click and is size-capped.
• Every finding shows why it matched, when it was first seen, and how to confirm it.
• Empty and failed states explain what to do, especially verification failures.
• Accessible by default: keyboard navigation and sufficient contrast.
11. Non-functional requirements
Area
Requirement
Security
Secrets in a secret store, not images; TLS everywhere; password-less or MFA-capable auth; per-org data isolation enforced in every query; dependency and image scanning in CI.
Container hardening
Non-root user, read-only root filesystem, all capabilities dropped (port scanning gets only what it needs, in its own stage), CPU, memory and PID limits, hard job timeouts. Headless Chrome runs in its own container with a seccomp profile.
Performance
A small-organization scan (up to 200 hosts) finishes in under 30 minutes on one worker; UI pages load in under 2 seconds at p95 for 10,000 assets.
Scalability
Workers scale horizontally with no code change; stages are idempotent; per-org concurrency limits prevent noisy neighbors.
Reliability
Retries with backoff; stuck-job recovery; scans are resumable; 99.5% API availability target for the hosted offering.
Observability
Structured logs, metrics (queue depth, stage duration, error rate, blocked-egress count) and traces across API and workers.
Compatibility
Pinned scanner versions and template set per release; adapters tolerate tool output changes; upgrade tests run on recorded sample outputs.
Data retention
Configurable retention for raw evidence (default 90 days); findings and audit log kept longer; org deletion removes all data.
Privacy and compliance
No collection of data from target sites beyond what findings need; evidence redaction; documented subprocessors if hosted.
Image build
Multi-stage builds with a minimal or distroless runtime image and no compilers in production. The raw-socket capability is granted with setcap to the port scanner binary only; everything else runs as a non-root user.
Idempotency
Jobs use deterministic IDs derived from target and scan, so retries never duplicate data. If a Redis queue is chosen, it must run with a no-eviction memory policy and append-only persistence.
Database access
Separate database roles for the application and for migrations; parameterized queries only; every API payload validated against a schema before it reaches a query.
12. Open-source tool matrix and licensing
Pin every tool by version and verify each repository's LICENSE before shipping. Rows marked verify were not confirmed during research.
Stage
Tool
License
Use in v1
Note
Subdomain discovery
subfinder
verify (ProjectDiscovery, expected MIT)
Yes
Passive sources; some need API keys
Subdomain discovery
OWASP Amass
Apache-2.0
P1
v5 stores results in an asset database; read the DB, not text output
Subdomain discovery
BBOT
verify
P2
80+ modules, JSON output
DNS
dnsx
verify
Yes
Resolution and CNAME checks
ASN and CIDR
asnmap
MIT
P1
CLI needs a ProjectDiscovery API key
HTTP probing
httpx
verify
Yes
Technology detection, JSON output
TLS
tlsx
verify
Yes
Certificates and ciphers
Ports
naabu
verify
P1
Verified IP space only
Crawling
katana
verify
P1
Headless mode available; confine scope
Vulnerability detection
nuclei
MIT
Yes
Templates are community-maintained; sign the curated set
Secrets
gitleaks
MIT
P1
Preferred over TruffleHog
Secrets
TruffleHog
AGPL-3.0
No
Copyleft applies to network services
Service detection
Nmap
NPSL
No
License restricts redistribution inside containers or products
Deep DAST
ZAP
Apache-2.0
P2
Now maintained by Checkmarx; use the Automation Framework
Historical URLs
gau
verify
P1
Queries public archives such as the Wayback Machine; passive
Out-of-band checks
interactsh
verify
P1
Self-host; do not default to public servers
Prioritization data
CISA KEV and EPSS feeds
Public data; verify terms
P1
Daily refresh
AI triage (optional)
Jev (TypeSafe AI)
Proprietary, hosted only
P2, off by default
No open weights or self-hosting; early access since September 15, 2026
13. Release plan and milestones
The MVP is phases 1 and 2, about six weeks; the safety controls land in phase 1, before any scan reaches a real target.
Gate
Exit criteria
Safety tests pass
CI proves zero scans on unverified targets and zero connections to private or metadata ranges; every scan appears in the audit log.
MVP beta-ready
First inventory under 15 minutes (p50) on test orgs; nuclei excludes dos, intrusive and fuzz tags; finding lifecycle verified with partial-scan test cases.
Private beta
Crawl, ports, alerts, reports and roles work end to end; false-positive rate is tracked against the 15% target.
Public launch
Load test meets the non-functional targets; abuse process and terms reviewed by counsel; documentation published.
MVP scope cut. Everything marked P0 in sections 4 and 5 ships in the MVP. Everything marked P1 waits for phase 3 or 4; P2 items (BBOT, ZAP, authenticated scanning) are not scheduled.
14. Risks, mitigations and open questions
Risk
Impact
Mitigation
Weak ownership verification enables unauthorized scanning
Legal exposure, abuse
Verification is a release blocker; scheduled re-verification; audit log; abuse process
Scanner traffic reaches internal networks (SSRF-style)
Data exposure, internal scanning
Network-level egress drops plus dial-time IP checks after DNS and redirects
False positives erode trust
Churn, alert fatigue
Technology-targeted templates, severity filters, verified and unverified labels, easy suppression
Poisoned or buggy community templates
Code execution or bad traffic
Curated, signed template set; unsigned templates disabled; review process
Upstream tool changes or licensing shifts
Breakage, compliance risk
Adapters, pinned versions, recorded-output upgrade tests, license review in CI
Scans harm small targets
Outages, complaints
Low default rates, backoff on errors, concurrency caps, kill switch
Hosting costs grow with scan volume
Margin pressure
Per-org quotas, incremental rescans, shared evidence storage with retention limits
AI triage vendor is early access and hosted only; terms, signups or behavior may change
Feature breaks or becomes unavailable
Optional adapter, off by default, no core dependency; test on labeled findings before relying on it
Evidence sent to a third-party AI service exposes customer data
Data leak, loss of trust
Per-org opt-in, field-level redaction, audit log of every call
Stealth or evasion features create legal and ethical exposure
Abuse claims, blocked scans
Attributable scanning with a published header; back off instead of evading
Open questions
• Is v1 self-hosted only, or also a hosted SaaS? This changes billing, tenancy and compliance scope.
• Which auth approach: email and password with MFA, OAuth only, or SSO from day one?
• Queue choice: River on Postgres (fewer services) or a Redis-based queue (richer flow features)?
• Do we need authenticated scanning in the first year, or is public-surface coverage enough?
• What is the official policy for opt-out requests from third-party target owners?
• Do we integrate Jev in the first year? It is early access, and one source reports new signups paused in late September 2026.
• What labeled data will we use to test AI triage before any automatic labeling is enabled?
• Which Slack and Jira features are needed at launch, and which can wait?
Sources (search results reviewed during research): Nuclei releases, exact-surface, Open-ASM, gridscan, LWN on the Nmap license, TruffleHog license notes, Detectify asset verification, Crawlee on SSRF. Information as of October 2026.
15. Changes from the second research report
A second research report on the same idea was reviewed on October 13, 2026. This PRD adopts its operational detail but keeps the Go backend, the verification-first safety model and an open-source-only core.
Correction. Earlier I read "jev" as a typo. It is Jev, a model from TypeSafe AI released on September 15, 2026, and it is now an optional plugin in this PRD.
About Jev (as of October 2026). TypeSafe describes Jev as a hosted decision model with three question types: a yes/no probability (called noul), a score and a choice. It accepts text input only, returns no explanations, has no open weights or self-hosting option, and was priced at $0.042 per million input tokens with free output. Access was early access behind a waitlist, and one source reports new signups paused in late September 2026. Its speed and cost multiples are vendor claims that I did not verify.
Report item
Decision
Reason
Next.js control plane, Docker, Go scanner binaries
Kept
Matches this PRD.
Node.js, BullMQ and Prisma backend
Not adopted
The backend is Go; River on Postgres replaces BullMQ, which stays an alternative (section 8).
Multi-stage builds, minimal image, setcap on the port scanner
Adopted
Added to section 11.
Subfinder per-source limits, JSON output, source collection, provider config
Adopted
Flags confirmed in the subfinder README; added to section 7 and FR-24.
Katana plus gau for endpoint discovery
Adopted
gau is P1 (FR-26).
Nuclei tag and severity filters, rate limits
Adopted with changes
dos, intrusive and fuzz tags stay excluded, and the default stays 10 to 30 requests per second, not 100 with 20 concurrent.
Stealth throttling and User-Agent randomization to avoid WAFs
Not adopted
Conflicts with authorized, attributable scanning; scans back off and report blocked hosts (SAF-20).
X-Scanner attribution header
Adopted
FR-21 and SAF-19.
Self-hosted interactsh
Adopted, flag corrected
Current nuclei help lists -iserver and -itoken; -interactsh-url is the older name.
Graceful shutdown and cooperative cancellation
Adopted
FR-22, using Go context cancellation.
Redis no-eviction policy and AOF
Conditional
Applies only if a Redis queue is chosen (section 11).
Output sanitization, schema validation, least-privilege database roles
Adopted
FR-23 and section 11.
KEV and EPSS enrichment
Adopted
FR-25, P1.
Attack surface graph, trend and MTTR charts, Jira tickets
Deferred
Useful, not scheduled; candidates for P2.
Jev as the built-in triage layer
Changed to optional plugin
Proprietary, hosted only and early access; conflicts with the open-source-only goal and sends evidence to a third party (FR-27, SAF-21).
Auto-suppress findings when false-positive confidence exceeds 0.90
Changed
Suggestions only; never resolve or delete. Automatic labeling is considered only after validation against analyst-labeled findings.
Validating exploitability and exploitation
Not adopted
Non-goal; nuclei detects and the product does not exploit.
Report omits ownership verification
PRD keeps it
Verification stays a release blocker (section 6).
Not verified. The report's tool nuclei-cve-analyzer and its Go image version were not checked, so neither appears in this PRD.
Where the PRD changed: sections 1, 2, 4, 5, 6, 7, 11, 12 and 14, plus this section.
Additional sources (search results reviewed October 13, 2026): TypeSafe System One docs, TypeSafe launch post, TrueFoundry on Jev hosting, Jev in Node.js, subfinder README, nuclei help listing.