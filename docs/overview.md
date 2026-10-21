# Overview dashboard

The homepage helps a workspace member decide what to review, what changed, and which assessments need follow-up. It uses the loaded workspace snapshot and selected target scope. It does not calculate an overall security score or infer historical risk totals from current findings.

## Widgets and definitions

- **Discovered hosts:** retained, non-removed assets in scope. The 24-hour figure counts first-seen observations, not net growth or successful HTTP responses.
- **Open security issues:** open findings with the existing security classification: absent/vulnerability category or secret category. Inventory observations and heuristic candidates are separate. Affected hosts are distinct, case-normalized hostnames, including findings retained after partial scans.
- **High / critical aged 30+ days:** open high/critical security issues first observed at least 30 elapsed days ago. This is a review threshold, not a configured remediation SLA or proof of continuous exposure. The card opens an equivalent query in Findings.
- **Latest runs completed:** selected targets whose latest attempt has completed, without explicit unfinished stages or coverage gaps. Earlier completed runs do not hide a newer partial, failed, canceled, or active attempt. This is an execution summary, not a percentage of the attack surface assessed.
- **Additional review queues:** open takeover candidates, parameter hazard candidates, and domains with missing/permissive SPF or missing/monitor-only DMARC policy. These are separate review categories, not confirmed exploitable vulnerabilities. A dataset absent from the snapshot is unavailable; a present empty dataset has zero recorded observations.

## Charts

**Open issues by severity and age** uses the current open security findings. The rows include critical, high, medium, low, informational, and unrecognized severity values. Bar lengths share one count scale. Segments distinguish under 7 days, 7–29 days, 30+ days, and unavailable age; unknown or future first-seen timestamps are not treated as new issues. Selecting a row opens its findings. Accessible row descriptions and an expandable data table expose every age count.

**Recorded surface changes** groups retained events into UTC calendar days, with a selectable 7- or 14-day window including today. The selected period is stored in the URL and restored by Back/refresh. The stacked bars separate asset discovery, new finding, resolution, and other events, with numeric count axes and dated labels. These are event counts, not numbers of currently open issues or a net asset trend. Future and malformed timestamps are excluded. A zero means no retained events in the bin, not proof that nothing changed. Daily values are also available as a table.

Selected-target event attribution matches hostname references in event details with domain boundaries. It excludes lookalike domains such as `notexample.com` and `example.com.evil.test` from `example.com`. Events with no domain reference remain visible under All targets. This applies to Changes and the homepage so their scoped records agree.

**Observed web responses** classifies unique service URLs into 2xx, 3xx, 4xx, 5xx, and no classified response. Older assets may supply their primary observed URL when a per-service collection is unavailable. A host without an observed URL does not create an inferred web service. Error and missing responses are neither proof of a vulnerability nor proof of absence; observations can have different timestamps.

## Follow-up and drilldowns

The target table includes targets regardless of scan readiness. It shows hosts, observed service URLs, open security issues, the latest attempt, prior completed-run context, and HTTP/detection counters. HTTP counts service origins; detection counts required service/template pairs. Unavailable legacy counters are labeled explicitly. Zero eligible checks are identified separately from unfinished work. Open a scan to inspect crawl, port, stage, exclusion, and service-specific diagnostics.

Domain and issue links preserve target scope and use the query language. Priority issues sort by severity and then oldest first-seen timestamp. The recommended action points to priority findings, open takeover candidates, assessment follow-up, or target setup. Scan actions respect role, workspace pause, and target readiness.

## Design rationale and sources

[Microsoft Defender EASM dashboard guidance](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/understanding-dashboards) informed the separation of surface composition, actionable observations, and inventory drilldowns. Surfacer uses its own available observations and does not imply the vendor's discovery or intelligence coverage.

[W3C's accessible table guidance](https://www.w3.org/WAI/tutorials/tables/) informed chart data tables with captions, column/row headers, and readable numerical alternatives. Labels, values, and patterns supplement chart colors. All widgets use the existing light/dark theme tokens.

See [scanning and coverage](scanning.md) for bounded profiles and lifecycle rules, and [query filters](query-language.md) for the expressions used by drilldowns.
