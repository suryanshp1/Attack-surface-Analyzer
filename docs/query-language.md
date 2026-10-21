# Query filters

Inventory, Endpoints, Findings, Takeovers, Hazards, Changes, and Scan activity use the same visual builder and query language. Open **Syntax & fields** beside the editor for the fields and examples available in that view. Click a field to insert it or an example to edit it, then press **Enter** or **Apply**. Shift+Enter inserts a new line; Escape restores the applied query. **⌘K / Ctrl+K** focuses the active filter editor (or opens Inventory from a view without one).

Queries filter the observations already loaded in the selected target scope. They do not trigger scans, expand domain authorization, or establish assessment completeness. Endpoint source tabs continue to separate live observations from historical, unverified URLs. Sorting and grouping remain separate controls.

## Visual builder

Use **Visual builder** to choose a field, an operator, and a value. Common fields such as severity, finding status and scanner tool offer suggested values; **Custom value…** lets you enter other observations. Number fields offer numeric comparisons, dates offer before/after comparisons with ISO date or timestamp input, and booleans offer true/false. **Has a value** and **Has no value** need no input.

Each group combines its conditions using **All conditions · AND** or **Any condition · OR**. **Add group** nests a separate combination. For example, place `Status equals open` in an AND group, then add an OR subgroup containing `Severity equals critical` and `Severity equals high`. The query preview makes the grouping explicit. Use **NOT** to invert one condition, or **Exclude group (NOT)** to invert a whole group.

Select **Apply** after editing. Incomplete conditions and empty nested groups cannot be applied; the current results and exports continue to use the last applied filter. Remove an unwanted row or group using its labeled remove button. Clear removes the whole applied filter. Escape restores the applied query.

**Query text** edits the same filter. Switching modes preserves parsed AND/OR precedence, nested groups, free-text search, NOT and quoted values. Invalid expressions remain in text mode until corrected. The visual editor supports up to 12 group levels; deeper valid expressions remain editable as text. Back/Forward, refresh, shared URLs, scope and pagination retain the existing applied-query behavior. New empty filters start in the visual editor.

The interaction follows field/operator/value and nested rule-group patterns documented by [React Query Builder](https://react-querybuilder.js.org/docs/components/querybuilder), alongside the structured filtering approach in [Elastic](https://www.elastic.co/docs/explore-analyze/query-filter/filtering). Surfacer uses its existing parser and native form controls without adding a query-builder dependency.

## Syntax

| Expression | Meaning |
| --- | --- |
| `nginx` | Contains this text in any searchable field |
| `tech:nginx` | Field contains text; for arrays, any element matches |
| `status=403` | Exact value |
| `status!=403` | No value equals 403, including records with no response |
| `status>=400 AND status<500` | Numeric range |
| `first_seen>=2026-01-01` | Date comparison; use ISO dates or quoted ISO timestamps |
| `host:*.example.com` | Wildcard pattern; `*` matches zero or more characters |
| `parameter:*` | Field has at least one observed, nonempty value |
| `NOT parameter:*` | Field has no observed value |
| `status:"accepted risk"` | Quote values containing spaces or punctuation |
| `url:"https://example.com/path?a=1"` | Quote URLs and other values with language punctuation |
| `(severity:high OR severity:critical) AND status:open` | Combine alternatives with required conditions |

Text matches ignore case. `:` uses substring matching; `=` uses exact matching. A value containing `*` matches the entire value as a wildcard pattern; use `*text*` to find text anywhere. Wildcards also work with `=` and `!=`. For arrays, `!=` excludes records where **any** element matches. `NOT` binds first, then `AND`, then `OR`; adjacent expressions imply `AND`. Keywords are case insensitive. Quote literal keywords such as `"OR"`. Single and double quotes are supported; backslash escapes the next character inside quotes.

Numeric and boolean fields validate values. Range operators apply only to numbers and dates. Unknown fields and malformed expressions produce a message with a column number. An invalid applied URL query shows no results until corrected; invalid drafts cannot be applied. Results and exports continue to use the last applied query while editing a draft. Missing HTTP responses are absent values, not observed status code zero.

The language is implemented locally without evaluation of code or user regular expressions. Queries are limited to 4,096 characters, 512 tokens, and 32 levels of nesting. It is inspired by [Shodan field filters](https://help.shodan.io/the-basics/search-query-fundamentals) and [Elastic KQL boolean and field syntax](https://github.com/elastic/elasticsearch/blob/main/docs/reference/query-languages/kql.md); it is a Surfacer-specific language, not a full implementation of either.

## Useful queries

```text
# Inventory: alternate HTTPS ports with open findings
(port:443 OR port:8443) AND findings>0

# Findings: open security issues, excluding one technology
status:open AND security:true AND (severity:critical OR severity:high) AND NOT tech:nginx

# Endpoints: observed errors with a named parameter
status>=400 AND parameter:redirect

# Takeovers: reopened candidates
reopens>0 AND status:open

# Hazards: review priorities, not confirmed vulnerabilities
(class:ssrf_candidate OR class:redirect_candidate) AND severity:high

# Scan activity: interrupted or unsuccessful assessments
status:partial OR status:failed OR status:canceled
```

The comment lines above explain the examples; comments are not part of the language. Inventory `findings` counts open findings for the host, and `exposure` accepts `exposed` or `clear` based on that count. Findings `security` uses the same security-issue classification as the overview. An absent finding category is treated as `vulnerability`.

## URLs and older links

Applied queries are stored in the URL's `q` parameter alongside target scope, pagination, sorting, and selected details. Apply and Clear create history entries, so Back/Forward and refresh restore the applied query. Draft text is not stored until applied. URLs may reveal the query to someone you share them with; do not include credentials or sensitive evidence in queries.

Old technology, port, exposure, endpoint kind, finding status/category/severity, takeover status, hazard class, change kind, and scan status parameters are converted to visible query clauses when their view opens. The next navigation writes the query representation. Old query text is interpreted using the new language; quote phrases or URLs if needed. Empty queries now show all records in scope, including resolved findings and inventory observations; use `status:open AND security:true` for the former default Findings view. Overview severity links supply that expression explicitly.
