## Summary

<!-- Provide a concise description of the change, the problem it solves, and the motivation. -->

## Subsystem & Scope

<!-- Check the relevant subsystem(s) adhering to repo conventions: -->
- [ ] `web` (Next.js App Router, React, Tailwind, UI components)
- [ ] `api` (Go API handlers, access control, jobs, scheduler)
- [ ] `worker` (Scanner execution, crawling, normalization, checkpoints)
- [ ] `gateway` (Egress controls, DNS rebinding guards, signed permits)
- [ ] `storage` (PostgreSQL schema, MinIO/S3 evidence, migrations)
- [ ] `scanners` (Curated templates, scanner version bumps, manifests)
- [ ] `docs` (Architecture, operations, scanning guides)

## Description of Changes

<!-- Detailed bullet points of what code or configuration was changed and why. -->
- 

## Security & Architecture Invariants

<!-- Confirm compliance with Surfacer scanning and trust boundary invariants (see AGENTS.md): -->
- [ ] **Scope Integrity**: Active scanner traffic strictly respects destination domain and subdomain scope boundaries.
- [ ] **Gateway Path**: Scanner traffic uses authorized gateway egress; no direct internet fallback or host networking introduced.
- [ ] **Evidence Redaction**: Discovered credentials, session tokens, or raw secrets are redacted and capped before persistence.
- [ ] **Lifecycle Rules**: Finding/asset resolution adheres to required scan verification counts (e.g. 2 successful scans).
- [ ] **Credential Safety**: No `.env`, private keys, bootstrap owner tokens, or live credentials included in this PR or commit history.

## Breaking Changes & Migrations

- [ ] This PR contains database schema changes or data migrations (verified compatibility with `backend/schema.sql` and restricted role).
- [ ] This PR modifies public API signatures (`public/openapi.json` and `lib/types.ts` updated).
- [ ] No breaking changes.

## Verification & Test Evidence

<!-- Provide the exact commands executed and copy-paste summary of results. -->
```bash
# Frontend validation
npm run typecheck
npm run build

# Backend unit and regression suite
npm run test:api
# Or focused test:
# cd backend && go test -race -run '^TestName$' .
```

Output:
```text
<!-- Paste terminal test output here -->
```

## UI Changes (if applicable)

<!-- If this PR alters the UI, attach screenshots or screencasts for both Light and Dark modes. -->
| Light Mode | Dark Mode |
|---|---|
| <!-- Add screenshot --> | <!-- Add screenshot --> |

---
*By submitting this pull request, I confirm that my contribution is made under the Apache-2.0 license as outlined in [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).*
