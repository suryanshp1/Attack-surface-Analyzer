# Complete Removal of Jev Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Completely eliminate all references, UI placeholders, CSS rules, and documentation artifacts regarding the third-party proprietary "Jev" decision model and hosted AI triage from Surfacer.

**Architecture:** Remove the inactive "Optional AI triage" placeholder card from `components/workspace.tsx`, delete orphaned `.integration-off` styles from `app/globals.css`, update privacy/security copy in the Help modal, sanitize operational documentation (`README.md`, `docs/scanning.md`), and update `PRD.md` to reflect the formal architectural decision rejecting external hosted models.

**Tech Stack:** Next.js 16 App Router, React 19, Tailwind CSS v4 / Vanilla CSS tokens, TypeScript 5.9, Markdown.

## Global Constraints
- Do NOT break or alter manual finding triage (`triage_finding`, `hazards-view.tsx`, `takeovers-view.tsx`, `backend/mcp.go`), which is an active core capability for human analysts.
- Keep the MCP server integration intact (which allows self-hosted AI clients to query inventory with explicit analyst tokens).
- Maintain 100% test pass on `npm run typecheck`, `npm run build`, and `npm run test:api`.
- Preserve clean git history with focused, conventional commit messages.

---

### Task 1: Remove Jev UI Block and Clean Orphaned CSS

**Files:**
- Modify: `components/workspace.tsx:3211-3228`
- Modify: `components/workspace.tsx:1191-1196`
- Modify: `app/globals.css:2015-2038, 2679-2685`

**Interfaces:**
- Consumes: Workspace Settings tab and Help modal component structure.
- Produces: Cleaned General Settings tab (Appearance, Workspace Details, Data Retention) and self-contained Help modal copy without dangling AI triage references.

- [x] **Step 1: Verify current typecheck and build pass**

Run: `npm run typecheck`
Expected: PASS

- [x] **Step 2: Remove the Optional AI triage card and update Help modal in `components/workspace.tsx`**

Remove the `settings-section` block containing "Optional AI triage" and Jev. Update Help modal text to state that no data is transmitted to third parties.

- [x] **Step 3: Remove `.integration-off` CSS rules from `app/globals.css`**

Delete `.integration-off` and its child selectors from base styles (around lines 2015-2038) and the mobile media query (around lines 2679-2685).

- [x] **Step 4: Run typecheck and production build to verify zero regressions**

Run: `npm run typecheck && npm run build`
Expected: PASS

- [x] **Step 5: Commit UI and CSS changes**

```bash
git add components/workspace.tsx app/globals.css
git commit -m "feat(ui): completely remove Jev integration placeholder and unused styles"
```

---

### Task 2: Update Documentation and PRD

**Files:**
- Modify: `README.md:175-180`
- Modify: `docs/scanning.md:70-75`
- Modify: `PRD.md:1-20, 255-265, 520-530, 565-590, 630-650`

**Interfaces:**
- Consumes: Repository architecture documentation and product requirements.
- Produces: Cohesive documentation asserting zero external telemetry and formal rejection of proprietary hosted AI triage models.

- [x] **Step 1: Update README.md and docs/scanning.md**

Remove references to disabled AI triage in favor of explicit zero-external-telemetry assertions.

- [x] **Step 2: Update PRD.md to formalize rejection of Jev**

Document that Jev was formally rejected due to proprietary hosting, telemetry risks, and incompatibility with self-hosted open-source operation.

- [x] **Step 3: Commit documentation updates**

```bash
git add README.md docs/scanning.md PRD.md docs/superpowers/plans/2026-10-19-complete-removal-of-jev.md
git commit -m "docs: formalize rejection and complete removal of Jev AI triage"
```
