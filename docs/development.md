# Development

[Back to README](../README.md)

## Local workspace

Requires Node.js 22+, npm, and Go 1.25+. Run commands from the repository root:

```sh
npm ci
node scripts/setup.mjs
npm run dev
```

The launcher builds a loopback Go API and starts Next.js. Sign in at [localhost:3000](http://localhost:3000) with `WORKSPACE_TOKEN` from `.env`. Local workspace data is stored in `backend/data/workspace.json`; it is separate from Compose's PostgreSQL volumes.

This mode does not start workers or execute live scans. Use the [Compose quick start](../README.md#quick-start) when changing scanner execution or verifying the full pipeline. Stop conflicting local/Compose web processes before reusing port 3000.

Read [AGENTS.md](../AGENTS.md) before modifying Next.js code. This project uses the installed Next.js documentation in `node_modules/next/dist/docs/`; do not assume older framework conventions apply.

## Validation

```sh
npm run typecheck
npm run build
npm run test:web
npm run test:api
```

The API command runs `go test -race ./...`. Native scanner and storage integration tests skip unless their explicit test environments are enabled. Unit and regression tests cover scope checks, private/rebinding destinations, permit expiry/tampering, lease recovery, stale-worker rejection, cancellation, triage, rollback, checkpoint retention, and conservative lifecycle behavior.

The web tests exercise workspace synchronization and the actual API/session handlers with a mocked upstream and isolated session stores. They cover opaque cookies, logout and stream cancellation, idle/absolute expiry, credential rotation, backend member-key revocation, session capacity, origin checks, and forwarding of report filters and webhook deletion IDs. Assessment view tests cover hostname-boundary scope matching and URL filter round trips. Webhook API tests use isolated receivers; DNS/destination overrides remain in test files.

For real scanner integration, build the separate Docker test target:

```sh
docker build -f backend/Dockerfile.worker --target test -t surfacer-native-test .
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=256m surfacer-native-test
```

The fixture runs locally with external networking disabled. Test-only DNS/dial injection is compiled into the test executable, not the production worker. The suite checks real scanner output, gateway behavior, normalization, redaction, and evidence.

`scripts/test-storage.py` additionally exercises a disposable database and bucket against Compose storage. It requires the native test image, generated `.env`, and the default `attack-surface_control` network name; adapt it if using a different Compose project name. It creates and drops `surfacer_test`, so use a dedicated development stack and do not use that database name for other data.

For UI changes, check desktop and mobile layouts, keyboard navigation, loading/empty/partial states, and light/dark/system appearance. Use actual application observations or isolated fixtures; never seed a live workspace to make a screenshot look populated.

## Repository layout

```text
app/                  Next.js routes, session, and API proxy
components/           Workspace UI and appearance controls
lib/                  Types, URL state, and theme initialization
backend/              Go API, worker, gateway, persistence, and tests
backend/templates/    Curated Nuclei templates and manifest
deploy/               Evidence-store image build
scripts/              Setup, launchers, scanner fetch, backup, storage tests
docs/                 Architecture, operations, scanning, and media
public/openapi.json   API route and role reference
compose.yaml          Complete local deployment
```

## Updating scanners and templates

Update pinned releases in [scripts/fetch-scanners.py](../scripts/fetch-scanners.py), retain checksum and license handling, and run the native fixture before proposing an upgrade. Update the README version table alongside the pins.

Template changes must include source provenance, hashes, review of request behavior, and fixture coverage. Keep signatures valid and update [the manifest](../backend/templates/manifest.json). Do not introduce unsolicited external callbacks, credential validation, or intrusive checks into the default set.

The [PRD](../PRD.md) and [design notes](../design.md) provide product context. The README describes implemented behavior and current limits; planned requirements are not release guarantees.
