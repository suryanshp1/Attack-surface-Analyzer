# Contributing to Surfacer

Thanks for helping improve Surfacer. Start with the [README](README.md), [architecture](docs/architecture.md), and [development guide](docs/development.md).

## Bugs and proposals

Use [GitHub issues](https://github.com/suryanshp1/attack-surface/issues) for reproducible bugs and feature proposals. For a bug, include:

- What you expected and what happened.
- Minimal reproduction steps, operating system, and relevant Docker/Node/Go versions.
- The affected service or scanner stage and redacted diagnostics.
- Whether the issue occurs in Compose or local development.

For substantial features, describe the problem and intended behavior in an issue before investing in an implementation. Report security vulnerabilities using [SECURITY.md](SECURITY.md), not a public reproduction.

## Pull requests

1. Create a focused branch from the current default branch.
2. Keep changes scoped to one problem and preserve existing workspace data and scan history.
3. Add meaningful regression coverage when changing backend behavior; use isolated fixtures for scanner tests.
4. Run the checks relevant to the change from [the development guide](docs/development.md).
5. Explain the problem, resulting behavior, validation, and any migration or compatibility impact. Include screenshots for UI changes.

Keep scope enforcement, redaction, cancellation, and coverage-aware lifecycle behavior intact. Scanner/template changes need pinned provenance and native fixture validation. Avoid unrelated dependency upgrades and generated output in pull requests.

Do not commit `.env`, session state, access keys, database dumps, personal scan exports, or unredacted evidence. Use domains and fixtures you control for reproductions.

## Documentation

Keep the README focused on getting started and understanding the project. Put implementation detail in `docs/`; update links, configuration examples, scanner versions, and current limits when behavior changes. Mermaid diagrams should match the actual service and network topology in `compose.yaml`.

## License

Contributions to Surfacer's own code are under [Apache-2.0](LICENSE). Preserve existing copyright and third-party notices; upstream tools and templates retain their original licenses. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
