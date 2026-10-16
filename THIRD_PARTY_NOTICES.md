# Third-party components

Surfacer's own code is licensed under [Apache-2.0](LICENSE). This does not relicense third-party source, binaries, templates, assets, or development tooling included in or used by the repository. Their original notices and license terms continue to apply.

## Scanner binaries

The worker image bundles pinned releases from these upstream projects:

| Component | Upstream |
| --- | --- |
| Subfinder | https://github.com/projectdiscovery/subfinder |
| DNSx | https://github.com/projectdiscovery/dnsx |
| Naabu | https://github.com/projectdiscovery/naabu |
| HTTPx | https://github.com/projectdiscovery/httpx |
| TLSx | https://github.com/projectdiscovery/tlsx |
| Katana | https://github.com/projectdiscovery/katana |
| Nuclei | https://github.com/projectdiscovery/nuclei |
| GAU | https://github.com/lc/gau |
| Gitleaks | https://github.com/gitleaks/gitleaks |

[scripts/fetch-scanners.py](scripts/fetch-scanners.py) records versions and release sources, verifies checksums, and retrieves each scanner's license. The runtime image includes these files at `/usr/local/bin/<tool>.LICENSE` alongside the binaries. Preserve them when redistributing the image.

## Detection templates

The curated files in `backend/templates/` originate from upstream [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates). The pinned upstream [MIT license](backend/templates/LICENSE.md) is included alongside them. Original source URLs, release, hashes, and technology gates are recorded in [manifest.json](backend/templates/manifest.json). Retain upstream attribution and applicable template notices when modifying or redistributing them.

## Evidence storage

The default Compose deployment builds MinIO from a pinned official source revision. MinIO is separately licensed under AGPLv3; Surfacer's Apache-2.0 license does not replace it. [deploy/Dockerfile.minio](deploy/Dockerfile.minio) records the source revision and copies its license into `/usr/share/licenses/minio/LICENSE` in the image.

## Other dependencies and tooling

Frontend dependencies are recorded in `package.json` and `package-lock.json`; Go dependencies are recorded in `backend/go.mod` and `backend/go.sum`. Container base images and their installed packages retain their respective notices. Development skills and tooling under `.agents/` retain any notices supplied with those files.

The API uses the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk/tree/v1.4.1) for MCP protocol negotiation, input schemas, and Streamable HTTP transport. Its upstream [license](https://github.com/modelcontextprotocol/go-sdk/blob/v1.4.1/LICENSE) retains MIT terms for existing code and Apache-2.0 terms for new contributions. Transitive dependencies retain their own licenses; the pinned module graph is recorded in `backend/go.mod` and `backend/go.sum`.

This document is a component and notice-location guide, not a complete software bill of materials. Preserve the applicable upstream licenses and notices when packaging or distributing Surfacer.
