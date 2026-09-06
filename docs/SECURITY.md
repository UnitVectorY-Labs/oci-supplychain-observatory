# Security Model

The application is intended for public internet exposure and treats image references, registry responses, manifests, and artifact payloads as untrusted input.

Important controls:

- User input is accepted only as a container image reference. URLs, file paths, whitespace, localhost, IP literal registries, and private or local registry addresses are rejected.
- Outbound registry access is restricted to the configured registry allow-list.
- Tags are resolved to immutable digests before artifact discovery is reported.
- Registry responses and artifact blobs are read through explicit byte limits.
- Artifact blob reads are limited to recognized metadata layer media types. Ordinary OCI/Docker image layer media types are skipped, including when a digest-derived legacy Cosign tag resolves to a normal image index.
- BuildKit `unknown/unknown` attestation descriptors are associated with their annotated platform digest, but only recognized metadata layers are read.
- Provenance-provided build-input and base-image references are untrusted input. They are normalized and checked against the registry allow-list before manifest access, and lineage candidate inspection is bounded per platform.
- Runtime-base inference compares layer descriptors without downloading layer content. Inferred relationships are labeled with their evidence and are not treated as cryptographic proof.
- Requests use strict server and outbound registry timeouts.
- POST requests are protected with `Origin` and `Sec-Fetch-Site` checks.
- Inspection job identifiers are random process-local IDs. They are used only to retrieve the rendered result for an inspection already started by `GET /inspect` or `POST /inspect`.
- HTMX is loaded from an exact unpkg version with a SHA-384 Subresource Integrity check and anonymous CORS mode. The Content Security Policy permits scripts only from the application and `https://unpkg.com`; app JavaScript and styles remain self-hosted. Pinning both the version and content hash prevents an unexpected CDN response from executing.
- Artifact downloads are served only for artifacts discovered during inspection and retained by the current cache/service process.
- Lineage navigation displays a tag only when registry-published metadata supplied it, and uses an immutable digest for the linked inspection. The app does not enumerate repository tags to reverse-map digests.
- Decoded payload views parse JSON and recursively expand embedded base64 JSON for display only. Decoding does not imply cryptographic verification or policy trust.

Verification status is deliberately explicit. The current implementation discovers and decodes signatures, attestations, provenance, and SBOM payloads, but does not yet perform full in-process Sigstore cryptographic verification or policy trust evaluation.

The report distinguishes discovered, decoded, unavailable, and unsupported-format metadata. A successful JSON decode never produces a cryptographically verified or policy-trusted status. Unknown artifact types are shown as other metadata rather than being counted as signatures. Published certificate identity is available separately and remains unverified. Declared base annotations do not imply measured layer inheritance; only a matching descriptor prefix displays inherited/added counts.

Artifact detail navigation reads only process-retained artifacts by ID, with the same HTML escaping and download boundaries as the report. It neither accepts an arbitrary URL nor fetches additional registry content. The per-artifact preview limit still applies to the optional detail response. Raw artifact downloads remain complete within the configured artifact byte limit.
