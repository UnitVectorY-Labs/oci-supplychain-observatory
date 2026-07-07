# Security Model

The application is intended for public internet exposure and treats image references, registry responses, manifests, and artifact payloads as untrusted input.

Important controls:

- User input is accepted only as a container image reference. URLs, file paths, whitespace, localhost, IP literal registries, and private or local registry addresses are rejected.
- Outbound registry access is restricted to the configured registry allow-list.
- Tags are resolved to immutable digests before artifact discovery is reported.
- Registry responses and artifact blobs are read through explicit byte limits.
- Requests use strict server and outbound registry timeouts.
- POST requests are protected with `Origin` and `Sec-Fetch-Site` checks.
- Inspection job identifiers are random process-local IDs. They are used only to retrieve the rendered result for an inspection already started by `POST /inspect`.
- Static HTMX and app JavaScript are self-hosted, and the Content Security Policy only allows self-hosted scripts and styles.
- Artifact downloads are served only for artifacts discovered during inspection and retained by the current cache/service process.
- Decoded payload views parse JSON and recursively expand embedded base64 JSON for display only. Decoding does not imply cryptographic verification or policy trust.

Verification status is deliberately explicit. The current implementation discovers and decodes signatures, attestations, provenance, and SBOM payloads, but does not yet perform full in-process Sigstore cryptographic verification or policy trust evaluation.
