# Security Model

The application is intended for public internet exposure and treats image references, registry responses, manifests, and artifact payloads as untrusted input.

Important controls:

- User input is accepted only as a container image reference. URLs, file paths, whitespace, localhost, IP literal registries, and private or local registry addresses are rejected.
- Outbound registry access is restricted to the configured registry allow-list.
- Tags are resolved to immutable digests before artifact discovery is reported.
- Registry responses and artifact blobs are read through explicit byte limits.
- Artifact blob reads are limited to recognized metadata layer media types. Ordinary OCI/Docker image layer media types are skipped, including when a digest-derived legacy Cosign tag resolves to a normal image index.
- Requests use strict server and outbound registry timeouts.
- POST requests are protected with `Origin` and `Sec-Fetch-Site` checks.
- Inspection job identifiers are random process-local IDs. They are used only to retrieve the rendered result for an inspection already started by `POST /inspect`.
- Static HTMX and app JavaScript are self-hosted, and the Content Security Policy only allows self-hosted scripts and styles.
- Artifact downloads are served only for artifacts discovered during inspection and retained by the current cache/service process.
- Decoded payload views parse JSON and recursively expand embedded base64 JSON for display only. Decoding does not imply cryptographic verification or policy trust.

Verification status is deliberately explicit. The UI keeps discovery, successful decoding, cryptographic validity, signer identity, and policy trust as separate concepts. The current implementation provides discovery and decoding only, labels every artifact `Not verified`, and does not perform in-process Sigstore verification or policy evaluation. Displaying a certificate or transparency-log record does not establish that it is valid or trusted.

Related container images are accepted only from explicit SLSA-style provenance material records, must include a SHA-256 digest, and must pass the same registry allow-list and reference validation as direct user input. Layer overlap is not used to infer a base image because shared content does not prove a build relationship.
