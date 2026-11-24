# Security Model

The application is intended for public internet exposure and treats image references, registry responses, manifests, configuration documents, and artifact payloads as untrusted input.

## Input and Registry Controls

- User input is accepted only as a container image reference. URLs, file paths, whitespace, `localhost`, IP-literal registries, and private or local registry addresses are rejected.
- Outbound registry access is restricted to the configured registry allow-list.
- Tags are resolved to immutable `sha256` digests before artifact discovery is reported.
- Digest-addressed manifest and blob fetches verify that the SHA-256 digest of the received bytes matches the requested `sha256:` digest before parsing or retaining the payload.
- Registry responses, OCI image config JSON, and artifact blobs are read through explicit byte limits.
- Artifact blob reads are limited to recognized metadata layer media types. Ordinary OCI/Docker image filesystem layer media types are skipped, including when a digest-derived legacy Cosign tag resolves to a normal image index.
- OCI Referrers `Link: rel="next"` pagination only follows relative `/v2/...` paths or HTTPS URLs on the exact same registry API host, capped at 5 pages and `OSO_MAX_REFERRERS`.
- BuildKit `unknown/unknown` attestation descriptors are associated with their annotated platform digest or manifest subject, and only recognized metadata layers are read.
- Provenance-provided build-input and base-image references are untrusted input. They are normalized and checked against the registry allow-list before manifest access, and lineage candidate inspection is bounded per scope.
- Runtime-base inference compares layer descriptors without downloading layer content. Inferred relationships are labeled with their evidence and are not treated as cryptographic proof.
- Requests use strict server and outbound registry timeouts. Redirects are limited to 3 HTTPS hops.

## Explicit Verification Boundaries

Verification states are intentionally explicit and never overstated as policy trust:

- **Discovered / Decoded / Unsupported format / Unavailable**: Tracks whether a metadata artifact was fetched and parsed as structured JSON.
- **Signature valid (embedded cert)** / **Signature invalid** / **Not verified**: Uses Go's standard library (`crypto/x509`, `crypto/ecdsa`, `crypto/rsa`, `crypto/ed25519`) to check Cosign simple-signing payloads, Sigstore bundles, and DSSE envelopes (using DSSEv1 Pre-Authentication Encoding) when an X.509 certificate is published alongside the signature (for example in `verificationMaterial.certificate.rawBytes`, `dev.sigstore.cosign/cert`, or `dev.sigstore.cosign/certificate`).
- **Subject digest match**: Separately checks whether the signed or attested subject digest matches the inspected manifest digest.
- **No policy trust evaluated**: Every verified or unverified artifact explicitly states that certificate chains, Fulcio roots, Rekor inclusion proofs, and organizational trust policies are not evaluated. A valid signature against an embedded self-contained certificate proves only internal consistency between the published payload, signature, and certificate—not that the signer is trusted.

## Web and Memory Controls

- `POST /inspect` is protected with `Origin` and `Sec-Fetch-Site` checks.
- Inspection job identifiers are random 128-bit hex process-local IDs. Both inspection jobs and retained artifacts enforce TTL expiration and maximum entry caps so memory stays bounded under public traffic.
- HTMX is loaded from an exact pinned version with a SHA-384 Subresource Integrity check and anonymous CORS mode. Content Security Policy restricts scripts to `'self'` and `https://unpkg.com`, restricts styles strictly to `'self'` (no inline `style` attributes), and disables framing (`frame-ancestors 'none'`, `X-Frame-Options: DENY`).
- All registry-derived strings, labels, history commands, and decoded payloads are rendered through Go `html/template` auto-escaping. Outbound links extracted from provenance or annotations are restricted to `https://` URLs with non-empty hosts.
- Raw artifact downloads are served only for retained artifacts by ID with `Content-Type: application/octet-stream`, `X-Content-Type-Options: nosniff`, and sanitized attachment filenames.
- Lineage navigation uses immutable digests for inspection links and never enumerates repository tags to reverse-map digests.
