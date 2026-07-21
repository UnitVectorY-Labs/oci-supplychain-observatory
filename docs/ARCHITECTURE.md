# Architecture

`main.go` only wires configuration, logging, the registry client, the in-memory cache, the inspection service, and the HTTP server.

The application code is split under `internal/`:

- `config` reads environment configuration, registry allow-list values, timeouts, and size limits.
- `reference` validates and normalizes user-provided image references before any registry access.
- `oci` contains OCI registry HTTP calls, manifest types, Cosign attachment helpers, and safe payload summarization.
- `inspect` orchestrates tag resolution, top-level and platform manifest inspection, referrer discovery, Cosign legacy lookup, artifact decoding, and artifact download registration.
- `cache` defines the cache boundary. The current implementation is in-memory and intentionally replaceable.
- `web` owns HTTP routes, HTMX partial rendering, templates, static assets, origin checks, and response security headers.

The primary user flow is intentionally asynchronous. `POST /inspect` validates the submitted image reference, starts an in-process inspection job, and immediately returns a results shell headed by the submitted image reference. The shell polls `GET /inspect/jobs/{id}` with HTMX until the rendered report is available. This keeps the page transition immediate while registry metadata is still being discovered.

Artifact payload rendering uses two levels. A compact summary first answers format-specific questions such as what digest was signed, which predicate schema is present, and how many packages an SBOM declares. The full structure remains available below it. That structure preserves original JSON keys but pairs common in-toto, DSSE, SLSA, SPDX, CycloneDX, Cosign, certificate, and transparency-log fields with plain-language meaning. Unknown fields are explicitly described as predicate- or producer-defined instead of receiving guessed semantics. Base64-encoded JSON, JSON string fields, and supported certificate fields are recursively expanded at their original location, with the raw representation still available.

The inspector extracts container-image materials only when provenance explicitly publishes them in SLSA-style `materials` or `buildDefinition.resolvedDependencies` fields. An allow-listed, digest-qualified container material is offered as a separate inspection target. The UI calls it a declared build input—often, but not necessarily, a Dockerfile base image. OCI filesystem layers do not encode their source image name, so the application does not infer ancestry from shared layer digests and does not fetch ordinary layers.

Artifact discovery treats individual metadata layers as separate artifacts. This matters for legacy Cosign tags because a single `.att` or `.sig` manifest may contain multiple DSSE or simple-signing layers. The inspector reads known metadata layer media types, including Cosign simple-signing, DSSE envelopes, SPDX, CycloneDX, in-toto, and JSON payloads. It intentionally skips ordinary image layer media types so digest-derived tags that point at normal image indexes are not treated as supply-chain metadata and do not cause container layers to be downloaded.

Legacy Cosign lookup checks `.sig`, `.att`, and `.sbom` tags derived from the resolved target digest. The unsuffixed digest-derived tag is inspected only as a possible attachment index, and platform descriptors in that index are ignored because they represent image manifests rather than metadata attachments.

The app remains an inspection tool. It does not generate SBOMs, pull full image layers, execute registry content, or treat decoded metadata as policy trust. Until a cryptographic verifier and an explicit trust policy are implemented, every artifact is labeled `Not verified`; discovery, successful parsing, cryptographic validity, signer identity, and policy trust are separate states.
