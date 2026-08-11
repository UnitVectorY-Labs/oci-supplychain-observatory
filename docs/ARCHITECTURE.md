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

Anonymous-access failures are reported explicitly to the user without exposing registry response bodies or internal request details.

`GET /inspect?image=<reference>` starts the same flow for links within a report. Lineage links use a canonical digest reference even when the UI also shows a human-readable tag recorded in provenance. This makes navigation reproducible without implying that a mutable tag still points at the same content.

The results page is evidence-first. A coverage table compares signatures, attestations, and SBOMs across the image index and each runnable platform manifest. Selecting a coverage row synchronizes the platform tab below it. Artifact-specific summaries precede decoded payloads: provenance exposes build facts, while SPDX and CycloneDX documents expose a component inventory. Registry transport fields and manifest sizes remain available as secondary technical details.

Artifact payload rendering keeps the payload structure as the primary view. Each fetched artifact exposes a raw JSON view and a decoded structure view. The decoded view recursively expands base64-encoded JSON, JSON string fields, and supported certificate fields at the row where the encoded value appeared. Those decoded substructures render as their own decoded/raw tab groups so users can inspect nested claim structure without losing the original location or raw encoded value.

Artifact discovery treats individual metadata layers as separate artifacts. This matters for legacy Cosign tags because a single `.att` or `.sig` manifest may contain multiple DSSE or simple-signing layers. The inspector reads known metadata layer media types, including Cosign simple-signing, DSSE envelopes, SPDX, CycloneDX, in-toto, and JSON payloads. It intentionally skips ordinary image layer media types so digest-derived tags that point at normal image indexes are not treated as supply-chain metadata and do not cause container layers to be downloaded.

Docker/BuildKit commonly stores per-platform attestations as `unknown/unknown` descriptors in an image index. These descriptors are not runnable platforms. The inspector recognizes their `vnd.docker.reference.type=attestation-manifest` annotation, associates them with the platform digest recorded by `vnd.docker.reference.digest`, and reads only their recognized metadata layers.

## Build Inputs and Runtime Lineage

The inspector extracts container-image dependencies from SLSA provenance `resolvedDependencies` and legacy `materials`. Each dependency is validated against the same registry allow-list before any outbound request. A configured maximum bounds how many lineage candidates are examined for each platform.

The UI distinguishes two relationships:

- A **builder image** is recorded as a provenance input but does not form the beginning of the output image's layer stack.
- A **runtime base** is supported by an OCI base-image annotation or by provenance plus an exact layer-prefix match. Prefix matching compares manifest layer digests only; it does not download filesystem layers.

OCI base annotations are optional, and provenance may omit inputs, so lineage is intentionally evidence-qualified rather than presented as universal fact. Candidate base and builder images are not recursively inspected during the original request. Instead, allow-listed public dependencies link to a new inspection using their immutable digest. This prevents an unexpectedly large recursive registry crawl while still allowing users to follow the supply chain.

There is no standardized registry API for reverse mapping a digest to every tag. Human-readable dependency tags are therefore shown only when published annotations or provenance provide them. Inspection links use the digest, not the tag.

Legacy Cosign lookup checks `.sig`, `.att`, and `.sbom` tags derived from the resolved target digest. The unsuffixed digest-derived tag is inspected only as a possible attachment index, and platform descriptors in that index are ignored because they represent image manifests rather than metadata attachments.

The app remains an inspection tool. It does not generate SBOMs, pull full image layers, execute registry content, or treat decoded metadata as policy trust.
