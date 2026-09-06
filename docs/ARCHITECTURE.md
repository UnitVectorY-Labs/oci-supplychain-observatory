# Architecture

`main.go` only wires configuration, logging, the registry client, the in-memory cache, the inspection service, and the HTTP server.

The application code is split under `internal/`:

- `config` reads environment configuration, registry allow-list values, timeouts, and size limits.
- `reference` validates and normalizes user-provided image references before any registry access.
- `oci` contains OCI registry HTTP calls, manifest types, Cosign attachment helpers, and safe payload summarization.
- `inspect` orchestrates tag resolution, top-level and platform manifest inspection, referrer discovery, Cosign legacy lookup, artifact decoding, and artifact download registration.
- `cache` defines the cache boundary. The current implementation is in-memory and intentionally replaceable.
- `web` owns HTTP routes, HTMX partial rendering, templates, static assets, origin checks, and response security headers.

The primary user flow is intentionally asynchronous. `GET /inspect?image=<reference>` (or the supported `POST /inspect`) validates the submitted image reference, starts an in-process inspection job, and immediately returns a results shell headed by the submitted image reference. The shell polls `GET /inspect/jobs/{id}` with HTMX until the rendered report is available. This keeps the page transition immediate while registry metadata is still being discovered.

Anonymous-access failures are reported explicitly to the user without exposing registry response bodies or internal request details.

`GET /inspect?image=<reference>` starts the same flow for links within a report. Lineage links use a canonical digest reference even when the UI also shows a human-readable tag recorded in provenance. This makes navigation reproducible without implying that a mutable tag still points at the same content.

The results page starts with a coverage table comparing signatures, attestations, and SBOMs across the index and runnable platform manifests. The runnable platform with the most discovered artifacts opens first (the first platform breaks ties); a single manifest opens directly. A persistent scope selector and coverage buttons switch the same panels, update a URL fragment, and preserve the distinction between index and platform evidence. A single manifest's OS, architecture, and variant come from its bounded configuration document when no index descriptor supplies them.

Provenance summaries show source, commit, builder, and build times. Repeated subject aliases and protocol identifiers remain in technical details so they do not dominate the report. SPDX and CycloneDX inventories display at most 200 packages, with a local text filter that searches those displayed rows only. CycloneDX nested components are included, with a 10,000-component counting ceiling and an explicit lower-bound count at that ceiling. Licenses are decoded independently from supplier information. This is a view of publisher-supplied inventory, not a generated SBOM or vulnerability scan.

The initial response omits decoded structure and raw payload HTML. `GET /artifacts/{id}/view` renders those on demand from already-retained metadata, without another registry request. HTMX replaces the disclosure link with a decoded/raw view; direct navigation gets a complete page. Raw downloads remain at `GET /artifacts/{id}/download`. Unknown IDs return 404. This keeps metadata-rich multi-platform reports small while preserving the original evidence.

Artifact payload rendering is an optional detail view. Each fetched artifact exposes a raw JSON view and a decoded structure view. The semantic decoder also unwraps JSON-string or base64-encoded predicates inside in-toto statements, preserving the statement subjects; this is required by Distroless SPDX attestations. Unsupported inventory structures are labeled instead of being reported as empty SBOMs. The decoded view recursively expands base64-encoded JSON, JSON string fields, and supported certificate fields at the row where the encoded value appeared. Those decoded substructures render as their own decoded/raw tab groups so users can inspect nested claim structure without losing the original location or raw encoded value.

Artifact discovery treats individual metadata layers as separate artifacts. This matters for legacy Cosign tags because a single `.att` or `.sig` manifest may contain multiple DSSE or simple-signing layers. The inspector reads known metadata layer media types, including Cosign simple-signing, DSSE envelopes, SPDX, CycloneDX, in-toto, and JSON payloads. It intentionally skips ordinary image layer media types so digest-derived tags that point at normal image indexes are not treated as supply-chain metadata and do not cause container layers to be downloaded.

Docker/BuildKit commonly stores per-platform attestations as `unknown/unknown` descriptors in an image index. These descriptors are not runnable platforms and do not consume the runnable-platform limit. The inspector recognizes their `vnd.docker.reference.type=attestation-manifest` annotation, associates them with the platform digest recorded by `vnd.docker.reference.digest`, and reads only their recognized metadata layers. If the target annotation is absent, the attestation manifest subject is used to associate the evidence. Index attestation candidates and Cosign attachment candidates are bounded by the referrer limit. Duplicate artifact payload digests within one target are counted once across discovery methods.

## Build Inputs and Runtime Lineage

The inspector extracts container-image dependencies from SLSA provenance `resolvedDependencies` and legacy `materials`. Each dependency is validated against the same registry allow-list before any outbound request. A configured maximum bounds how many lineage candidates are examined for each scope, including single manifests and index-level provenance. Index scopes without filesystem layers collect input links without fetching candidate layers. OCI package URLs can supply `repository_url`, and digest versions or embedded OCI base digests preserve immutable navigation. Ambiguous platform variants do not produce an arbitrary match; the longest exact layer-prefix match is selected when multiple candidates match.

The UI distinguishes two relationships:

- A **build input** is recorded in provenance. A non-matching input is not automatically a builder: it might be a source for copied files or another build stage.
- A **runtime base** is supported by an OCI base-image annotation or by provenance plus an exact layer-prefix match. Prefix matching compares manifest layer digests only; it does not download filesystem layers.

OCI base annotations are optional, and provenance may omit inputs, so lineage is intentionally evidence-qualified rather than presented as universal fact. Candidate base and build-input images are not recursively inspected during the original request. Instead, allow-listed public dependencies link to a new inspection using their immutable digest. This prevents an unexpectedly large recursive registry crawl while still allowing users to follow the supply chain.

There is no standardized registry API for reverse mapping a digest to every tag. Human-readable dependency tags are therefore shown only when published annotations or provenance provide them. Inspection links use the digest, not the tag.

Legacy Cosign lookup checks `.sig`, `.att`, and `.sbom` tags derived from the resolved target digest. The unsuffixed digest-derived tag is inspected only as a possible attachment index, and platform descriptors in that index are ignored because they represent image manifests rather than metadata attachments.

The app remains an inspection tool. It does not generate SBOMs, pull full image layers, execute registry content, or treat decoded metadata as policy trust.

## Search and appearance

The search form accepts one image reference and uses the configured allow-list to generate registry input buttons. These buttons only insert a registry prefix; server-side normalization and access checks remain authoritative. There is no hard-coded image example or default repository. The same form is available from every report. GET navigation makes inspections shareable and browser history usable; POST remains supported for existing callers. Validation errors render a full page for ordinary navigation and a fragment for HTMX.

The embedded stylesheet defaults to dark mode with restrained orange accents. Light mode uses the same semantic color variables; the preference is stored locally in the browser, with dark mode as the fallback when storage is unavailable. Scope controls, package filters, and payload tabs support keyboard use. No new UI dependencies are required.
