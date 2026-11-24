# Architecture

`main.go` only wires configuration, build version metadata, logging, the registry client, the in-memory cache, the inspection service, and the HTTP server.

The application code is split into small, purpose-driven packages under `internal/`:

- `config` reads environment configuration, registry allow-list values, timeouts, size limits, and optional version-display settings.
- `reference` validates and normalizes user-provided image references before any registry access.
- `oci` contains OCI registry HTTP calls, anonymous Bearer token caching, digest-verified manifest/blob reads, paginated OCI referrer discovery, Cosign attachment helpers, Fulcio X.509 certificate OID extraction, Rekor transparency log extraction, and payload summarization.
- `verify` performs explicit, Go-stdlib-only cryptographic signature checks against embedded X.509 certificates (Cosign simple-signing layers, Sigstore bundles, and DSSE envelopes) and checks whether signed/attested subject digests match the inspected target digest.
- `inspect` orchestrates tag resolution, top-level and concurrent platform manifest inspection, OCI image config and build-history parsing, referrer and Cosign discovery, artifact decoding, lineage matching, SBOM facet aggregation, and bounded artifact retention.
- `cache` defines the cache boundary. The current implementation is in-memory and intentionally replaceable (for example, with PostgreSQL later).
- `web` owns HTTP routes, HTMX partial rendering, UnitVectorY-Labs Design templates and assets, origin checks, bounded job retention, and response security headers.

## Request Flow and Concurrency

The primary user flow is intentionally asynchronous so page transitions stay immediate while registry metadata is discovered:

1. `GET /inspect?image=<reference>` (or `POST /inspect`) validates the submitted image reference against the allow-list, creates a process-local job, starts inspection in a goroutine bounded by `OSO_REQUEST_TIMEOUT`, and renders the results shell. (`GET /inspect` with an empty `image` redirects to `/`.)
2. The results shell polls `GET /inspect/jobs/{id}` with HTMX until the rendered inspection report replaces the loading panel. If polling encounters a network or server error, the UI surfaces an explicit retry prompt rather than spinning indefinitely.
3. Anonymous-access failures and upstream errors are reported explicitly without leaking registry response bodies or internal request details.
4. `oci.Client` caches anonymous Bearer pull tokens per `(registry, repository)` up to a bounded cap, honoring token expiration with a safety buffer and automatically refreshing on `401`. Multi-platform indexes inspect runnable platform manifests concurrently with a bounded worker pool (`maxPlatformConcurrency = 6`) while preserving deterministic output order.

## Decoded Presentation and On-Demand Views

Each inspected scope (the top-level image index and each runnable platform manifest) opens into a 5-tab human-first workspace:

- **Overview**: Synthesizes runtime base and build-input lineage, SLSA provenance highlights (source repository, commit link, workflow, builder, duration), signing identity highlights (signer SAN, Fulcio OIDC issuer, certificate issuer, Rekor log entry), SBOM summary (package count, top ecosystems, top licenses), and runtime configuration highlights (non-root vs root user, entrypoint/cmd, ports, created timestamp, layer size).
- **Signatures & Attestations**: Lists discovered signatures, SLSA provenance, and other metadata with explicit decode status, embedded-cert cryptographic verification status, subject digest match, certificate identity details, and build materials.
- **SBOM & Packages**: Computes ecosystem and license counts across up to 10,000 SPDX or CycloneDX components (including nested CycloneDX components), renders clickable facet chips, and backs live search, filtering, and pagination with `GET /artifacts/{id}/packages` over HTMX so large inventories remain fast without sacrificing full-SBOM searchability.
- **Layers & Lineage**: Maps ordered manifest layer descriptors (base to application) to non-empty OCI image config build-history entries, marks layers inherited from an established runtime base, displays proportional compressed size bars, and offers the full OCI build history (including metadata-only config directives) without ever downloading filesystem layers.
- **Config & Raw Manifest**: Displays runtime configuration (`User`, `Entrypoint`, `Cmd`, `WorkingDir`, `ExposedPorts`, `Volumes`, `StopSignal`, `Env`, OCI annotations, labels) and provides on-demand viewing and downloading of the raw OCI manifest JSON and image config JSON.

To keep multi-platform reports compact, decoded JSON trees and raw payload HTML are omitted from the initial report response and loaded on demand via `GET /artifacts/{id}/view` from process-retained artifacts (no extra registry round-trips). Complete raw artifacts remain downloadable at `GET /artifacts/{id}/download`. Retained artifacts and inspection jobs are bounded by both TTL and maximum entry counts.

## Discovery and Lineage

- **Multi-layout discovery**: Combines OCI Referrers API (with same-host `Link: rel="next"` pagination bounded by `OSO_MAX_REFERRERS`), BuildKit `unknown/unknown` index attestation manifests (matched via `vnd.docker.reference.digest` or manifest `subject`), Cosign attachment indexes (`sha256-<hex>`), and legacy Cosign tags (`.sig`, `.att`, `.sbom`).
- **Metadata-only layer filtering**: Individual metadata layers are treated as separate artifacts, while ordinary container filesystem layer media types are skipped.
- **Build inputs vs. runtime base**: Extracts `pkg:docker/` and `pkg:oci/` dependencies from SLSA `resolvedDependencies` and `materials`, validates each against the registry allow-list, and compares manifest layer digest prefixes without downloading layers. Falls back to `org.opencontainers.image.base.name`/`.digest` annotations across descriptor, manifest, config, and index scopes, and checks exact layer-prefix matches when the declared base is inspectable. Matched base layers are flagged in the ordered layer stack, and inspectable upstream images link directly to a new inspection by immutable digest.

## Design System and Assets

The UI adopts the UnitVectorY-Labs Design language by embedding `uvy.css`, `uvy.js`, and the standalone isometric cube marks verbatim under `internal/web/static/`, paired with a minimal `app.css` extension that relies exclusively on `--uvy-*` custom properties and zero inline styles (preserving strict `style-src 'self'` CSP). Theme selection follows system `prefers-color-scheme` by default and persists explicit light/dark choices via the `uvy-theme` cookie before first paint. Tabler outline icons are delivered via an inline SVG symbol sprite containing only the icons used by the application.
