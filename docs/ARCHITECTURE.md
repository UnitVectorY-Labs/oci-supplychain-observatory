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

Artifact payload rendering keeps the payload structure as the primary view. Each fetched artifact exposes a raw JSON view and a decoded structure view. The decoded view recursively expands base64-encoded JSON, JSON string fields, and supported certificate fields at the row where the encoded value appeared. Those decoded substructures render as their own decoded/raw tab groups so users can inspect nested claim structure without losing the original location or raw encoded value.

The app remains an inspection tool. It does not generate SBOMs, pull full image layers, execute registry content, or treat decoded metadata as policy trust.
