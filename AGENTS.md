# AGENTS.md

## Project Intent

`oci-supplychain-observatory` is a public-facing Go web application for inspecting supply chain metadata associated with public OCI container images.

The application accepts only a container image reference as input. It discovers and displays existing registry-published metadata such as signatures, attestations, provenance, and SBOMs. It must not generate SBOMs, download full container images, or execute registry-provided content.

## Architecture Expectations

- `main.go` is only the command-line entry point.
- Application behavior must be implemented under `internal/`.
- Keep packages small and purpose-driven.
- Prefer clear boundaries between HTTP handling, registry access, verification, parsing, rendering, and configuration.
- Avoid placing business logic in templates, handlers, or `main.go` it is just an entry point.
- The HTML templates are all stored under `internal/web/templates/` and should be rendered with HTMX and included as part of the Go binary using the `embed` package.
- Treat registry responses, artifact payloads, and user-provided image references as untrusted input.

## Tech Stack

- Language: Go
- Runtime: single containerized Go application
- HTTP: prefer the Go standard library unless an external dependency is clearly justified
- UI: server-rendered HTML templates with HTMX
- Styling: simple dark theme
- Icons: Tabler Icons from `https://github.com/tabler/tabler-icons`
- Storage: no database required for the initial version
- Future caching: PostgreSQL may be added later as an optional cache layer

## Functional Requirements

- Inspect public images only.
- Enforce an allow-list of supported registries.
- Resolve tags to immutable digests before inspection.
- Inspect both top-level OCI image indexes and platform-specific manifests.
- Discover and display signatures, attestations, provenance, and SBOM artifacts.
- Verify signatures and attestations where supported.
- Present decoded, human-readable views first.
- Provide download links for raw discovered metadata.
- Do not generate SBOMs.
- Do not pull full image layers.
- Do not execute or trust registry-provided content.

## Documentation Requirements

Documentation lives in `docs/` and must be maintained with functional, architectural, and security-relevant changes.

Documentation should explain why technical and architectural decisions were made. Avoid writing docs that merely restate what is obvious from the code.

Update documentation when changing:

- registry allow-list behavior
- OCI discovery logic
- signature or attestation verification behavior
- SBOM parsing behavior
- request limits, artifact size limits, or timeout behavior
- caching behavior
- public-facing security assumptions
- HTTP routes, user flows, or rendering behavior
- configuration options

## Security Expectations

This application is intended to be exposed on the public internet.

- Validate and normalize image references before registry access.
- Restrict outbound registry access to the configured allow-list.
- Use strict request timeouts.
- Limit artifact size before reading content into memory.
- Avoid following unsafe redirects.
- Avoid leaking internal errors to users.
- Log enough detail for operators without exposing sensitive runtime details.
- Keep verification results explicit. Distinguish between found, parsed, cryptographically verified, and policy trusted states.
- Add dependencies cautiously, especially around parsing and cryptographic verification.

## Development Expectations

- Keep the initial implementation simple and dependency-conscious.
- Prefer readable Go over clever abstractions.
- Add tests for parsing, registry allow-list enforcement, digest resolution behavior, and verification result handling.
- Keep user-facing text clear and precise.
- Preserve the core constraint: this is an inspection and visualization tool, not a generator, scanner, puller, or policy enforcement system.