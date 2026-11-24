# Configuration

## Registry Allow-List

The allowed registries are configured in `internal/config/registries.yaml`:

```yaml
registries:
  - ghcr.io
  - registry.access.redhat.com
  - registry.k8s.io
  - gcr.io
  - quay.io
  - docker.io
```

The YAML file is embedded into the binary at build time. To change the allowed registries, edit the file and rebuild.

The `OSO_ALLOWED_REGISTRIES` environment variable overrides the YAML configuration entirely with a comma-separated list (for example, `OSO_ALLOWED_REGISTRIES=ghcr.io,docker.io`). The legacy `CTI_ALLOWED_REGISTRIES` variable is also accepted.

## Runtime Environment Variables

- `OSO_HTTP_ADDR`: listen address, default `:8080` (legacy `CTI_HTTP_ADDR` is also accepted).
- `OSO_SHOW_VERSION`: display the build version line in the application footer (`true`/`false`), default `true`. When set to `false` (or when no build version is embedded), the `.version` element is omitted completely from rendered HTML.
- `OSO_REQUEST_TIMEOUT`: outbound inspection timeout and HTTP client timeout, default `30s`.
- `OSO_READ_TIMEOUT`: HTTP server read timeout, default `10s`.
- `OSO_WRITE_TIMEOUT`: HTTP server write timeout, default `45s`.
- `OSO_IDLE_TIMEOUT`: HTTP server idle timeout, default `120s`.
- `OSO_MAX_ARTIFACT_BYTES`: maximum artifact blob or OCI config bytes read into memory, default `10485760` (10 MiB).
- `OSO_MAX_PREVIEW_BYTES`: maximum decoded/raw preview bytes rendered in payload views, default `524288` (512 KiB).
- `OSO_MAX_PLATFORMS`: maximum runnable platform manifests inspected from an image index, default `50`.
- `OSO_MAX_REFERRERS`: maximum OCI referrers, BuildKit index attestations, or Cosign attachment candidates inspected per target, default `100`.
- `OSO_MAX_LINEAGE_INPUTS`: maximum provenance image dependencies examined for base-layer lineage per scope, default `10`.

## Behavior Notes

- The approved registry allow-list also drives the quick-insert registry buttons on the search form. The UI never grants exceptions outside the configured allow-list.
- `OSO_MAX_PLATFORMS` counts runnable platform descriptors, excluding BuildKit `unknown/unknown` attestation entries.
- SBOM indexing traverses up to 10,000 SPDX packages or nested CycloneDX components to compute ecosystem and license facets and power server-side search and pagination (`GET /artifacts/{id}/packages`, 50 rows per page). Complete published metadata remains available through raw downloads (`GET /artifacts/{id}/download`).
- Raw/decoded payload HTML is loaded on demand via `GET /artifacts/{id}/view` and observes `OSO_MAX_PREVIEW_BYTES`.
