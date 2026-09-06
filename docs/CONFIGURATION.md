# Configuration

## Registry Allow-List

The allowed registries are configured in `internal/config/registries.yaml`:

```yaml
registries:
  - ghcr.io
  - registry.k8s.io
  - gcr.io
  - quay.io
  - docker.io
```

The YAML file is embedded into the binary at build time. To change the allowed registries, edit the file and rebuild.

The `OSO_ALLOWED_REGISTRIES` environment variable can be used to override the YAML configuration entirely with a comma-separated list (e.g., `OSO_ALLOWED_REGISTRIES=ghcr.io,docker.io`). The legacy `CTI_ALLOWED_REGISTRIES` variable is also accepted.

## Other Configuration

Environment variables:

- `OSO_HTTP_ADDR`: listen address, default `:8080`.
- `OSO_REQUEST_TIMEOUT`: outbound inspection timeout, default `30s`.
- `OSO_READ_TIMEOUT`: HTTP server read timeout, default `10s`.
- `OSO_WRITE_TIMEOUT`: HTTP server write timeout, default `45s`.
- `OSO_IDLE_TIMEOUT`: HTTP server idle timeout, default `120s`.
- `OSO_MAX_ARTIFACT_BYTES`: maximum artifact blob bytes read into memory, default `10485760`.
- `OSO_MAX_PREVIEW_BYTES`: maximum decoded preview bytes rendered, default `524288`.
- `OSO_MAX_PLATFORMS`: maximum platform manifests inspected from an index, default `50`.
- `OSO_MAX_REFERRERS`: maximum OCI referrers inspected per digest, default `100`.
- `OSO_MAX_LINEAGE_INPUTS`: maximum provenance image dependencies examined for base-layer lineage per platform, default `10`.

The legacy prototype variable name `CTI_HTTP_ADDR` is also accepted for migration convenience.

The approved registry list also drives the search form's registry buttons. The UI does not add exceptions to the configured allow-list. `OSO_MAX_PLATFORMS` counts runnable platform descriptors, excluding BuildKit attestation entries. `OSO_MAX_REFERRERS` also bounds index-attestation and Cosign attachment candidates. `OSO_MAX_LINEAGE_INPUTS` applies to each inspected scope, including a directly referenced image manifest. Existing timeouts and artifact byte limits are unchanged.

Package inventories render the first 200 entries; filtering searches that displayed subset. CycloneDX nested component counting is capped at 10,000 entries and reports a lower bound at the ceiling. Complete published metadata remains available through raw downloads. Raw/decoded payload HTML is loaded only when requested and still observes `OSO_MAX_PREVIEW_BYTES`.
