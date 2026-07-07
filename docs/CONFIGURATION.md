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
- `OSO_REQUEST_TIMEOUT`: outbound inspection timeout, default `20s`.
- `OSO_READ_TIMEOUT`: HTTP server read timeout, default `10s`.
- `OSO_WRITE_TIMEOUT`: HTTP server write timeout, default `45s`.
- `OSO_IDLE_TIMEOUT`: HTTP server idle timeout, default `120s`.
- `OSO_MAX_ARTIFACT_BYTES`: maximum artifact blob bytes read into memory, default `10485760`.
- `OSO_MAX_PREVIEW_BYTES`: maximum decoded preview bytes rendered, default `524288`.
- `OSO_MAX_PLATFORMS`: maximum platform manifests inspected from an index, default `50`.
- `OSO_MAX_REFERRERS`: maximum OCI referrers inspected per digest, default `100`.

The legacy prototype variable name `CTI_HTTP_ADDR` is also accepted for migration convenience.
