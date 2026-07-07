package inspect

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/cache"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/config"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestInspectDecodesObservedCosignLayouts(t *testing.T) {
	tests := []struct {
		name            string
		image           string
		registry        *fakeRegistry
		wantSignatures  int
		wantAttest      []string
		wantSBOMs       int
		wantBlobFetches []string
	}{
		{
			name:  "chainguard multi-attestation tag",
			image: "cgr.dev/chainguard/wolfi-base:latest",
			registry: fakeRegistryForImage("cgr.dev", "chainguard/wolfi-base").
				withMainIndex().
				withLegacySignature("signature").
				withLegacyAttestations(map[string][]byte{
					"spdx": payloadEnvelope("https://spdx.dev/Document", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"wolfi-base","packages":[{},{}]}`),
					"slsa": payloadEnvelope("https://slsa.dev/provenance/v1", `{"buildDefinition":{"buildType":"apko"}}`),
					"apko": payloadEnvelope("https://apko.dev/image-configuration", `{"contents":{"packages":["wolfi-baselayout"]}}`),
				}),
			wantSignatures: 1,
			wantAttest: []string{
				"https://slsa.dev/provenance/v1",
				"https://apko.dev/image-configuration",
			},
			wantSBOMs:       1,
			wantBlobFetches: []string{"signature", "spdx", "slsa", "apko"},
		},
		{
			name:  "distroless signature-only positive control",
			image: "gcr.io/distroless/static-debian12:nonroot",
			registry: fakeRegistryForImage("gcr.io", "distroless/static-debian12").
				withMainManifest().
				withLegacySignature("signature"),
			wantSignatures:  1,
			wantBlobFetches: []string{"signature"},
		},
		{
			name:  "ghcr cosign signature sbom and digest-tag image index",
			image: "ghcr.io/sigstore/cosign/cosign:v3.0.2",
			registry: fakeRegistryForImage("ghcr.io", "sigstore/cosign/cosign").
				withMainIndex().
				withDigestTagImageIndex().
				withLegacySignature("signature-a", "signature-b").
				withLegacySBOM("sbom"),
			wantSignatures:  2,
			wantSBOMs:       1,
			wantBlobFetches: []string{"signature-a", "signature-b", "sbom"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewService(testConfig(), tt.registry, cache.NewMemory[*Report](), nil)
			report, err := service.Inspect(context.Background(), tt.image)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.TopLevel.Signatures) != tt.wantSignatures {
				t.Fatalf("signatures = %d, want %d: %#v", len(report.TopLevel.Signatures), tt.wantSignatures, report.TopLevel.Signatures)
			}
			if len(report.TopLevel.SBOMs) != tt.wantSBOMs {
				t.Fatalf("SBOMs = %d, want %d: %#v", len(report.TopLevel.SBOMs), tt.wantSBOMs, report.TopLevel.SBOMs)
			}
			for _, want := range tt.wantAttest {
				if !targetHasPredicate(report.TopLevel.Attestations, want) {
					t.Fatalf("missing attestation predicate %q in %#v", want, report.TopLevel.Attestations)
				}
			}
			if !sameStrings(tt.registry.blobFetches, tt.wantBlobFetches) {
				t.Fatalf("blob fetches = %#v, want %#v", tt.registry.blobFetches, tt.wantBlobFetches)
			}
			for _, artifact := range append(append(report.TopLevel.Signatures, report.TopLevel.Attestations...), report.TopLevel.SBOMs...) {
				if artifact.Downloadable && len(artifact.DecodedRows) == 0 {
					t.Fatalf("downloadable artifact has no decoded rows: %#v", artifact)
				}
			}
		})
	}
}

func TestInspectSkipsNonMetadataLayersFromDigestTagIndex(t *testing.T) {
	registry := fakeRegistryForImage("ghcr.io", "sigstore/cosign/cosign").
		withMainIndex().
		withDigestTagImageIndex()
	service := NewService(testConfig(), registry, cache.NewMemory[*Report](), nil)
	report, err := service.Inspect(context.Background(), "ghcr.io/sigstore/cosign/cosign:v3.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if report.ArtifactCount() != 0 {
		t.Fatalf("artifact count = %d, want 0: %#v", report.ArtifactCount(), report.TopLevel)
	}
	if len(registry.blobFetches) != 0 {
		t.Fatalf("fetched non-metadata blobs: %#v", registry.blobFetches)
	}
}

type fakeRegistry struct {
	registry    string
	repository  string
	manifests   map[string]fakeManifest
	blobs       map[string][]byte
	blobAliases map[string]string
	blobFetches []string
}

type fakeManifest struct {
	resp     oci.RegistryResponse
	manifest oci.Manifest
}

func fakeRegistryForImage(registry, repository string) *fakeRegistry {
	return &fakeRegistry{
		registry:    registry,
		repository:  repository,
		manifests:   map[string]fakeManifest{},
		blobs:       map[string][]byte{},
		blobAliases: map[string]string{},
	}
}

func (r *fakeRegistry) withMainIndex() *fakeRegistry {
	r.manifests["latest"] = fakeManifest{
		resp: response(testDigest, oci.MediaOCIIndex),
		manifest: oci.Manifest{MediaType: oci.MediaOCIIndex, Manifests: []oci.Descriptor{{
			MediaType: oci.MediaOCIManifest,
			Digest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Platform:  &oci.Platform{OS: "linux", Architecture: "amd64"},
		}}},
	}
	r.manifests["v3.0.2"] = r.manifests["latest"]
	return r
}

func (r *fakeRegistry) withMainManifest() *fakeRegistry {
	r.manifests["nonroot"] = fakeManifest{
		resp:     response(testDigest, oci.MediaOCIManifest),
		manifest: oci.Manifest{MediaType: oci.MediaOCIManifest},
	}
	return r
}

func (r *fakeRegistry) withDigestTagImageIndex() *fakeRegistry {
	tag := oci.LegacyCosignTag(testDigest, "")
	platformDigest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	layerDigest := r.addBlob("image-layer", []byte("not metadata"))
	r.manifests[tag] = fakeManifest{
		resp: response(tagDigest(tag), oci.MediaOCIIndex),
		manifest: oci.Manifest{MediaType: oci.MediaOCIIndex, Manifests: []oci.Descriptor{{
			MediaType: oci.MediaOCIManifest,
			Digest:    platformDigest,
			Platform:  &oci.Platform{OS: "linux", Architecture: "amd64"},
		}}},
	}
	r.manifests[platformDigest] = fakeManifest{
		resp: response(platformDigest, oci.MediaOCIManifest),
		manifest: oci.Manifest{MediaType: oci.MediaOCIManifest, Layers: []oci.Descriptor{{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
			Digest:    layerDigest,
			Size:      int64(len(r.blobs[layerDigest])),
		}}},
	}
	return r
}

func (r *fakeRegistry) withLegacySignature(names ...string) *fakeRegistry {
	var layers []oci.Descriptor
	for _, name := range names {
		raw := []byte(`{"critical":{"type":"cosign container image signature","image":{"docker-manifest-digest":"` + testDigest + `"}}}`)
		digest := r.addBlob(name, raw)
		layers = append(layers, oci.Descriptor{
			MediaType: oci.MediaCosignSimpleSigning,
			Digest:    digest,
			Size:      int64(len(raw)),
			Annotations: map[string]string{
				"dev.cosignproject.cosign/signature": "MEUCIQDsignature",
			},
		})
	}
	r.manifests[oci.LegacyCosignTag(testDigest, ".sig")] = fakeManifest{
		resp:     response("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", oci.MediaOCIManifest),
		manifest: oci.Manifest{MediaType: oci.MediaOCIManifest, Layers: layers},
	}
	return r
}

func (r *fakeRegistry) withLegacyAttestations(payloads map[string][]byte) *fakeRegistry {
	var layers []oci.Descriptor
	for name, raw := range payloads {
		digest := r.addBlob(name, raw)
		layers = append(layers, oci.Descriptor{
			MediaType: oci.MediaDSSEEnvelope,
			Digest:    digest,
			Size:      int64(len(raw)),
			Annotations: map[string]string{
				"dev.sigstore.cosign/predicateType": predicateTypeName(name),
			},
		})
	}
	r.manifests[oci.LegacyCosignTag(testDigest, ".att")] = fakeManifest{
		resp:     response("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", oci.MediaOCIManifest),
		manifest: oci.Manifest{MediaType: oci.MediaOCIManifest, Layers: layers},
	}
	return r
}

func (r *fakeRegistry) withLegacySBOM(name string) *fakeRegistry {
	raw := []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"cosign","packages":[{}]}`)
	digest := r.addBlob(name, raw)
	r.manifests[oci.LegacyCosignTag(testDigest, ".sbom")] = fakeManifest{
		resp: response("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", oci.MediaOCIManifest),
		manifest: oci.Manifest{MediaType: oci.MediaOCIManifest, Layers: []oci.Descriptor{{
			MediaType: "text/spdx+json",
			Digest:    digest,
			Size:      int64(len(raw)),
		}}},
	}
	return r
}

func (r *fakeRegistry) addBlob(name string, raw []byte) string {
	digest := "sha256:" + oci.MakeID(name+string(raw)) + oci.MakeID(string(raw)+name)
	for len(digest) < len(testDigest) {
		digest += "0"
	}
	digest = digest[:len(testDigest)]
	r.blobs[digest] = raw
	r.blobAliases[digest] = name
	return digest
}

func (r *fakeRegistry) GetManifest(_ context.Context, registry, repository, reference string) (oci.RegistryResponse, oci.Manifest, error) {
	if registry != r.registry || repository != r.repository {
		return oci.RegistryResponse{}, oci.Manifest{}, os.ErrNotExist
	}
	if reference == testDigest {
		for _, tag := range []string{"latest", "nonroot", "v3.0.2"} {
			if manifest, ok := r.manifests[tag]; ok {
				return manifest.resp, manifest.manifest, nil
			}
		}
	}
	manifest, ok := r.manifests[reference]
	if !ok {
		return oci.RegistryResponse{}, oci.Manifest{}, os.ErrNotExist
	}
	return manifest.resp, manifest.manifest, nil
}

func (r *fakeRegistry) GetReferrers(context.Context, string, string, string, int) ([]oci.Descriptor, []string) {
	return nil, nil
}

func (r *fakeRegistry) GetBlob(_ context.Context, registry, repository, digest string, maxBytes int64) ([]byte, error) {
	if registry != r.registry || repository != r.repository {
		return nil, os.ErrNotExist
	}
	raw, ok := r.blobs[digest]
	if !ok {
		return nil, os.ErrNotExist
	}
	if int64(len(raw)) > maxBytes {
		return nil, errors.New("too large")
	}
	r.blobFetches = append(r.blobFetches, r.blobAliases[digest])
	return raw, nil
}

func testConfig() config.Config {
	return config.Config{
		AllowedRegistry:  map[string]bool{"cgr.dev": true, "gcr.io": true, "ghcr.io": true},
		MaxArtifactBytes: 1 << 20,
		MaxPreviewBytes:  1 << 20,
		MaxPlatforms:     10,
		MaxReferrers:     10,
	}
}

func response(digest, mediaType string) oci.RegistryResponse {
	return oci.RegistryResponse{Digest: digest, MediaType: mediaType, Size: 100, Bytes: []byte(`{"schemaVersion":2}`)}
}

func tagDigest(tag string) string {
	return "sha256:" + oci.MakeID(tag) + oci.MakeID("digest-"+tag)
}

func payloadEnvelope(predicateType, predicate string) []byte {
	statement := `{"_type":"https://in-toto.io/Statement/v1","predicateType":"` + predicateType + `","subject":[{"name":"image","digest":{"sha256":"abc"}}],"predicate":` + predicate + `}`
	payload := base64.StdEncoding.EncodeToString([]byte(statement))
	return []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"` + payload + `","signatures":[{"sig":"MEUCIQDattestation"}]}`)
}

func predicateTypeName(name string) string {
	switch name {
	case "spdx":
		return "https://spdx.dev/Document"
	case "slsa":
		return "https://slsa.dev/provenance/v1"
	case "apko":
		return "https://apko.dev/image-configuration"
	default:
		return ""
	}
}

func targetHasPredicate(artifacts []Artifact, want string) bool {
	for _, artifact := range artifacts {
		for _, kv := range artifact.Summary {
			if kv.Key == "Predicate type" && kv.Value == want {
				return true
			}
		}
	}
	return false
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	got = append([]string{}, got...)
	want = append([]string{}, want...)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}
