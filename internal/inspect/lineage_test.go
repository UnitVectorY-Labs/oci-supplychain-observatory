package inspect

import (
	"context"
	"testing"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/reference"
)

func TestDiscoverLineageIncludesSingleManifest(t *testing.T) {
	service := NewService(testConfig(), fakeRegistryForImage("ghcr.io", "example/app"), nil, nil)
	report := &Report{TopLevel: TargetResult{
		Name:         "Image manifest",
		Attestations: []Artifact{{Raw: []byte(`{"predicate":{"buildDefinition":{"resolvedDependencies":[{"uri":"pkg:docker/library/alpine@3.20","digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}}}`)}},
	}}

	service.discoverLineage(context.Background(), reference.ImageRef{Registry: "ghcr.io", Repository: "example/app"}, report)
	if len(report.TopLevel.BuildInputs) != 1 {
		t.Fatalf("top-level build inputs = %#v", report.TopLevel.BuildInputs)
	}
	input := report.TopLevel.BuildInputs[0]
	if input.Role != "Build input" || input.Reference != "library/alpine:3.20" {
		t.Fatalf("input = %#v", input)
	}
	if len(report.BuildInputs) != 1 {
		t.Fatalf("report build inputs = %#v", report.BuildInputs)
	}
}

func TestParseImagePURLUsesRepositoryURLQualifier(t *testing.T) {
	name, tag, ok := parseImagePURL("pkg:oci/base@1.2.3?repository_url=https%3A%2F%2Fghcr.io%2Forg%2Fbase&platform=linux%2Farm64")
	if !ok || name != "ghcr.io/org/base" || tag != "1.2.3" {
		t.Fatalf("got name=%q tag=%q ok=%v", name, tag, ok)
	}
}

func TestBuildInputUsesPURLDigestWhenDependencyDigestMissing(t *testing.T) {
	service := NewService(testConfig(), fakeRegistryForImage("ghcr.io", "example/app"), nil, nil)
	input, ok := service.buildInputFromDependency(provenanceDependency{
		URI: "pkg:docker/ghcr.io/org/base@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, "linux/amd64")
	if !ok || input.Digest == "" || !input.Inspectable || input.Tag != "" {
		t.Fatalf("input = %#v, ok=%v", input, ok)
	}
}

func TestDeclaredBaseUsesDigestEmbeddedInName(t *testing.T) {
	service := NewService(testConfig(), fakeRegistryForImage("ghcr.io", "example/app"), nil, nil)
	input, ok := service.declaredBase(TargetResult{Annotations: map[string]string{
		"org.opencontainers.image.base.name": "ghcr.io/org/base@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}})
	if !ok || !input.Inspectable || input.Digest == "" || input.Canonical == "" {
		t.Fatalf("input = %#v, ok=%v", input, ok)
	}
}

func TestParseImagePURLRejectsUnsafeRepositoryURL(t *testing.T) {
	for _, value := range []string{
		"pkg:oci/base@1?repository_url=ftp%3A%2F%2Fghcr.io%2Forg%2Fbase",
		"pkg:oci/base@1?repository_url=https%3A%2F%2Fuser%3Apass%40ghcr.io%2Forg%2Fbase",
	} {
		name, _, ok := parseImagePURL(value)
		if ok {
			t.Fatalf("value=%q got name=%q ok=%v", value, name, ok)
		}
	}
}

func TestMatchingPlatformPrefersVariantMatch(t *testing.T) {
	descriptors := []oci.Descriptor{
		{Digest: "sha256:generic", Platform: &oci.Platform{OS: "linux", Architecture: "arm64"}},
		{Digest: "sha256:v8", Platform: &oci.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
	}
	match, ok := matchingPlatform(descriptors, TargetResult{OS: "linux", Architecture: "arm64", Variant: "v8"})
	if !ok || match.Digest != "sha256:v8" {
		t.Fatalf("match = %#v, ok=%v", match, ok)
	}
}

func TestMatchingPlatformDoesNotGuessBetweenVariants(t *testing.T) {
	descriptors := []oci.Descriptor{
		{Digest: "sha256:v7", Platform: &oci.Platform{OS: "linux", Architecture: "arm64", Variant: "v7"}},
		{Digest: "sha256:v8", Platform: &oci.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
	}
	if _, ok := matchingPlatform(descriptors, TargetResult{OS: "linux", Architecture: "arm64", Variant: "v9"}); ok {
		t.Fatal("unexpected arbitrary variant match")
	}
}
