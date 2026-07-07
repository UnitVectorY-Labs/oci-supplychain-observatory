package reference

import (
	"errors"
	"testing"
)

func testConfig() Config {
	return Config{AllowedRegistry: map[string]bool{
		"ghcr.io":         true,
		"docker.io":       true,
		"registry.k8s.io": true,
	}}
}

func TestParseNormalizesDockerHub(t *testing.T) {
	ref, err := Parse("nginx:latest", testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if ref.Normalized != "docker.io/library/nginx:latest" {
		t.Fatalf("unexpected normalized ref: %s", ref.Normalized)
	}
}

func TestParseRejectsURLs(t *testing.T) {
	_, err := Parse("https://ghcr.io/unitvectory-labs/iapheaders:v0.5.1", testConfig())
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input, got %v", err)
	}
}

func TestParseRejectsUnallowedRegistry(t *testing.T) {
	_, err := Parse("example.com/project/image:latest", testConfig())
	if !errors.Is(err, ErrRegistryNotAllowed) {
		t.Fatalf("expected registry allow-list error, got %v", err)
	}
}

func TestParseRejectsLocalhost(t *testing.T) {
	_, err := Parse("localhost:5000/project/image:latest", testConfig())
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input, got %v", err)
	}
}
