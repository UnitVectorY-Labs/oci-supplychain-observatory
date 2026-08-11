package inspect

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/reference"
)

type provenanceDependency struct {
	URI    string
	Digest string
}

func (s *Service) discoverLineage(ctx context.Context, imageRef reference.ImageRef, report *Report) {
	limit := s.cfg.MaxLineageInputs
	if limit <= 0 {
		limit = 10
	}
	aggregated := map[string]*BuildInput{}
	for platformIndex := range report.Platforms {
		platform := &report.Platforms[platformIndex]
		dependencies := platformDependencies(*platform)
		if len(dependencies) > limit {
			dependencies = dependencies[:limit]
			platform.Warnings = append(platform.Warnings, fmt.Sprintf("Build input lineage truncated at %d entries.", limit))
		}
		for _, dependency := range dependencies {
			input, ok := s.buildInputFromDependency(dependency, platform.Name)
			if !ok {
				continue
			}
			input.Role = "Builder image"
			input.Evidence = []string{"Build provenance"}
			if input.Inspectable {
				if layers, ok := s.platformLayers(ctx, input, *platform); ok && exactLayerPrefix(platform.Layers, layers) {
					input.Role = "Runtime base"
					input.SharedLayers = len(layers)
					input.BaseLayerCount = len(layers)
					input.AddedLayerCount = len(platform.Layers) - len(layers)
					input.Evidence = append(input.Evidence, "Exact layer prefix")
					base := input
					platform.Base = &BaseRelationship{BuildInput: base}
				}
			}
			platform.BuildInputs = append(platform.BuildInputs, input)
			aggregateBuildInput(aggregated, input)
		}

		if platform.Base == nil {
			if declared, ok := s.declaredBase(*platform); ok {
				platform.Base = &BaseRelationship{BuildInput: declared}
				platform.BuildInputs = append(platform.BuildInputs, declared)
				aggregateBuildInput(aggregated, declared)
			}
		}
	}

	for _, input := range aggregated {
		sort.Strings(input.Platforms)
		report.BuildInputs = append(report.BuildInputs, *input)
	}
	sort.Slice(report.BuildInputs, func(i, j int) bool {
		if report.BuildInputs[i].Role != report.BuildInputs[j].Role {
			return report.BuildInputs[i].Role == "Builder image"
		}
		return report.BuildInputs[i].Reference < report.BuildInputs[j].Reference
	})
}

func platformDependencies(platform TargetResult) []provenanceDependency {
	seen := map[string]bool{}
	var result []provenanceDependency
	for _, artifact := range platform.Attestations {
		for _, dependency := range artifactDependencies(artifact.Raw) {
			key := dependency.URI + "\x00" + dependency.Digest
			if seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, dependency)
		}
	}
	return result
}

func artifactDependencies(raw []byte) []provenanceDependency {
	doc, ok := decodeArtifactDocument(raw)
	if !ok {
		return nil
	}
	predicate, _ := doc["predicate"].(map[string]any)
	if predicate == nil {
		return nil
	}
	var collections []any
	if buildDefinition, ok := predicate["buildDefinition"].(map[string]any); ok {
		if dependencies, ok := buildDefinition["resolvedDependencies"].([]any); ok {
			collections = append(collections, dependencies...)
		}
	}
	if materials, ok := predicate["materials"].([]any); ok {
		collections = append(collections, materials...)
	}
	var result []provenanceDependency
	for _, item := range collections {
		entry, _ := item.(map[string]any)
		uri := stringAt(entry, "uri")
		if !strings.HasPrefix(uri, "pkg:docker/") && !strings.HasPrefix(uri, "pkg:oci/") {
			continue
		}
		digest, _ := entry["digest"].(map[string]any)
		result = append(result, provenanceDependency{URI: uri, Digest: firstDigest(digest)})
	}
	return result
}

func (s *Service) buildInputFromDependency(dependency provenanceDependency, platform string) (BuildInput, bool) {
	name, tag, ok := parseImagePURL(dependency.URI)
	if !ok {
		return BuildInput{}, false
	}
	displayRef := name
	if tag != "" {
		displayRef += ":" + tag
	}
	parsed, err := reference.Parse(displayRef, reference.Config{AllowedRegistry: s.cfg.AllowedRegistry})
	input := BuildInput{Reference: displayRef, Digest: dependency.Digest, Tag: tag, Platforms: []string{platform}}
	if err != nil {
		return input, true
	}
	input.Registry = parsed.Registry
	input.Repository = parsed.Repository
	if dependency.Digest != "" {
		canonical := parsed.Registry + "/" + parsed.Repository + "@" + dependency.Digest
		if _, digestErr := reference.Parse(canonical, reference.Config{AllowedRegistry: s.cfg.AllowedRegistry}); digestErr == nil {
			input.Inspectable = true
			input.Canonical = canonical
		}
	}
	return input, true
}

func parseImagePURL(value string) (string, string, bool) {
	prefix := "pkg:docker/"
	if strings.HasPrefix(value, "pkg:oci/") {
		prefix = "pkg:oci/"
	}
	if !strings.HasPrefix(value, prefix) {
		return "", "", false
	}
	path := strings.TrimPrefix(value, prefix)
	path, _, _ = strings.Cut(path, "?")
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return "", "", false
	}
	name, tag := decoded, ""
	if at := strings.LastIndex(decoded, "@"); at >= 0 {
		name, tag = decoded[:at], decoded[at+1:]
	}
	if name == "" {
		return "", "", false
	}
	return name, tag, true
}

func (s *Service) platformLayers(ctx context.Context, input BuildInput, target TargetResult) ([]LayerDescriptor, bool) {
	_, manifest, err := s.registry.GetManifest(ctx, input.Registry, input.Repository, input.Digest)
	if err != nil {
		return nil, false
	}
	if len(manifest.Manifests) > 0 {
		descriptor, ok := matchingPlatform(manifest.Manifests, target)
		if !ok {
			return nil, false
		}
		_, manifest, err = s.registry.GetManifest(ctx, input.Registry, input.Repository, descriptor.Digest)
		if err != nil {
			return nil, false
		}
	}
	layers := make([]LayerDescriptor, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		layers = append(layers, LayerDescriptor{Digest: layer.Digest, MediaType: layer.MediaType, Size: layer.Size})
	}
	return layers, len(layers) > 0
}

func matchingPlatform(descriptors []oci.Descriptor, target TargetResult) (oci.Descriptor, bool) {
	for _, descriptor := range descriptors {
		if descriptor.Platform == nil {
			continue
		}
		if descriptor.Platform.OS == target.OS && descriptor.Platform.Architecture == target.Architecture &&
			(target.Variant == "" || descriptor.Platform.Variant == "" || descriptor.Platform.Variant == target.Variant) {
			return descriptor, true
		}
	}
	return oci.Descriptor{}, false
}

func exactLayerPrefix(target, base []LayerDescriptor) bool {
	if len(base) == 0 || len(base) > len(target) {
		return false
	}
	for index := range base {
		if target[index].Digest != base[index].Digest {
			return false
		}
	}
	return true
}

func (s *Service) declaredBase(platform TargetResult) (BuildInput, bool) {
	name := platform.Annotations["org.opencontainers.image.base.name"]
	digest := platform.Annotations["org.opencontainers.image.base.digest"]
	if name == "" {
		return BuildInput{}, false
	}
	parsed, err := reference.Parse(name, reference.Config{AllowedRegistry: s.cfg.AllowedRegistry})
	input := BuildInput{
		Reference: name,
		Digest:    digest,
		Role:      "Runtime base",
		Platforms: []string{platform.Name},
		Evidence:  []string{"OCI base image annotation"},
	}
	if err == nil && digest != "" {
		input.Registry = parsed.Registry
		input.Repository = parsed.Repository
		input.Tag = parsed.Tag
		canonical := parsed.Registry + "/" + parsed.Repository + "@" + digest
		if _, digestErr := reference.Parse(canonical, reference.Config{AllowedRegistry: s.cfg.AllowedRegistry}); digestErr == nil {
			input.Canonical = canonical
			input.Inspectable = true
		}
	}
	return input, true
}

func aggregateBuildInput(values map[string]*BuildInput, input BuildInput) {
	key := input.Role + "\x00" + input.Reference + "\x00" + input.Digest
	if existing := values[key]; existing != nil {
		for _, platform := range input.Platforms {
			if !contains(existing.Platforms, platform) {
				existing.Platforms = append(existing.Platforms, platform)
			}
		}
		if input.SharedLayers > existing.SharedLayers {
			existing.SharedLayers = input.SharedLayers
			existing.BaseLayerCount = input.BaseLayerCount
			existing.AddedLayerCount = input.AddedLayerCount
		}
		return
	}
	copy := input
	values[key] = &copy
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func firstDigest(values map[string]any) string {
	for _, algorithm := range []string{"sha256", "sha512", "blake3"} {
		if value, ok := values[algorithm].(string); ok && value != "" {
			return algorithm + ":" + value
		}
	}
	return ""
}
