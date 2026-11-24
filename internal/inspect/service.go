package inspect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/cache"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/config"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/reference"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/verify"
)

const (
	maxPlatformConcurrency = 6
	maxRetainedArtifacts   = 2000
	artifactRetentionTTL   = 20 * time.Minute
)

type Registry interface {
	GetManifest(ctx context.Context, registry, repository, reference string) (oci.RegistryResponse, oci.Manifest, error)
	GetReferrers(ctx context.Context, registry, repository, digest string, limit int) ([]oci.Descriptor, []string)
	GetBlob(ctx context.Context, registry, repository, digest string, maxBytes int64) ([]byte, error)
}

type retainedArtifact struct {
	artifact  *Artifact
	expiresAt time.Time
}

type Service struct {
	cfg       config.Config
	registry  Registry
	cache     cache.Cache[*Report]
	cacheTTL  time.Duration
	logger    *slog.Logger
	mu        sync.Mutex
	artifacts map[string]retainedArtifact
}

func NewService(cfg config.Config, registry Registry, reportCache cache.Cache[*Report], logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		cfg:       cfg,
		registry:  registry,
		cache:     reportCache,
		cacheTTL:  10 * time.Minute,
		logger:    logger,
		artifacts: map[string]retainedArtifact{},
	}
}

func (s *Service) Inspect(ctx context.Context, input string) (*Report, error) {
	ref, err := reference.Parse(input, reference.Config{AllowedRegistry: s.cfg.AllowedRegistry})
	if err != nil {
		return nil, err
	}
	if s.cache != nil {
		if entry, ok := s.cache.Get(ctx, ref.Normalized); ok && entry.Value != nil {
			clone := *entry.Value
			clone.FromCache = true
			return &clone, nil
		}
	}
	report, err := s.inspect(ctx, ref)
	if err != nil {
		return nil, err
	}
	if s.cache != nil {
		s.cache.Set(ctx, ref.Normalized, report, s.cacheTTL)
	}
	return report, nil
}

func (s *Service) Artifact(id string) (*Artifact, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.artifacts[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.artifacts, id)
		return nil, false
	}
	return entry.artifact, true
}

func (s *Service) inspect(ctx context.Context, ref reference.ImageRef) (*Report, error) {
	start := time.Now()
	manifestResp, manifest, err := s.registry.GetManifest(ctx, ref.Registry, ref.Repository, ref.Reference())
	if err != nil {
		return nil, err
	}
	resolvedDigest := manifestResp.Digest
	if resolvedDigest == "" {
		resolvedDigest = oci.DigestOf(manifestResp.Bytes)
	}
	report := &Report{
		ID:                  oci.MakeID(ref.Normalized + resolvedDigest + start.String()),
		Input:               ref.Original,
		Normalized:          ref.Normalized,
		Registry:            ref.Registry,
		Repository:          ref.Repository,
		Tag:                 ref.Tag,
		ResolvedDigest:      resolvedDigest,
		Canonical:           ref.Registry + "/" + ref.Repository + "@" + resolvedDigest,
		InspectedAt:         start,
		VerificationMessage: "Published metadata decoded for inspection",
	}
	topLevel := TargetResult{
		Name:      "Top-level image reference",
		Kind:      oci.KindForMediaType(manifest.MediaType),
		Digest:    resolvedDigest,
		MediaType: manifestResp.MediaType,
		Size:      manifestResp.Size,
	}
	s.populateTargetFromManifest(ctx, ref, &topLevel, manifest, manifestResp.Bytes, nil)
	report.TopLevel = s.inspectTarget(ctx, ref, topLevel)

	if manifest.MediaType == oci.MediaOCIIndex || manifest.MediaType == oci.MediaDockerManifestList || len(manifest.Manifests) > 0 {
		var platformDescriptors []oci.Descriptor
		for _, d := range manifest.Manifests {
			if d.Platform == nil || d.Platform.OS == "unknown" || d.Platform.Architecture == "unknown" {
				continue
			}
			if len(platformDescriptors) >= s.cfg.MaxPlatforms {
				report.Warnings = append(report.Warnings, fmt.Sprintf("Platform list truncated at %d entries.", s.cfg.MaxPlatforms))
				break
			}
			platformDescriptors = append(platformDescriptors, d)
		}

		results := make([]TargetResult, len(platformDescriptors))
		if len(platformDescriptors) <= 1 {
			for i, d := range platformDescriptors {
				results[i] = s.inspectPlatformDescriptor(ctx, ref, d)
			}
		} else {
			sem := make(chan struct{}, maxPlatformConcurrency)
			var wg sync.WaitGroup
			for i, d := range platformDescriptors {
				wg.Add(1)
				go func(idx int, desc oci.Descriptor) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					results[idx] = s.inspectPlatformDescriptor(ctx, ref, desc)
				}(i, d)
			}
			wg.Wait()
		}
		report.Platforms = results
		s.attachIndexAttestations(ctx, ref, report, manifest.Manifests)
	} else {
		report.TopLevel.Kind = "Image manifest"
	}
	s.discoverLineage(ctx, ref, report)
	s.logger.Info("inspection completed", "registry", ref.Registry, "repository", ref.Repository, "digest", resolvedDigest, "platforms", len(report.Platforms), "duration", time.Since(start))
	return report, nil
}

func (s *Service) inspectPlatformDescriptor(ctx context.Context, ref reference.ImageRef, d oci.Descriptor) TargetResult {
	platform := TargetResult{
		Name:         oci.PlatformName(d.Platform),
		Kind:         "Platform manifest",
		OS:           d.Platform.OS,
		Architecture: d.Platform.Architecture,
		Variant:      d.Platform.Variant,
		Digest:       d.Digest,
		MediaType:    d.MediaType,
		Size:         d.Size,
	}
	if resp, platformManifest, err := s.registry.GetManifest(ctx, ref.Registry, ref.Repository, d.Digest); err == nil {
		s.populateTargetFromManifest(ctx, ref, &platform, platformManifest, resp.Bytes, d.Annotations)
	} else {
		platform.Warnings = append(platform.Warnings, "Platform manifest details could not be loaded.")
	}
	return s.inspectTarget(ctx, ref, platform)
}

func (s *Service) populateTargetFromManifest(ctx context.Context, ref reference.ImageRef, target *TargetResult, manifest oci.Manifest, rawManifest []byte, descriptorAnnotations map[string]string) {
	if target.MediaType == "" {
		target.MediaType = manifest.MediaType
	}
	// Merge annotations from index descriptor -> manifest -> config labels (later wins on conflict).
	mergedAnnotations := map[string]string{}
	for k, v := range descriptorAnnotations {
		mergedAnnotations[k] = v
	}
	for k, v := range manifest.Annotations {
		mergedAnnotations[k] = v
	}

	if len(rawManifest) > 0 && int64(len(rawManifest)) <= s.cfg.MaxArtifactBytes {
		target.ManifestArtifactID = s.registerDocumentArtifact(target.Digest, "OCI manifest", "OCI manifest", target.Digest, target.MediaType, rawManifest)
	}

	var totalLayerBytes int64
	for i, layer := range manifest.Layers {
		totalLayerBytes += layer.Size
		target.Layers = append(target.Layers, LayerDescriptor{
			Index:          i + 1,
			Digest:         layer.Digest,
			MediaType:      layer.MediaType,
			ShortMediaType: shortLayerMediaType(layer.MediaType),
			Size:           layer.Size,
		})
	}
	if totalLayerBytes > 0 {
		for i := range target.Layers {
			pct := int((target.Layers[i].Size * 100) / totalLayerBytes)
			if pct == 0 && target.Layers[i].Size > 0 {
				pct = 1
			}
			target.Layers[i].SizePercent = pct
		}
	}

	if manifest.Config.Digest != "" && manifest.Config.Size <= s.cfg.MaxArtifactBytes {
		if raw, err := s.registry.GetBlob(ctx, ref.Registry, ref.Repository, manifest.Config.Digest, s.cfg.MaxArtifactBytes); err == nil {
			target.ConfigArtifactID = s.registerDocumentArtifact(target.Digest, "Image config", "OCI image configuration", manifest.Config.Digest, manifest.Config.MediaType, raw)
			s.applyImageConfig(target, raw, mergedAnnotations)
		}
	}

	if len(mergedAnnotations) > 0 {
		target.Annotations = mergedAnnotations
		if target.Config == nil {
			target.Config = &ImageConfig{}
		}
		target.Config.OCIAnnotations = extractOCIAnnotations(mergedAnnotations)
	}
}

func (s *Service) applyImageConfig(target *TargetResult, raw []byte, mergedAnnotations map[string]string) {
	var configDoc struct {
		Created      string `json:"created"`
		Author       string `json:"author"`
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
		Config       struct {
			User         string              `json:"User"`
			WorkingDir   string              `json:"WorkingDir"`
			Entrypoint   []string            `json:"Entrypoint"`
			Cmd          []string            `json:"Cmd"`
			Env          []string            `json:"Env"`
			ExposedPorts map[string]any      `json:"ExposedPorts"`
			Volumes      map[string]any      `json:"Volumes"`
			StopSignal   string              `json:"StopSignal"`
			Labels       map[string]string   `json:"Labels"`
		} `json:"config"`
		History []struct {
			Created    string `json:"created"`
			CreatedBy  string `json:"created_by"`
			EmptyLayer bool   `json:"empty_layer"`
			Comment    string `json:"comment"`
		} `json:"history"`
	}
	if json.Unmarshal(raw, &configDoc) != nil {
		return
	}
	if target.OS == "" {
		target.OS = configDoc.OS
	}
	if target.Architecture == "" {
		target.Architecture = configDoc.Architecture
	}
	if target.Variant == "" {
		target.Variant = configDoc.Variant
	}
	for key, value := range configDoc.Config.Labels {
		mergedAnnotations[key] = value
	}

	imgCfg := &ImageConfig{
		Author:     strings.TrimSpace(configDoc.Author),
		User:       strings.TrimSpace(configDoc.Config.User),
		WorkingDir: strings.TrimSpace(configDoc.Config.WorkingDir),
		Entrypoint: configDoc.Config.Entrypoint,
		Cmd:        configDoc.Config.Cmd,
		StopSignal: strings.TrimSpace(configDoc.Config.StopSignal),
	}
	if t, err := time.Parse(time.RFC3339Nano, configDoc.Created); err == nil {
		imgCfg.Created = t.UTC()
	}
	for port := range configDoc.Config.ExposedPorts {
		imgCfg.ExposedPorts = append(imgCfg.ExposedPorts, port)
	}
	sort.Strings(imgCfg.ExposedPorts)
	for vol := range configDoc.Config.Volumes {
		imgCfg.Volumes = append(imgCfg.Volumes, vol)
	}
	sort.Strings(imgCfg.Volumes)

	for _, envLine := range configDoc.Config.Env {
		k, v, ok := strings.Cut(envLine, "=")
		if ok {
			imgCfg.Env = append(imgCfg.Env, oci.KV{Key: k, Value: v})
		} else if strings.TrimSpace(envLine) != "" {
			imgCfg.Env = append(imgCfg.Env, oci.KV{Key: envLine, Value: ""})
		}
	}

	labelKeys := make([]string, 0, len(configDoc.Config.Labels))
	for k := range configDoc.Config.Labels {
		labelKeys = append(labelKeys, k)
	}
	sort.Strings(labelKeys)
	for _, k := range labelKeys {
		imgCfg.Labels = append(imgCfg.Labels, oci.KV{Key: k, Value: configDoc.Config.Labels[k]})
	}

	// Align non-empty history entries to filesystem layers in order.
	nonEmptyIdx := 0
	for _, h := range configDoc.History {
		entry := HistoryEntry{
			Command:    cleanHistoryCommand(h.CreatedBy),
			RawCommand: strings.TrimSpace(h.CreatedBy),
			EmptyLayer: h.EmptyLayer,
			Comment:    strings.TrimSpace(h.Comment),
		}
		if t, err := time.Parse(time.RFC3339Nano, h.Created); err == nil {
			entry.Created = t.UTC()
		}
		if !h.EmptyLayer {
			if nonEmptyIdx < len(target.Layers) {
				entry.LayerIndex = nonEmptyIdx + 1
				target.Layers[nonEmptyIdx].Command = entry.Command
				target.Layers[nonEmptyIdx].RawCommand = entry.RawCommand
			}
			nonEmptyIdx++
		}
		imgCfg.History = append(imgCfg.History, entry)
	}
	target.Config = imgCfg
}

func cleanHistoryCommand(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// Strip standard Docker / BuildKit shell wrapper prefixes for human readability.
	for _, prefix := range []string{
		"/bin/sh -c #(nop) ",
		"/bin/sh -c #(nop)",
		"cmd /S /C #(nop) ",
		"/bin/sh -c ",
	} {
		if strings.HasPrefix(s, prefix) {
			trimmed := strings.TrimSpace(strings.TrimPrefix(s, prefix))
			if prefix == "/bin/sh -c " && !strings.HasPrefix(trimmed, "RUN ") {
				return "RUN " + trimmed
			}
			return trimmed
		}
	}
	return s
}

func shortLayerMediaType(mediaType string) string {
	lower := strings.ToLower(mediaType)
	switch {
	case strings.Contains(lower, "tar+zstd"):
		return "tar+zstd"
	case strings.Contains(lower, "tar+gzip") || strings.Contains(lower, "rootfs.diff.tar.gzip"):
		return "tar+gzip"
	case strings.HasSuffix(lower, ".tar"):
		return "tar"
	case mediaType == "":
		return "layer"
	default:
		if idx := strings.LastIndex(mediaType, "."); idx >= 0 && idx+1 < len(mediaType) {
			return mediaType[idx+1:]
		}
		return mediaType
	}
}

func extractOCIAnnotations(annotations map[string]string) []oci.KV {
	ordered := []struct {
		key   string
		label string
	}{
		{"org.opencontainers.image.title", "Title"},
		{"org.opencontainers.image.description", "Description"},
		{"org.opencontainers.image.version", "Version"},
		{"org.opencontainers.image.source", "Source repository"},
		{"org.opencontainers.image.revision", "Revision"},
		{"org.opencontainers.image.licenses", "Licenses"},
		{"org.opencontainers.image.url", "URL"},
		{"org.opencontainers.image.documentation", "Documentation"},
		{"org.opencontainers.image.authors", "Authors"},
		{"org.opencontainers.image.vendor", "Vendor"},
		{"org.opencontainers.image.created", "Created"},
		{"org.opencontainers.image.base.name", "Declared base"},
		{"org.opencontainers.image.base.digest", "Declared base digest"},
	}
	var out []oci.KV
	for _, item := range ordered {
		if val := strings.TrimSpace(annotations[item.key]); val != "" {
			out = append(out, oci.KV{Key: item.label, Value: val})
		}
	}
	return out
}

func (s *Service) registerDocumentArtifact(targetDigest, typ, purpose, digest, mediaType string, raw []byte) string {
	views := oci.BuildPayloadViews(raw, s.cfg.MaxPreviewBytes)
	artifact := &Artifact{
		ID:                   oci.MakeID(targetDigest + typ + digest),
		TargetDigest:         targetDigest,
		Type:                 typ,
		Purpose:              purpose,
		Discovery:            "OCI manifest inspection",
		Digest:               digest,
		MediaType:            mediaType,
		Size:                 int64(len(raw)),
		RawView:              views.Raw,
		RawViewTruncated:     views.RawTruncated,
		DecodedView:          views.Decoded,
		DecodedViewChanged:   views.DecodedChanged,
		DecodedViewJSON:      views.DecodedJSON,
		DecodedViewTruncated: views.DecodedTruncated,
		DecodedRows:          views.Rows,
		DecodedRowsTruncated: views.RowsTruncated,
		Preview:              views.Raw,
		PreviewTruncated:     views.RawTruncated,
		Downloadable:         true,
		Raw:                  raw,
		VerificationStatus:   "Not applicable",
	}
	s.registerArtifact(artifact)
	return artifact.ID
}

func (s *Service) attachIndexAttestations(ctx context.Context, ref reference.ImageRef, report *Report, descriptors []oci.Descriptor) {
	seen := 0
	for _, descriptor := range descriptors {
		if seen >= s.cfg.MaxReferrers {
			report.Warnings = append(report.Warnings, fmt.Sprintf("Index attestation list truncated at %d entries.", s.cfg.MaxReferrers))
			break
		}
		if descriptor.Platform == nil || (descriptor.Platform.OS != "unknown" && descriptor.Platform.Architecture != "unknown") {
			continue
		}
		seen++
		if !strings.Contains(strings.ToLower(annotationValue(descriptor.Annotations, "vnd.docker.reference.type")), "attestation") {
			continue
		}
		targetDigest := annotationValue(descriptor.Annotations, "vnd.docker.reference.digest")
		// BuildKit normally records the target digest as an annotation, while
		// other builders put it on the attestation manifest's subject. Resolve
		// the latter so platform evidence follows the platform it describes.
		if targetDigest == "" {
			if _, attestationManifest, err := s.registry.GetManifest(ctx, ref.Registry, ref.Repository, descriptor.Digest); err == nil && attestationManifest.Subject != nil {
				targetDigest = attestationManifest.Subject.Digest
			}
		}
		if targetDigest == "" {
			continue
		}
		for platformIndex := range report.Platforms {
			if report.Platforms[platformIndex].Digest != targetDigest {
				continue
			}
			artifacts := s.artifactsFromDescriptor(ctx, ref, targetDigest, "Image index attestation manifest", descriptor)
			for _, artifact := range artifacts {
				s.addArtifact(&report.Platforms[platformIndex], artifact)
			}
		}
	}
}

func annotationValue(annotations map[string]string, key string) string {
	for name, value := range annotations {
		if strings.EqualFold(name, key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Service) inspectTarget(ctx context.Context, ref reference.ImageRef, target TargetResult) TargetResult {
	referrers, warnings := s.registry.GetReferrers(ctx, ref.Registry, ref.Repository, target.Digest, s.cfg.MaxReferrers)
	target.Warnings = append(target.Warnings, warnings...)
	target.ReferrerCount = len(referrers)
	for _, desc := range referrers {
		for _, artifact := range s.artifactsFromDescriptor(ctx, ref, target.Digest, "OCI referrer", desc) {
			s.addArtifact(&target, artifact)
		}
	}
	s.inspectCosignAttachmentIndex(ctx, ref, &target)
	for _, legacy := range []struct {
		suffix string
		typ    string
	}{{".sig", "Signature"}, {".att", "Attestation"}, {".sbom", "SBOM"}} {
		tag := oci.LegacyCosignTag(target.Digest, legacy.suffix)
		resp, manifest, err := s.registry.GetManifest(ctx, ref.Registry, ref.Repository, tag)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, oci.ErrAuthenticationNeeded) {
				target.Warnings = append(target.Warnings, fmt.Sprintf("Legacy Cosign %s metadata could not be loaded.", legacy.suffix))
			}
			continue
		}
		artifact := Artifact{
			Type:               legacy.typ,
			Discovery:          "Cosign legacy tag " + tag,
			Digest:             resp.Digest,
			MediaType:          resp.MediaType,
			TargetDigest:       target.Digest,
			VerificationStatus: "Discovered",
			Size:               resp.Size,
			Summary:            []oci.KV{{Key: "Legacy tag", Value: tag}, {Key: "Manifest layers", Value: strconv.Itoa(len(manifest.Layers))}},
		}
		for _, layerArtifact := range s.artifactsFromManifestLayers(ctx, ref, artifact, manifest) {
			s.registerArtifact(&layerArtifact)
			s.addArtifact(&target, layerArtifact)
		}
	}
	return target
}

func (s *Service) inspectCosignAttachmentIndex(ctx context.Context, ref reference.ImageRef, target *TargetResult) {
	tag := oci.LegacyCosignTag(target.Digest, "")
	_, manifest, err := s.registry.GetManifest(ctx, ref.Registry, ref.Repository, tag)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, oci.ErrAuthenticationNeeded) {
			target.Warnings = append(target.Warnings, "Cosign attachment index metadata could not be loaded.")
		}
		return
	}
	if len(manifest.Manifests) == 0 {
		return
	}
	seen := map[string]bool{}
	for _, existing := range append(append(append(target.Signatures, target.Attestations...), target.SBOMs...), target.OtherArtifacts...) {
		seen[existing.Digest] = true
	}
	candidates := 0
	for _, desc := range manifest.Manifests {
		if desc.Platform != nil {
			continue
		}
		if candidates >= s.cfg.MaxReferrers {
			target.Warnings = append(target.Warnings, fmt.Sprintf("Cosign attachment list truncated at %d entries.", s.cfg.MaxReferrers))
			break
		}
		candidates++
		if seen[desc.Digest] {
			continue
		}
		for _, artifact := range s.artifactsFromDescriptor(ctx, ref, target.Digest, "Cosign attachment index tag "+tag, desc) {
			s.addArtifact(target, artifact)
		}
	}
}

func (s *Service) artifactsFromDescriptor(ctx context.Context, ref reference.ImageRef, targetDigest, discovery string, desc oci.Descriptor) []Artifact {
	artifact := Artifact{
		Type:               oci.ClassifyArtifact(desc.ArtifactType, desc.MediaType, desc.Annotations),
		Discovery:          discovery,
		Digest:             desc.Digest,
		MediaType:          desc.MediaType,
		ArtifactType:       desc.ArtifactType,
		Size:               desc.Size,
		TargetDigest:       targetDigest,
		VerificationStatus: "Discovered",
		Summary:            []oci.KV{{Key: "Artifact type", Value: oci.ValueOr(desc.ArtifactType, "not provided")}, {Key: "Media type", Value: oci.ValueOr(desc.MediaType, "not provided")}},
	}
	for k, v := range desc.Annotations {
		if strings.HasPrefix(k, "org.opencontainers.image.") || strings.HasPrefix(k, "dev.sigstore.") || strings.Contains(strings.ToLower(k), "title") {
			artifact.Summary = append(artifact.Summary, oci.KV{Key: k, Value: v})
		}
	}
	resp, manifest, err := s.registry.GetManifest(ctx, ref.Registry, ref.Repository, desc.Digest)
	if err != nil {
		s.logger.Warn("artifact manifest fetch failed", "registry", ref.Registry, "repository", ref.Repository, "digest", desc.Digest, "error", err)
		artifact.Error = "Could not fetch artifact manifest."
		s.registerArtifact(&artifact)
		return []Artifact{artifact}
	}
	artifact.MediaType = oci.ValueOr(resp.MediaType, artifact.MediaType)
	if len(manifest.Layers) > 0 {
		artifacts := s.artifactsFromManifestLayers(ctx, ref, artifact, manifest)
		for i := range artifacts {
			s.registerArtifact(&artifacts[i])
		}
		return artifacts
	} else if len(resp.Bytes) > 0 {
		artifact.Raw = resp.Bytes
		artifact.Downloadable = true
		s.setPayloadViews(&artifact, resp.Bytes, desc.Annotations)
		summary, signatures, isSBOM := oci.SummarizeJSON(resp.Bytes)
		artifact.Summary = append(artifact.Summary, summary...)
		artifact.Signatures = append(artifact.Signatures, signatures...)
		if artifact.Type == "Attestation" && isSBOM {
			artifact.Type = "SBOM attestation"
		}
	}
	s.registerArtifact(&artifact)
	return []Artifact{artifact}
}

func (s *Service) artifactsFromManifestLayers(ctx context.Context, ref reference.ImageRef, base Artifact, manifest oci.Manifest) []Artifact {
	var artifacts []Artifact
	for i, layer := range manifest.Layers {
		if !oci.IsMetadataLayer(layer.MediaType) {
			continue
		}
		artifact := base
		artifact.ID = ""
		artifact.Digest = layer.Digest
		artifact.MediaType = layer.MediaType
		artifact.ArtifactType = oci.ValueOr(manifest.ArtifactType, artifact.ArtifactType)
		artifact.Size = layer.Size
		artifact.Raw = nil
		artifact.Downloadable = false
		artifact.RawView = ""
		artifact.DecodedView = ""
		artifact.DecodedRows = nil
		artifact.Error = ""
		if len(manifest.Layers) > 1 {
			artifact.Summary = append(append([]oci.KV{}, artifact.Summary...), oci.KV{Key: "Metadata layer", Value: fmt.Sprintf("%d of %d", i+1, len(manifest.Layers))})
		} else {
			artifact.Summary = append([]oci.KV{}, artifact.Summary...)
		}
		if artifact.Type == "Signature" || artifact.Type == "" {
			artifact.Type = oci.ClassifyArtifact(manifest.ArtifactType, layer.MediaType, layer.Annotations)
		}
		if artifact.Type == "Attestation" && strings.Contains(strings.ToLower(layer.MediaType), "spdx") {
			artifact.Type = "SBOM attestation"
		}
		if layer.Size > s.cfg.MaxArtifactBytes {
			artifact.Error = fmt.Sprintf("Layer %s is larger than the configured artifact limit.", layer.Digest)
			artifacts = append(artifacts, artifact)
			continue
		}
		raw, err := s.registry.GetBlob(ctx, ref.Registry, ref.Repository, layer.Digest, s.cfg.MaxArtifactBytes)
		if err != nil {
			s.logger.Warn("artifact layer fetch failed", "registry", ref.Registry, "repository", ref.Repository, "digest", layer.Digest, "error", err)
			artifact.Error = "Could not fetch artifact layer."
			artifacts = append(artifacts, artifact)
			continue
		}
		artifact.Raw = raw
		artifact.Downloadable = true
		s.setPayloadViews(&artifact, raw, layer.Annotations)
		addDescriptorAnnotationDetails(&artifact, layer.Annotations)
		summary, signatures, isSBOM := oci.SummarizeArtifactPayload(raw, layer.MediaType)
		artifact.Summary = append(artifact.Summary, summary...)
		artifact.Signatures = append(artifact.Signatures, signatures...)
		if artifact.Type == "Attestation" && isSBOM {
			artifact.Type = "SBOM attestation"
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts
}

func (s *Service) setPayloadViews(artifact *Artifact, raw []byte, annotations map[string]string) {
	views := oci.BuildPayloadViews(raw, s.cfg.MaxPreviewBytes)
	artifact.RawView = views.Raw
	artifact.RawViewTruncated = views.RawTruncated
	artifact.DecodedView = views.Decoded
	artifact.DecodedViewChanged = views.DecodedChanged
	artifact.DecodedViewJSON = views.DecodedJSON
	artifact.DecodedViewTruncated = views.DecodedTruncated
	artifact.DecodedRows = views.Rows
	artifact.DecodedRowsTruncated = views.RowsTruncated
	artifact.Preview = views.Raw
	artifact.PreviewTruncated = views.RawTruncated
	analyzeArtifact(artifact)
	artifact.Verification = verify.Artifact(raw, annotations, artifact.TargetDigest, artifact.ClaimedDigests)
	artifact.VerificationStatus = artifact.Verification.DisplayLabel()
	enrichSignatureFromVerification(artifact)
}

func addDescriptorAnnotationDetails(artifact *Artifact, annotations map[string]string) {
	for k, v := range annotations {
		lower := strings.ToLower(k)
		switch {
		case strings.Contains(lower, "signature") && strings.TrimSpace(v) != "":
			artifact.Signatures = append(artifact.Signatures, oci.KV{Key: k, Value: oci.CompactString(v, 120)})
		case strings.Contains(lower, "certificate") || strings.HasSuffix(lower, "/cert") || lower == "cert":
			artifact.Summary = append(artifact.Summary, oci.KV{Key: k, Value: "present"})
			artifact.Summary = append(artifact.Summary, oci.CertificateSummary(v)...)
		case strings.Contains(lower, "bundle") || strings.Contains(lower, "chain"):
			artifact.Summary = append(artifact.Summary, oci.KV{Key: k, Value: "present"})
		}
	}
}

func (s *Service) registerArtifact(artifact *Artifact) {
	if artifact.ID == "" {
		artifact.ID = oci.MakeID(artifact.TargetDigest + artifact.Type + artifact.Digest + artifact.Discovery)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.artifacts) >= maxRetainedArtifacts {
		for k, entry := range s.artifacts {
			if now.After(entry.expiresAt) {
				delete(s.artifacts, k)
			}
		}
		if len(s.artifacts) >= maxRetainedArtifacts {
			for k := range s.artifacts {
				delete(s.artifacts, k)
				break
			}
		}
	}
	s.artifacts[artifact.ID] = retainedArtifact{artifact: artifact, expiresAt: now.Add(artifactRetentionTTL)}
}

func (s *Service) addArtifact(target *TargetResult, artifact Artifact) {
	if artifact.Digest != "" {
		for _, existing := range targetArtifacts(*target) {
			if existing.Digest == artifact.Digest && existing.TargetDigest == artifact.TargetDigest {
				return
			}
		}
	}
	switch {
	case strings.Contains(strings.ToLower(artifact.Type), "sbom"):
		target.SBOMs = append(target.SBOMs, artifact)
	case strings.Contains(strings.ToLower(artifact.Type), "attestation"):
		target.Attestations = append(target.Attestations, artifact)
	case strings.Contains(strings.ToLower(artifact.Type), "other"):
		target.OtherArtifacts = append(target.OtherArtifacts, artifact)
	default:
		target.Signatures = append(target.Signatures, artifact)
	}
}

func targetArtifacts(target TargetResult) []Artifact {
	all := make([]Artifact, 0, target.ArtifactCount())
	all = append(all, target.Signatures...)
	all = append(all, target.Attestations...)
	all = append(all, target.SBOMs...)
	return append(all, target.OtherArtifacts...)
}
