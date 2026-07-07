package inspect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/cache"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/config"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/reference"
)

type Registry interface {
	GetManifest(ctx context.Context, registry, repository, reference string) (oci.RegistryResponse, oci.Manifest, error)
	GetReferrers(ctx context.Context, registry, repository, digest string, limit int) ([]oci.Descriptor, []string)
	GetBlob(ctx context.Context, registry, repository, digest string, maxBytes int64) ([]byte, error)
}

type Service struct {
	cfg       config.Config
	registry  Registry
	cache     cache.Cache[*Report]
	cacheTTL  time.Duration
	logger    *slog.Logger
	mu        sync.Mutex
	artifacts map[string]*Artifact
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
		artifacts: map[string]*Artifact{},
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
	artifact, ok := s.artifacts[id]
	return artifact, ok
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
		VerificationMessage: "Decoded metadata",
	}
	report.TopLevel = s.inspectTarget(ctx, ref, TargetResult{
		Name:      "Top-level image reference",
		Kind:      oci.KindForMediaType(manifest.MediaType),
		Digest:    resolvedDigest,
		MediaType: manifestResp.MediaType,
		Size:      manifestResp.Size,
	})

	if manifest.MediaType == oci.MediaOCIIndex || manifest.MediaType == oci.MediaDockerManifestList || len(manifest.Manifests) > 0 {
		for i, d := range manifest.Manifests {
			if i >= s.cfg.MaxPlatforms {
				report.Warnings = append(report.Warnings, fmt.Sprintf("Platform list truncated at %d entries.", s.cfg.MaxPlatforms))
				break
			}
			if d.Platform == nil || d.Platform.OS == "unknown" || d.Platform.Architecture == "unknown" {
				continue
			}
			report.Platforms = append(report.Platforms, s.inspectTarget(ctx, ref, TargetResult{
				Name:         oci.PlatformName(d.Platform),
				Kind:         "Platform manifest",
				OS:           d.Platform.OS,
				Architecture: d.Platform.Architecture,
				Variant:      d.Platform.Variant,
				Digest:       d.Digest,
				MediaType:    d.MediaType,
				Size:         d.Size,
			}))
		}
	} else {
		report.TopLevel.Kind = "Image manifest"
	}
	s.logger.Info("inspection completed", "registry", ref.Registry, "repository", ref.Repository, "digest", resolvedDigest, "duration", time.Since(start))
	return report, nil
}

func (s *Service) inspectTarget(ctx context.Context, ref reference.ImageRef, target TargetResult) TargetResult {
	referrers, warnings := s.registry.GetReferrers(ctx, ref.Registry, ref.Repository, target.Digest, s.cfg.MaxReferrers)
	target.Warnings = append(target.Warnings, warnings...)
	target.ReferrerCount = len(referrers)
	for _, desc := range referrers {
		s.addArtifact(&target, s.artifactFromDescriptor(ctx, ref, target.Digest, "OCI referrer", desc))
	}
	s.inspectCosignAttachmentIndex(ctx, ref, &target)
	for _, legacy := range []struct {
		suffix string
		typ    string
	}{{".sig", "Signature"}, {".att", "Attestation"}} {
		tag := oci.LegacyCosignTag(target.Digest, legacy.suffix)
		resp, manifest, err := s.registry.GetManifest(ctx, ref.Registry, ref.Repository, tag)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, oci.ErrAuthenticationNeeded) {
				target.Warnings = append(target.Warnings, fmt.Sprintf("Legacy Cosign %s lookup failed: %v", legacy.suffix, err))
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
		s.fetchLayers(ctx, ref, &artifact, manifest)
		s.registerArtifact(&artifact)
		s.addArtifact(&target, artifact)
	}
	return target
}

func (s *Service) inspectCosignAttachmentIndex(ctx context.Context, ref reference.ImageRef, target *TargetResult) {
	tag := oci.LegacyCosignTag(target.Digest, "")
	resp, manifest, err := s.registry.GetManifest(ctx, ref.Registry, ref.Repository, tag)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, oci.ErrAuthenticationNeeded) {
			target.Warnings = append(target.Warnings, fmt.Sprintf("Cosign attachment index lookup failed: %v", err))
		}
		return
	}
	if len(manifest.Manifests) == 0 {
		return
	}
	target.Warnings = append(target.Warnings, fmt.Sprintf("Discovered Cosign attachment index %s (%s).", tag, oci.ValueOr(resp.Digest, "digest unavailable")))
	seen := map[string]bool{}
	for _, existing := range append(append(target.Signatures, target.Attestations...), target.SBOMs...) {
		seen[existing.Digest] = true
	}
	for _, desc := range manifest.Manifests {
		if seen[desc.Digest] {
			continue
		}
		s.addArtifact(target, s.artifactFromDescriptor(ctx, ref, target.Digest, "Cosign attachment index tag "+tag, desc))
	}
}

func (s *Service) artifactFromDescriptor(ctx context.Context, ref reference.ImageRef, targetDigest, discovery string, desc oci.Descriptor) Artifact {
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
		artifact.Error = "Could not fetch artifact manifest: " + err.Error()
		return artifact
	}
	artifact.MediaType = oci.ValueOr(resp.MediaType, artifact.MediaType)
	if len(manifest.Layers) > 0 {
		s.fetchLayers(ctx, ref, &artifact, manifest)
	} else if len(resp.Bytes) > 0 {
		artifact.Raw = resp.Bytes
		artifact.Downloadable = true
		s.setPayloadViews(&artifact, resp.Bytes)
		summary, signatures, isSBOM := oci.SummarizeJSON(resp.Bytes)
		artifact.Summary = append(artifact.Summary, summary...)
		artifact.Signatures = append(artifact.Signatures, signatures...)
		if artifact.Type == "Attestation" && isSBOM {
			artifact.Type = "SBOM attestation"
		}
	}
	s.registerArtifact(&artifact)
	return artifact
}

func (s *Service) fetchLayers(ctx context.Context, ref reference.ImageRef, artifact *Artifact, manifest oci.Manifest) {
	for _, layer := range manifest.Layers {
		if layer.Size > s.cfg.MaxArtifactBytes {
			artifact.Error = fmt.Sprintf("Layer %s is larger than the configured artifact limit.", layer.Digest)
			continue
		}
		raw, err := s.registry.GetBlob(ctx, ref.Registry, ref.Repository, layer.Digest, s.cfg.MaxArtifactBytes)
		if err != nil {
			artifact.Error = "Could not fetch artifact layer: " + err.Error()
			continue
		}
		artifact.Raw = raw
		artifact.Downloadable = true
		s.setPayloadViews(artifact, raw)
		addDescriptorAnnotationDetails(artifact, layer.Annotations)
		summary, signatures, isSBOM := oci.SummarizeArtifactPayload(raw, layer.MediaType)
		artifact.Summary = append(artifact.Summary, summary...)
		artifact.Signatures = append(artifact.Signatures, signatures...)
		if artifact.Type == "Attestation" && isSBOM {
			artifact.Type = "SBOM attestation"
		}
		return
	}
}

func (s *Service) setPayloadViews(artifact *Artifact, raw []byte) {
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
}

func addDescriptorAnnotationDetails(artifact *Artifact, annotations map[string]string) {
	for k, v := range annotations {
		lower := strings.ToLower(k)
		switch {
		case strings.Contains(lower, "signature") && strings.TrimSpace(v) != "":
			artifact.Signatures = append(artifact.Signatures, oci.KV{Key: k, Value: oci.CompactString(v, 120)})
		case strings.Contains(lower, "certificate"):
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
	s.artifacts[artifact.ID] = artifact
	s.mu.Unlock()
}

func (s *Service) addArtifact(target *TargetResult, artifact Artifact) {
	switch {
	case strings.Contains(strings.ToLower(artifact.Type), "sbom"):
		target.SBOMs = append(target.SBOMs, artifact)
	case strings.Contains(strings.ToLower(artifact.Type), "attestation"):
		target.Attestations = append(target.Attestations, artifact)
	default:
		target.Signatures = append(target.Signatures, artifact)
	}
}
