package inspect

import (
	"fmt"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/oci-supplychain-observatory/internal/oci"
)

// DefaultTargetID opens runnable evidence first; index signatures remain one click away.
func (r *Report) DefaultTargetID() string {
	best, score := -1, 0
	for i, target := range r.Platforms {
		n := target.ArtifactCount()
		if n > score {
			best, score = i, n
		}
	}
	if best >= 0 {
		return fmt.Sprintf("target-platform-%d", best)
	}
	if len(r.Platforms) > 0 {
		return "target-platform-0"
	}
	return "target-top"
}

func (r *Report) PlatformCount() int {
	if len(r.Platforms) > 0 {
		return len(r.Platforms)
	}
	if r.TopLevel.Kind != "Image index" {
		return 1
	}
	return 0
}

func (t TargetResult) ScopeLabel() string {
	if t.Kind == "Image index" {
		return "Image index"
	}
	if t.OS != "" && t.Architecture != "" {
		name := t.OS + "/" + t.Architecture
		if t.Variant != "" {
			name += "/" + t.Variant
		}
		return name
	}
	return "Image manifest"
}

func (t TargetResult) LayerBytes() int64 {
	var size int64
	for _, layer := range t.Layers {
		size += layer.Size
	}
	return size
}

func (a Artifact) DecodeStatus() string {
	if a.Error != "" {
		return "Unavailable"
	}
	if a.DecodedViewJSON {
		return "Decoded"
	}
	if a.Downloadable {
		return "Found · unsupported format"
	}
	return "Discovered"
}

// CertificateFacts are publisher-supplied identity details, not a trust decision.
func (a Artifact) CertificateFacts() []struct{ Key, Value string } {
	var facts []struct{ Key, Value string }
	for _, fact := range a.Summary {
		if strings.HasPrefix(fact.Key, "Certificate ") || fact.Key == "OIDC issuer" {
			facts = append(facts, struct{ Key, Value string }{fact.Key, fact.Value})
		}
	}
	return facts
}

// OverviewFacts keeps repeated subjects and protocol identifiers out of the reading path.
// The complete claims remain accessible under artifact technical details and raw payloads.
func (a Artifact) OverviewFacts() []oci.KV {
	var result []oci.KV
	for _, fact := range a.Facts {
		switch fact.Key {
		case "Covers", "Predicate", "Build type", "Build run", "Relationships", "Dependencies":
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, fact.Value); err == nil {
			fact.Value = parsed.UTC().Format("02 Jan 2006 · 15:04 UTC")
		}
		result = append(result, fact)
	}
	return result
}

func (r *Report) HasOtherMetadata() bool {
	if len(r.TopLevel.OtherArtifacts) > 0 {
		return true
	}
	for _, target := range r.Platforms {
		if len(target.OtherArtifacts) > 0 {
			return true
		}
	}
	return false
}
